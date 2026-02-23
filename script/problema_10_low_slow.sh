#!/bin/bash

# PROBLEMA 10: RILEVAMENTO ATTACCHI LOW & SLOW - RATE LIMITING
#
# SCOPO: Identificare attacchi distribuiti lenti che inviano poche richieste
#        distribuite su lungo periodo per evitare detection tradizionale
#
# METODO: Analizza database per IP con pattern di richieste a basso rate
#         ma persistenti nel tempo (distribuite su finestra lunga)
#
# DATABASE: Query principale per rilevamento
# BLACKLIST: Registra IP con pattern low & slow
#
# DIPENDENZE: sqlite3

# Output minimale: riduce il rumore sul terminale
# FD 3 resta collegato al terminale per messaggi essenziali
exec 3>&1
# Silenzia stdout standard per tutte le stampe verbose
exec 1>/dev/null

# Stampa solo le righe essenziali su terminale
log() {
    # Usa FD 3 per non essere silenziato
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_LOWSLOW="/workspaces/SO/logs/low_slow_attacks.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"
LAST_CHECK_FILE="/tmp/problema10_last_check.txt"

# Parametri
FINESTRA_ANALISI=60             # Analizza ultimi 60 secondi
SOGLIA_RICHIESTE_MAX=8          # Max 8 richieste in finestra (rate basso)
SOGLIA_RICHIESTE_MIN=3          # Min 3 richieste (persistente)
INTERVALLO_CHECK=3
DURATA_MONITORAGGIO=60

# Soglia di blocco per risk_score (IP)
RISK_BLOCK_THRESHOLD=100

mkdir -p $(dirname "$LOG_LOWSLOW")

# Array per tracciare IP già segnalati
declare -A SEGNALATI
ALERT_COUNT=0

get_timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%S'
}

# log_evento: scrive solo su file (stdout e' silenziato)
log_evento() {
    local messaggio="$1"
    local timestamp=$(get_timestamp)
    echo "[$timestamp] $messaggio" >> "$LOG_LOWSLOW"
}

controlla_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    grep -q "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH" 2>/dev/null
    return $?
}

get_risk_score() {
    local tipo_elemento="$1"
    local elemento="$2"
    local score=$(awk -F',' -v tipo="$tipo_elemento" -v elem="$elemento" \
        '$3==tipo && $4==elem {print $7}' "$BLACKLIST_PATH" | tail -1)
    if [ -z "$score" ]; then
        echo 0
    else
        echo "$score"
    fi
}

aggiungi_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    local azione="$3"
    local gravita="$4"
    local risk_score="$5"
    local note="$6"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local stato="blacklisted"
    local final_risk="$risk_score"
    
    if controlla_blacklist "$tipo_elemento" "$elemento"; then
        local current_risk=$(get_risk_score "$tipo_elemento" "$elemento")
        local recidivita=$(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH")
        recidivita=$((recidivita + 1))
        local new_risk=$((current_risk + risk_score))
        final_risk="$new_risk"
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_LOWSLOW"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},LOW_SLOW,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_LOWSLOW"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},LOW_SLOW,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: blocca_ip_se_necessario
# Blocca l'IP con iptables quando il risk_score supera la soglia
blocca_ip_se_necessario() {
    local ip_to_block="$1"
    local risk_score="$2"

    # Blocca solo se supera la soglia e iptables e' disponibile
    if [ "$risk_score" -ge "$RISK_BLOCK_THRESHOLD" ] && command -v iptables >/dev/null 2>&1; then
        # Evita duplicati: -C verifica se la regola esiste gia'
        if ! iptables -C INPUT -s "$ip_to_block" -j DROP 2>/dev/null; then
            iptables -A INPUT -s "$ip_to_block" -j DROP 2>/dev/null
        fi
    fi
}

# Inizializza timestamp ultimo controllo
if [ -f "$LAST_CHECK_FILE" ]; then
    LAST_CHECK=$(cat "$LAST_CHECK_FILE")
else
    LAST_CHECK=$(date -u -d '2 minutes ago' '+%Y-%m-%dT%H:%M:%S')
fi

# Avvio monitoraggio con output minimo
log "P10 start"

# Log dettagliato su file
log_evento "=== AVVIO MONITORAGGIO LOW & SLOW ATTACKS ==="
log_evento "Finestra analisi: $FINESTRA_ANALISI secondi"
log_evento "Soglie richieste: MIN=$SOGLIA_RICHIESTE_MIN, MAX=$SOGLIA_RICHIESTE_MAX"
log_evento "Ultimo controllo: $LAST_CHECK"

# Calcola timestamp inizio finestra
TIMESTAMP_FINESTRA=$(date -u -d "$FINESTRA_ANALISI seconds ago" '+%Y-%m-%dT%H:%M:%S')

# Output verbose silenziato da exec 1>/dev/null
echo "Controllo attacchi low & slow in corso..."

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))

while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    ITERAZIONI=$((ITERAZIONI + 1))
    
    # Query: IP con numero richieste in range basso (3-8) in finestra lunga (60s)
    # Questo indica rate costante ma molto basso = pattern low & slow
    while read; do
        [ -z "$REPLY" ] && continue
        
        ip=$(echo "$REPLY" | cut -d '|' -f1)
        num_req=$(echo "$REPLY" | cut -d '|' -f2)
        customer_id=$(echo "$REPLY" | cut -d '|' -f3)
        
        # Calcola rate: richieste / secondi
        rate=$(awk "BEGIN {printf \"%.2f\", $num_req / $FINESTRA_ANALISI}")
        
        # Low & Slow: poche richieste distribuite su lungo periodo
        if [ -z "${SEGNALATI[$ip]}" ]; then
            # Messaggio minimo di alert
            log "P10 alert $ip"

            log_evento "ALERT LOW & SLOW: IP $ip | Richieste: $num_req in ${FINESTRA_ANALISI}s | Rate: ${rate} req/s | Cliente: $customer_id"
            
            aggiungi_blacklist "IP" "$ip" "LOW_SLOW_ATTACK" "ALTA" 60 \
                "Rate basso: ${rate} req/s; ${num_req} richieste in ${FINESTRA_ANALISI}s; customer: $customer_id"
            
            SEGNALATI[$ip]=1
            ALERT_COUNT=$((ALERT_COUNT + 1))
            break
        fi
    done < <(sqlite3 "$DB_PATH" <<EOF
SELECT 
    ip_address,
    COUNT(*) as num_requests,
    customer_id
FROM logs
WHERE timestamp > '$TIMESTAMP_FINESTRA'
  AND timestamp > '$LAST_CHECK'
GROUP BY ip_address, customer_id
HAVING num_requests >= $SOGLIA_RICHIESTE_MIN 
   AND num_requests <= $SOGLIA_RICHIESTE_MAX
ORDER BY num_requests DESC;
EOF
)
    
    [ $ALERT_COUNT -eq 0 ] && sleep $INTERVALLO_CHECK
done

if [ $ALERT_COUNT -eq 0 ]; then
    log_evento "Nessun pattern low & slow rilevato in ${DURATA_MONITORAGGIO}s"
fi

# Aggiorna timestamp ultimo controllo
get_timestamp > "$LAST_CHECK_FILE"

log_evento "=== FINE MONITORAGGIO LOW & SLOW ==="
log_evento "Iterazioni: $ITERAZIONI | Alert generati: $ALERT_COUNT"

# Messaggio minimo di fine
log "P10 done"
