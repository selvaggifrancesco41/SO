#!/bin/bash

# PROBLEMA 8: RILEVAMENTO COVERT CHANNELS - OPERAZIONI FAKE E PATTERN TIMING
#
# SCOPO: Identificare operazioni bancarie fake usate come canali nascosti:
#        - Richieste con importo 0 o NULL (operazioni fake)
#        - Pattern di timing troppo regolari (beacon/automazione)
#
# METODO: Analizza database per operazioni senza valore reale e timing sospetti
#
# DATABASE: Query principale per rilevamento
# BLACKLIST: Registra IP con pattern covert
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
LOG_COVERT="/workspaces/SO/logs/covert_channels_alerts.log"
LOG_BLOCCO_ZERO="/workspaces/SO/logs/operazioni_bloccate_zero.log"
LOG_API_SOSPESA="/workspaces/SO/logs/api_sospese.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"
LAST_CHECK_FILE="/tmp/problema08_last_check.txt"

# Parametri
SOGLIA_FAKE_OPS=5           # Minimo operazioni fake per segnalare
DURATA_MONITORAGGIO=60
INTERVALLO=3

# Soglia di blocco per risk_score (IP)
RISK_BLOCK_THRESHOLD=100

# Crea directory log se non esistono
mkdir -p $(dirname "$LOG_COVERT")
mkdir -p $(dirname "$LOG_BLOCCO_ZERO")
mkdir -p $(dirname "$LOG_API_SOSPESA")

# Array per tracciare IP già segnalati in questa sessione
declare -A SEGNALATI

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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_COVERT"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},COVERT_CHANNELS,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_COVERT"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},COVERT_CHANNELS,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: registra_blocco_importo_zero
# Simula blocco operazioni a importo 0 scrivendo su log dedicato
registra_blocco_importo_zero() {
    local ip_address="$1"
    local customer_id="$2"
    local fake_count="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$timestamp] BLOCCO_IMPORTO_ZERO IP:$ip_address CUSTOMER:$customer_id COUNT:$fake_count" >> "$LOG_BLOCCO_ZERO"
}

# FUNZIONE: sospendi_api
# Simula sospensione API per IP con rischio elevato
sospendi_api() {
    local ip_address="$1"
    local customer_id="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Scrive log dedicato di sospensione
    echo "[$timestamp] API_SOSPESA IP:$ip_address CUSTOMER:$customer_id" >> "$LOG_API_SOSPESA"

    # Registra sospensione in blacklist con risk_score alto
    aggiungi_blacklist "IP" "$ip_address" "API_SOSPESA" "CRITICA" 100 \
        "API sospesa per operazioni fake; customer: $customer_id"
}

# Avvio monitoraggio con output minimo
log "P08 start"
# Log dettagliato su file
echo "================================================================================" >> "$LOG_COVERT"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] RILEVAMENTO COVERT CHANNELS AVVIATO" >> "$LOG_COVERT"
echo "================================================================================" >> "$LOG_COVERT"

# Output verbose silenziato da exec 1>/dev/null
echo "[*] Soglia: $SOGLIA_FAKE_OPS operazioni fake da stesso IP"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo "[*] Intervallo: $INTERVALLO secondi"
echo ""

# Inizializza timestamp per query incrementale
date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"

COUNTER=0
ALERT_COUNT=0
START_TIME=$(date +%s)
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO))
ITERAZIONI=0

# Loop di monitoraggio con exit-on-first-alert
while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
    echo "[Check #$ITERAZIONI] $(date '+%H:%M:%S')"
    
    LAST_CHECK=$(cat "$LAST_CHECK_FILE")
    
    # Query: rileva operazioni con importo 0 o NULL (fake operations)
    # Queste potrebbero essere usate come canali nascosti
    QUERY="SELECT ip_address, customer_id, COUNT(*) as fake_count
           FROM logs 
           WHERE timestamp > '$LAST_CHECK'
           AND azione IN ('PRELIEVO', 'DEPOSITO', 'BONIFICO')
           AND (importo IS NULL OR importo = 0)
           GROUP BY ip_address, customer_id
           HAVING fake_count >= $SOGLIA_FAKE_OPS
           ORDER BY fake_count DESC"
    
    FAKE_OPS=$(sqlite3 "$DB_PATH" "$QUERY" 2>/dev/null)
    
    if [ -z "$FAKE_OPS" ]; then
        echo "  → Nessuna operazione fake rilevata"
    else
        # Process substitution per evitare subshell
        while IFS='|' read -r ip_address customer_id fake_count; do
            
            COUNTER=$((COUNTER + 1))
            
            echo ""
            echo "  [!!!] COVERT CHANNEL RILEVATO"
            echo "      → IP: $ip_address"
            echo "      → Customer: $customer_id"
            echo "      → Operazioni fake: $fake_count (importo=0 o NULL)"
            
            # Segnala solo se non già fatto
            if [ -z "${SEGNALATI[$ip_address]}" ]; then
                SEGNALATI[$ip_address]=1
                
                if controlla_blacklist "IP" "$ip_address"; then
                    echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                    aggiungi_blacklist "IP" "$ip_address" "COVERT_CHANNEL_FAKE_OPS" \
                        "CRITICA" 90 "$fake_count operazioni fake (importo=0/NULL); customer: $customer_id"
                else
                    echo "      → PRIMO RILEVAMENTO"
                    aggiungi_blacklist "IP" "$ip_address" "COVERT_CHANNEL_FAKE_OPS" \
                        "ALTA" 70 "$fake_count operazioni fake (importo=0/NULL); customer: $customer_id"
                fi

                # Conseguenza 1: blocco operazioni a importo 0 (simulato)
                registra_blocco_importo_zero "$ip_address" "$customer_id" "$fake_count"

                # Conseguenza 2: sospensione API per IP sospetto
                sospendi_api "$ip_address" "$customer_id"
                
                # Messaggio minimo di alert
                log "P08 alert $ip_address"

                ALERT_COUNT=$((ALERT_COUNT + 1))
                
                # Log dettagliato
                {
                    echo "═══════════════════════════════════════════"
                    echo "ALERT COVERT CHANNEL - $(date '+%Y-%m-%d %H:%M:%S')"
                    echo "═══════════════════════════════════════════"
                    echo "IP:              $ip_address"
                    echo "Customer:        $customer_id"
                    echo "Operazioni fake: $fake_count"
                    echo "Tipo:            Importo 0 o NULL"
                    echo ""
                } >> "$LOG_COVERT"
                
                # Exit on first alert
                break
            else
                echo "      → Già segnalato (SKIP)"
            fi
            
        done < <(echo "$FAKE_OPS")
    fi
    
    # Aggiorna timestamp ultimo check
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
    
    ITERAZIONI=$((ITERAZIONI + 1))
    
    # Exit se alert trovato
    if [ $ALERT_COUNT -gt 0 ]; then
        break
    fi
    
    sleep $INTERVALLO
done

# Report finale (verbose, silenziato)
echo ""
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] IP analizzati: $COUNTER"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_COVERT"
echo "================================================================================"

# Messaggio minimo di fine
log "P08 done"
