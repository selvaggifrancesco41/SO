#!/bin/bash

# PROBLEMA 4: RILEVAMENTO ATM CON PATTERN ANOMALI - DATABASE ANALYSIS
#
# SCOPO: Identificare ATM che effettuano login con pattern anomali
#        (es: ATM da range IP specifici 192.168.30.x che si connettono
#        in modo sospetto o frequente)
#
# METODO: Analizza database per trovare login da IP ATM con pattern anomali
#
# DATABASE: Query periodiche per eventi da IP ATM
# BLACKLIST: Registra IP ATM con comportamenti sospetti
#
# DIPENDENZE: sqlite3, date, awk

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
LOG_ATM="/workspaces/SO/logs/atm_porte_alerts.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"
LAST_CHECK_FILE="/tmp/problema04_last_check.txt"

# Parametri
# Range IP ATM da monitorare (192.168.30.x)
ATM_IP_PATTERN="192.168.30.%"
INTERVALLO_CHECK=2
DURATA_MONITORAGGIO=30

# Soglia di blocco per risk_score (IP)
RISK_BLOCK_THRESHOLD=100

mkdir -p $(dirname "$LOG_ATM")

# Inizializza timestamp ultimo check (solo se non esiste)
if [ ! -f "$LAST_CHECK_FILE" ]; then
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
fi

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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_ATM"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},ATM_PORTE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_ATM"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},ATM_PORTE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# Avvio monitoraggio con output minimo
log "P04 start"
# Log dettagliato su file
echo "================================================================================" >> "$LOG_ATM"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO ATM ANOMALI AVVIATO" >> "$LOG_ATM"
echo "================================================================================" >> "$LOG_ATM"

# Output verbose silenziato da exec 1>/dev/null
echo "[*] Range IP ATM monitorato: $ATM_IP_PATTERN"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
    ORA_ATTUALE=$(date '+%H:%M:%S')
    echo "[Check #$ITERAZIONI] $ORA_ATTUALE"
    
    # Leggi timestamp ultimo check
    LAST_CHECK=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo "1970-01-01T00:00:00")
    
    # Query: trova login da IP ATM (range 192.168.30.x) recenti
    QUERY="SELECT timestamp, customer_id, ip_address, session_duration 
           FROM logs 
           WHERE azione = 'LOGIN' 
           AND ip_address LIKE '$ATM_IP_PATTERN'
           AND timestamp > '$LAST_CHECK'
           ORDER BY timestamp DESC"
    
    # Esegui query e processa risultati
    ATM_LOGINS=$(sqlite3 "$DB_PATH" "$QUERY" 2>/dev/null)
    
    if [ -n "$ATM_LOGINS" ]; then
        NUM_LOGIN=$(echo "$ATM_LOGINS" | wc -l)
        echo "  → Login ATM anomali rilevati: $NUM_LOGIN"
        echo ""
        
        # Processa ogni login ATM (process substitution per evitare subshell)
        while IFS='|' read -r timestamp customer_id atm_ip session_dur; do
            
            if [ -n "$atm_ip" ]; then
                
                echo "  [!!!] ATM ANOMALO RILEVATO"
                echo "      → Timestamp: $timestamp"
                echo "      → ATM ID: $customer_id"
                echo "      → IP ATM: $atm_ip"
                echo "      → Durata sessione: ${session_dur}s"
                echo "      → Pattern: IP da range ATM non autorizzato"
                
                # Segnala solo se non già fatto in questa sessione
                if [ -z "${SEGNALATI[$atm_ip]}" ]; then
                    SEGNALATI[$atm_ip]=1
                    
                    # Controlla blacklist
                    if controlla_blacklist "IP" "$atm_ip"; then
                        echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                        # Isolamento immediato ATM: forza risk_score=100 e stato blocked
                        aggiungi_blacklist "IP" "$atm_ip" "ATM_PATTERN_ANOMALO" \
                            "CRITICA" 100 "ATM con pattern anomalo ($timestamp); IP: $atm_ip"
                    else
                        echo "      → PRIMO RILEVAMENTO"
                        # Isolamento immediato ATM: forza risk_score=100 e stato blocked
                        aggiungi_blacklist "IP" "$atm_ip" "ATM_PATTERN_ANOMALO" \
                            "CRITICA" 100 "ATM con pattern anomalo ($timestamp); IP: $atm_ip"
                    fi
                    
                    # Messaggio minimo di alert
                    log "P04 alert $atm_ip"

                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    
                    # Log dettagliato
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT ATM ANOMALO - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "IP ATM:       $atm_ip"
                        echo "ATM ID:       $customer_id"
                        echo "Timestamp:    $timestamp"
                        echo "Sessione:     ${session_dur}s"
                        echo ""
                    } >> "$LOG_ATM"
                    
                    break
                else
                    echo "      → Già segnalato in questa sessione (SKIP)"
                fi
                
                echo ""
            fi
        done < <(echo "$ATM_LOGINS")
    else
        echo "  → Nessun ATM anomalo rilevato"
    fi
    
    # Aggiorna timestamp ultimo check
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
    
    echo ""
    ITERAZIONI=$((ITERAZIONI + 1))
    
    if [ $ITERAZIONI -lt $MAX_ITERAZIONI ]; then
        sleep $INTERVALLO_CHECK
    fi
done

# Report finale (verbose, silenziato)
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_ATM"
echo "================================================================================"

# Messaggio minimo di fine
log "P04 done"
