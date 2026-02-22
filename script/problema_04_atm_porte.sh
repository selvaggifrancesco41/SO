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

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_ATM="/workspaces/SO/logs/atm_porte_alerts.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"
LAST_CHECK_FILE="/tmp/problema04_last_check.txt"

# Parametri
# Range IP ATM da monitorare (192.168.30.x)
ATM_IP_PATTERN="192.168.30.%"
INTERVALLO_CHECK=2
DURATA_MONITORAGGIO=30

mkdir -p $(dirname "$LOG_ATM")

# Inizializza timestamp ultimo check (solo se non esiste)
if [ ! -f "$LAST_CHECK_FILE" ]; then
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
fi

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
    
    if controlla_blacklist "$tipo_elemento" "$elemento"; then
        local current_risk=$(get_risk_score "$tipo_elemento" "$elemento")
        local recidivita=$(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH")
        recidivita=$((recidivita + 1))
        local new_risk=$((current_risk + risk_score))
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,ATM_PORTE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,ATM_PORTE,${note}" >> "$BLACKLIST_PATH"
    fi
}

echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO ATM ANOMALI AVVIATO"
echo "================================================================================" | tee -a "$LOG_ATM"

echo "[*] Range IP ATM monitorato: $ATM_IP_PATTERN"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ]; do
    
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
        
        # Processa ogni login ATM
        echo "$ATM_LOGINS" | while IFS='|' read -r timestamp customer_id atm_ip session_dur; do
            
            if [ -n "$atm_ip" ]; then
                
                echo "  [!!!] ATM ANOMALO RILEVATO"
                echo "      → Timestamp: $timestamp"
                echo "      → ATM ID: $customer_id"
                echo "      → IP ATM: $atm_ip"
                echo "      → Durata sessione: ${session_dur}s"
                echo "      → Pattern: IP da range ATM non autorizzato"
                
                # Controlla blacklist
                if controlla_blacklist "IP" "$atm_ip"; then
                    echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                    aggiungi_blacklist "IP" "$atm_ip" "ATM_PATTERN_ANOMALO" \
                        "CRITICA" 90 "ATM $customer_id con pattern anomalo ($timestamp), IP: $atm_ip"
                else
                    echo "      → PRIMO RILEVAMENTO"
                    aggiungi_blacklist "IP" "$atm_ip" "ATM_PATTERN_ANOMALO" \
                        "ALTA" 70 "ATM $customer_id con pattern anomalo ($timestamp), IP: $atm_ip"
                fi
                
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
                
                echo ""
            fi
        done
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

echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_ATM"
echo "================================================================================"
