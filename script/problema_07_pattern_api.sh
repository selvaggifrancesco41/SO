#!/bin/bash

# PROBLEMA 7: ANALISI PATTERN API - HTTP REQUEST MONITORING
#
# SCOPO: Identificare pattern anomali nelle richieste API (sequenze sospette,
#        timing irregolari, user-agent strani)
#
# METODO: Usa curl/wget per testare endpoint API e tshark per catturare headers,
#         analizza user-agent, timing, sequenze di richieste
#
# DATABASE: Usato SOLO per lookup puntuale customer_id
# BLACKLIST: Registra IP con pattern di richieste anomali
#
# DIPENDENZE: tshark, curl, awk

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
LOG_PATTERN="/workspaces/SO/logs/pattern_api_alerts.log"
STATE_FILE="/workspaces/SO/logs/pattern_state.tmp"
DB_PATH="/workspaces/SO/data/bank_logs.db"

# Parametri
SERVER_PORT=8000
SERVER_URL="http://localhost:$SERVER_PORT"
SOGLIA_RICHIESTE_RAPIDE=15   # Max richieste in finestra
FINESTRA_SECONDI=15
DURATA_MONITORAGGIO=60
INTERVALLO=3
LAST_CHECK_FILE="/tmp/problema07_last_check.txt"

# Soglia di blocco per risk_score (IP)
RISK_BLOCK_THRESHOLD=100

mkdir -p $(dirname "$LOG_PATTERN")

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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_PATTERN"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},PATTERN_API,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_PATTERN"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},PATTERN_API,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: verifica_endpoint_disponibile
# Testa se API endpoint risponde
verifica_endpoint_disponibile() {
    # curl:
    # -s: silent mode (no progress bar)
    # -o /dev/null: scarta output body
    # -w "%{http_code}": write-out solo HTTP status code
    # -m 5: max-time 5 secondi timeout
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$SERVER_URL/login?customer_id=test&porta=5000" 2>/dev/null)
    
    # 200-299: success codes
    # ${var:0:1}: substring, primo carattere
    if [ "${http_code:0:1}" == "2" ] || [ "${http_code:0:1}" == "3" ]; then
        return 0  # Disponibile
    else
        return 1  # Non disponibile
    fi
}

# FUNZIONE: identifica_user_agent_sospetto
# Verifica se user-agent è sospetto (bot, scanner, tool automatici)
# ARG1: user-agent string
identifica_user_agent_sospetto() {
    local ua="$1"
    
    # User-agent sospetti comuni
    # grep -i: case-insensitive
    # -E: extended regex (alternation con |)
    echo "$ua" | grep -iE "curl|wget|python|scanner|nikto|sqlmap|nmap|masscan|bot|crawler" > /dev/null
    
    # $?: exit code del grep (0=match, 1=no match)
    if [ $? -eq 0 ]; then
        return 0  # Sospetto
    else
        return 1  # Normale
    fi
}

# Avvio monitoraggio con output minimo
log "P07 start"
# Log dettagliato su file
echo "================================================================================" >> "$LOG_PATTERN"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO PATTERN API AVVIATO" >> "$LOG_PATTERN"
echo "================================================================================" >> "$LOG_PATTERN"

# Test connettività API (verbose silenziato)
echo "[*] Test endpoint API..."
if verifica_endpoint_disponibile; then
    echo "  ✓ Server API raggiungibile su $SERVER_URL"
else
    echo "  ✗ Server API NON raggiungibile"
    echo "  [!] Avvia il server prima di eseguire questo script"
    exit 1
fi

# Output verbose silenziato da exec 1>/dev/null
echo ""
echo "[*] Porta: $SERVER_PORT"
echo "[*] Soglia: $SOGLIA_RICHIESTE_RAPIDE richieste in $FINESTRA_SECONDI secondi"
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
    
    # Query database: richieste API recenti (non LOGIN)
    QUERY="SELECT timestamp, ip_address, customer_id, azione 
           FROM logs 
           WHERE timestamp > '$LAST_CHECK' 
           AND azione IN ('PRELIEVO', 'DEPOSITO', 'BONIFICO')
           ORDER BY timestamp ASC"
    
    RICHIESTE_RECENTI=$(sqlite3 "$DB_PATH" "$QUERY" 2>/dev/null)
    
    if [ -z "$RICHIESTE_RECENTI" ]; then
        echo "  → Nessuna richiesta API rilevata"
    else
        # Process substitution per evitare subshell
        while IFS='|' read -r timestamp ip_src customer_id azione; do
    
            COUNTER=$((COUNTER + 1))
            
            echo "  [+] Richiesta #$COUNTER: $azione da IP $ip_src (customer: $customer_id)"
            
            # Conta richieste da questo IP negli ultimi FINESTRA_SECONDI
            WINDOW_START=$(date -u -d "$FINESTRA_SECONDI seconds ago" '+%Y-%m-%dT%H:%M:%S')
            
            COUNT_QUERY="SELECT COUNT(*) FROM logs 
                         WHERE ip_address='$ip_src' 
                         AND timestamp > '$WINDOW_START' 
                         AND azione IN ('PRELIEVO', 'DEPOSITO', 'BONIFICO')"
            
            RICHIESTE_IP=$(sqlite3 "$DB_PATH" "$COUNT_QUERY" 2>/dev/null)
            
            echo "      → Richieste ultimi ${FINESTRA_SECONDI}s: $RICHIESTE_IP"
            
            # Soglia superata?
            if [ $RICHIESTE_IP -ge $SOGLIA_RICHIESTE_RAPIDE ]; then
                echo ""
                echo "  [!!!] PATTERN RAPIDO: $RICHIESTE_IP richieste da $ip_src in ${FINESTRA_SECONDI}s"
                echo "      → Customer: $customer_id"
                
                # Segnala solo se non già fatto
                if [ -z "${SEGNALATI[$ip_src]}" ]; then
                    SEGNALATI[$ip_src]=1
                    
                    if controlla_blacklist "IP" "$ip_src"; then
                        echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                        aggiungi_blacklist "IP" "$ip_src" "RICHIESTE_RAPIDE" \
                            "ALTA" 60 "$RICHIESTE_IP richieste in ${FINESTRA_SECONDI}s; customer: $customer_id"
                    else
                        echo "      → PRIMO RILEVAMENTO"
                        aggiungi_blacklist "IP" "$ip_src" "RICHIESTE_RAPIDE" \
                            "MEDIA" 40 "$RICHIESTE_IP richieste in ${FINESTRA_SECONDI}s; customer: $customer_id"
                    fi
                    
                    # Messaggio minimo di alert
                    log "P07 alert $ip_src"

                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    
                    # Log dettagliato
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT PATTERN API - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "IP:              $ip_src"
                        echo "Customer:        $customer_id"
                        echo "Richieste/${FINESTRA_SECONDI}s: $RICHIESTE_IP"
                        echo "Azione:          $azione"
                        echo ""
                    } >> "$LOG_PATTERN"
                    
                    # Exit on first alert
                    break
                else
                    echo "      → Già segnalato (SKIP)"
                fi
                
                echo ""
            fi
            
        done < <(echo "$RICHIESTE_RECENTI")
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
echo "[*] Richieste analizzate: $COUNTER"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_PATTERN"
echo "================================================================================"

# Messaggio minimo di fine
log "P07 done"
