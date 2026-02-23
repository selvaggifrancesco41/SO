#!/bin/bash

# PROBLEMA 5: RILEVAMENTO BRUTE-FORCE LOGIN - NETWORK MONITORING
#
# SCOPO: Rilevare tentativi di brute-force sulle API /login del server
#
# METODO: Usa 'tshark' per catturare pacchetti HTTP POST verso /login
#         Conta tentativi per IP sorgente, segnala se eccedono soglia
#
# NETWORK TOOLS: tshark, tcpdump, awk, grep

# Output minimale
exec 3>&1
exec 1>/dev/null

log() {
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_BRUTEFORCE="/workspaces/SO/logs/bruteforce_alerts.log"

# Parametri
SERVER_PORT=8000
SOGLIA_TENTATIVI=10
FINESTRA_SECONDI=10
DURATA_MONITORAGGIO=60
INTERVALLO_CHECK=3
RISK_BLOCK_THRESHOLD=100

mkdir -p $(dirname "$LOG_BRUTEFORCE")

declare -A SEGNALATI
declare -A IP_TENTATIVI

# FUNZIONI COMUNI
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

blocca_ip_se_necessario() {
    local ip_to_block="$1"
    local risk_score="$2"
    if [ "$risk_score" -ge "$RISK_BLOCK_THRESHOLD" ] && command -v iptables >/dev/null 2>&1; then
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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_BRUTEFORCE"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},BRUTEFORCE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_BRUTEFORCE"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},BRUTEFORCE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# INIZIO MONITORAGGIO
log "P05 start"

echo "================================================================================" >> "$LOG_BRUTEFORCE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] RILEVAMENTO BRUTE-FORCE (NETWORK)" >> "$LOG_BRUTEFORCE"
echo "================================================================================" >> "$LOG_BRUTEFORCE"

echo "[*] Port: $SERVER_PORT"
echo "[*] Soglia: $SOGLIA_TENTATIVI tentativi in $FINESTRA_SECONDI secondi"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0
CAPTURE_FILE="/tmp/brute_capture_$$.pcap"

# Avvia cattura tshark in background
# tshark: network protocol analyzer
# -i lo: interface loopback
# -f "tcp port 8000": cattura solo traffico TCP porta 8000
# -w: scrivi in file pcap

timeout $DURATA_MONITORAGGIO tshark -i lo -f "tcp port $SERVER_PORT" -w "$CAPTURE_FILE" >/dev/null 2>&1 &
TSHARK_PID=$!
sleep 0.5  # Dai tempo di start

while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
    ITERAZIONI=$((ITERAZIONI + 1))
    ORA_ATTUALE=$(date '+%H:%M:%S')
    echo "[Check #$ITERAZIONI] $ORA_ATTUALE"
    
    # Analizza cattura con tshark: estrai i POST verso /login
    # -r: leggi dal file pcap
    # -Y: apply filter (display filter)
    # -T fields: output in fields
    # -e: extrai campi specifici
    
    if [ -f "$CAPTURE_FILE" ]; then
        echo "  → Analizzando pacchetti catturati..."
        
        # Estrai tentativi di login (POST /login) con IP sorgente
        LOGIN_ATTEMPTS=$(tshark -r "$CAPTURE_FILE" -Y 'http.request.method == "POST" && http.request.uri contains "/login"' \
            -T fields -e ip.src 2>/dev/null | sort | uniq -c)
        
        if [ -n "$LOGIN_ATTEMPTS" ]; then
            echo "  → Tentativi di login catturati:"
            echo ""
            
            while read -r count ip_src; do
                
                if [ -z "$ip_src" ]; then
                    continue
                fi
                
                echo "  [!] IP: $ip_src | Tentativi: $count"
                
                # Controlla soglia brute-force
                if [ "$count" -ge "$SOGLIA_TENTATIVI" ]; then
                    echo "      → BRUTE-FORCE RILEVATO!"
                    
                    if [ -z "${SEGNALATI[$ip_src]}" ]; then
                        SEGNALATI[$ip_src]=1
                        
                        aggiungi_blacklist "IP" "$ip_src" "BRUTEFORCE_LOGIN" "ALTA" 70 \
                            "$count tentativi login in ~${FINESTRA_SECONDI}s"
                        
                        # Log dettagliato
                        {
                            echo "═══════════════════════════════════════════"
                            echo "ALERT BRUTE-FORCE - $(date '+%Y-%m-%d %H:%M:%S')"
                            echo "═══════════════════════════════════════════"
                            echo "IP Sorgente:   $ip_src"
                            echo "Tentativi:     $count"
                            echo "Soglia:        $SOGLIA_TENTATIVI"
                            echo "Endpoint:      /login"
                            echo "Metodo:        POST"
                        } >> "$LOG_BRUTEFORCE"
                        
                        log "P05 alert $ip_src"
                        ALERT_COUNT=$((ALERT_COUNT + 1))
                        break
                    fi
                fi
            done <<< "$LOGIN_ATTEMPTS"
        else
            echo "  → Nessun tentativo di login rilevato nel traffico catturato"
        fi
    fi
    
    echo ""
    sleep $INTERVALLO_CHECK
done

# Cleanup
kill $TSHARK_PID 2>/dev/null
wait $TSHARK_PID 2>/dev/null
rm -f "$CAPTURE_FILE" 2>/dev/null

# REPORT FINALE
echo ""
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Iterazioni: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
if [ $ALERT_COUNT -eq 0 ]; then
    echo "[*] Nessun brute-force rilevato"
fi
echo "[*] Log: $LOG_BRUTEFORCE"
echo "================================================================================"

log "P05 done"

