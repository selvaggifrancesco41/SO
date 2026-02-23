#!/bin/bash

# PROBLEMA 7: PATTERN ANOMALI API - NETWORK MONITORING
#
# SCOPO: Rilevare abusi pattern API (endpoint ripetuti in breve tempo)
#
# METODO: Usa 'tshark' per catturare traffico HTTP verso server API
#         Analizza POST/GET requests agli endpoint
#         Conta richieste per IP sorgente
#         Identifica pattern ripetitivo sospetto
#
# NETWORK TOOLS: tshark, curl

# Output minimale
exec 3>&1
exec 1>/dev/null

log() {
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_PATTERN="/workspaces/SO/logs/pattern_api_alerts.log"

# Parametri
SERVER_PORT=8000
DURATION_CAPTURE=20  # Capture per 20 secondi
RICHIESTE_SOGLIA=15  # Max richieste prima di alert
INTERVALLO_RICHIESTE=5  # In finestra di 5 secondi

mkdir -p $(dirname "$LOG_PATTERN")

declare -A SEGNALATI

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
    if [ "$risk_score" -ge 100 ] && command -v iptables >/dev/null 2>&1; then
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
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge 100 ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_PATTERN"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},PATTERN_API,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge 100 ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_PATTERN"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},PATTERN_API,${note}" >> "$BLACKLIST_PATH"
    fi
}

# INIZIO MONITORAGGIO
log "P07 start"

echo "================================================================================" >> "$LOG_PATTERN"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ANALISI PATTERN API (NETWORK)" >> "$LOG_PATTERN"
echo "================================================================================" >> "$LOG_PATTERN"

echo "[*] Porta server: $SERVER_PORT"
echo "[*] Soglia richieste: $RICHIESTE_SOGLIA in $INTERVALLO_RICHIESTE secondi"
echo "[*] Durata cattura: $DURATION_CAPTURE secondi"
echo ""

# FILE PER CATTURA
CAPTURE_FILE="/tmp/api_capture_$$.pcap"
TSHARK_OUTPUT="/tmp/tshark_out_$$.txt"

# CATTURA TRAFFICO HTTP
echo "  → Cattura pacchetti HTTP per $DURATION_CAPTURE secondi..."
if command -v tshark >/dev/null 2>&1; then
    timeout "$DURATION_CAPTURE" tshark -i lo -f "tcp port $SERVER_PORT" \
        -w "$CAPTURE_FILE" \
        -q 2>/dev/null
    sleep 1
    
    if [ -f "$CAPTURE_FILE" ]; then
        echo "  [✓] Cattura completata"
        echo ""
        
        # ANALIZZA HTTP REQUESTS
        echo "  → Analizzando richieste HTTP..."
        
        # Estrai requests usando tshark
        tshark -r "$CAPTURE_FILE" \
            -Y "http.request.method" \
            -T fields \
            -e frame.time \
            -e ip.src \
            -e http.request.method \
            -e http.request.uri > "$TSHARK_OUTPUT" 2>/dev/null
        
        # Conta richieste per IP
        declare -A REQUEST_COUNTS
        declare -A IP_REQUESTS
        
        while IFS=$'\t' read -r timestamp src_ip method uri; do
            if [ -n "$src_ip" ]; then
                REQUEST_COUNTS[$src_ip]=$((${REQUEST_COUNTS[$src_ip]:-0} + 1))
                if [ -z "${IP_REQUESTS[$src_ip]}" ]; then
                    IP_REQUESTS[$src_ip]="$uri"
                else
                    IP_REQUESTS[$src_ip]="${IP_REQUESTS[$src_ip]}|$uri"
                fi
            fi
        done < "$TSHARK_OUTPUT"
        
        ALERT_COUNT=0
        
        # Analizza risultati
        for ip in "${!REQUEST_COUNTS[@]}"; do
            count=${REQUEST_COUNTS[$ip]}
            if [ "$count" -ge "$RICHIESTE_SOGLIA" ]; then
                echo "  [!] Richieste anomale da IP: $ip"
                echo "      → Totale richieste: $count"
                
                # Estrai endpoint univoci
                endpoints="${IP_REQUESTS[$ip]}"
                unique_endpoints=$(echo "$endpoints" | tr '|' '\n' | sort -u | head -5)
                echo "      → Endpoint acceduti: $(echo "$unique_endpoints" | wc -l)"
                echo "$unique_endpoints" | while read -r ep; do
                    echo "         • $ep"
                done
                
                if [ -z "${SEGNALATI[$ip]}" ]; then
                    SEGNALATI[$ip]=1
                    
                    risk_score=$((30 + (count - RICHIESTE_SOGLIA) * 5))
                    [ "$risk_score" -gt 80 ] && risk_score=80
                    
                    aggiungi_blacklist "IP" "$ip" "PATTERN_API_ABUSE" "MEDIA" "$risk_score" \
                        "Richieste HTTP anomale: $count richieste in poco tempo; endpoint: $unique_endpoints"
                    
                    log "P07 alert $ip ($count requests)"
                    ALERT_COUNT=$((ALERT_COUNT + 1))
                fi
                echo ""
            fi
        done
        
        # Report finale
        echo "================================================================================"
        echo "[✓] Analisi pattern API completata"
        echo "[*] IP monitorati: $(echo "${!REQUEST_COUNTS[@]}" | wc -w)"
        echo "[*] Alert generati: $ALERT_COUNT"
        echo "[*] Log: $LOG_PATTERN"
        
        # Log dettagliato degli endpoint
        {
            echo "═══════════════════════════════════════════"
            echo "PATTERN API - $(date '+%Y-%m-%d %H:%M:%S')"
            echo "═══════════════════════════════════════════"
            for ip in "${!REQUEST_COUNTS[@]}"; do
                count=${REQUEST_COUNTS[$ip]}
                if [ "$count" -ge "$RICHIESTE_SOGLIA" ]; then
                    echo "IP: $ip | Richieste: $count"
                fi
            done
        } >> "$LOG_PATTERN"
        
    else
        echo "  [✗] Errore nella cattura di pacchetti"
    fi
else
    echo "  [!] tshark non disponibile - fallback a ss"
    
    # Fallback: Conta connessioni per IP
    CONNESSIONI_PER_IP=$(ss -tn state established 2>/dev/null | grep ":$SERVER_PORT " | awk '{print $5}' | cut -d: -f1 | sort | uniq -c)
    
    while read -r count ip; do
        if [ "$count" -ge "$RICHIESTE_SOGLIA" ]; then
            echo "  [!] Connessioni anomale da IP: $ip (count: $count)"
            
            if [ -z "${SEGNALATI[$ip]}" ]; then
                SEGNALATI[$ip]=1
                risk_score=$((20 + count * 2))
                [ "$risk_score" -gt 70 ] && risk_score=70
                
                aggiungi_blacklist "IP" "$ip" "PATTERN_API_HEAVY_USE" "BASSA" "$risk_score" \
                    "Utilizzo intenso API: $count connessioni simultanee"
                
                log "P07 fallback_alert $ip"
            fi
        fi
    done <<< "$CONNESSIONI_PER_IP"
fi

echo "================================================================================"

# Cleanup
rm -f "$CAPTURE_FILE" "$TSHARK_OUTPUT"

log "P07 done"

