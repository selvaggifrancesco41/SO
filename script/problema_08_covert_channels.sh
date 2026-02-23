#!/bin/bash

# PROBLEMA 8: COVERT CHANNELS - NETWORK MONITORING
#
# SCOPO: Rilevare operazioni fittizie (BONIFICO con importo=0)
#        e canali nascosti (pacchetti anomali/zero-byte)
#
# METODO: Usa 'tcpdump' per catturare pacchetti anomali
#         Cerca pacchetti con solo header (ACK senza payload)
#         Conta pattern anomali per IP sorgente
#         Integra log realtime per importi=0
#
# NETWORK TOOLS: tcpdump, ss

# Output minimale
exec 3>&1
exec 1>/dev/null

log() {
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_COVERT="/workspaces/SO/logs/covert_channels_alerts.log"
LOG_REALTIME="/workspaces/SO/logs/realtime_access.log"

# Parametri
SERVER_PORT=8000
DURATION_CAPTURE=15
PACKET_ANOMALY_THRESHOLD=20  # pacchetti anomali per alert
INTERVALLO_CHECK=2

mkdir -p $(dirname "$LOG_COVERT")

declare -A SEGNALATI
declare -A PACKET_ANOMALIES

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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_COVERT"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},COVERT_CHANNELS,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge 100 ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_COVERT"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},COVERT_CHANNELS,${note}" >> "$BLACKLIST_PATH"
    fi
}

# INIZIO MONITORAGGIO
log "P08 start"

echo "================================================================================" >> "$LOG_COVERT"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ANALISI COVERT CHANNELS (NETWORK)" >> "$LOG_COVERT"
echo "================================================================================" >> "$LOG_COVERT"

echo "[*] Porta server: $SERVER_PORT"
echo "[*] Durata cattura: $DURATION_CAPTURE secondi"
echo "[*] Soglia anomalie: $PACKET_ANOMALY_THRESHOLD pacchetti"
echo ""

# METODO 1: Cattura pacchetti anomali con tcpdump
if command -v tcpdump >/dev/null 2>&1; then
    echo "  → Cattura pacchetti anomali (tcpdump)..."
    
    CAPTURE_FILE="/tmp/covert_$$.pcap"
    TSHARK_ANALYSIS="/tmp/covert_analysis_$$.txt"
    
    timeout "$DURATION_CAPTURE" tcpdump -i lo "tcp port $SERVER_PORT" \
        -w "$CAPTURE_FILE" -q 2>/dev/null
    sleep 1
    
    if [ -f "$CAPTURE_FILE" ]; then
        echo "  [✓] Cattura completata"
        
        # Analizza con tshark per cercare pacchetti anomali
        if command -v tshark >/dev/null 2>&1; then
            {
                tshark -r "$CAPTURE_FILE" \
                    -T fields \
                    -e ip.src \
                    -e tcp.flags \
                    -e tcp.len 2>/dev/null
            } > "$TSHARK_ANALYSIS"
            
            echo "  → Analizzando pattern anomali..."
            
            # Conta ACK-only packets e zero-length packets
            declare -A ACK_ONLY_PACKETS
            declare -A ZERO_PAYLOAD
            
            while IFS=$'\t' read -r src_ip flags payload_len; do
                if [ -n "$src_ip" ]; then
                    
                    # Cerca ACK-only packets (flags = 0x10)
                    if [ "$flags" = "0x10" ] || [ "$flags" = "16" ]; then
                        ACK_ONLY_PACKETS[$src_ip]=$((${ACK_ONLY_PACKETS[$src_ip]:-0} + 1))
                    fi
                    
                    # Cerca zero-length payload
                    if [ "$payload_len" = "0" ] && [ "$flags" != "0x02" ]; then
                        ZERO_PAYLOAD[$src_ip]=$((${ZERO_PAYLOAD[$src_ip]:-0} + 1))
                    fi
                fi
            done < "$TSHARK_ANALYSIS"
            
            ALERT_COUNT=0
            
            echo ""
            for ip in "${!ACK_ONLY_PACKETS[@]}"; do
                ack_count=${ACK_ONLY_PACKETS[$ip]}
                if [ "$ack_count" -ge "$PACKET_ANOMALY_THRESHOLD" ]; then
                    echo "  [!] Pacchetti ACK anomali da: $ip"
                    echo "      → Count: $ack_count"
                    
                    if [ -z "${SEGNALATI[$ip]}" ]; then
                        SEGNALATI[$ip]=1
                        
                        risk_score=$((40 + (ack_count / 10) * 10))
                        [ "$risk_score" -gt 75 ] && risk_score=75
                        
                        aggiungi_blacklist "IP" "$ip" "COVERT_ACK_FLOOD" "MEDIA" "$risk_score" \
                            "Flood di pacchetti ACK senza payload: $ack_count pacchetti"
                        
                        log "P08 alert ACK $ip"
                        ALERT_COUNT=$((ALERT_COUNT + 1))
                    fi
                fi
            done
            
            for ip in "${!ZERO_PAYLOAD[@]}"; do
                zero_count=${ZERO_PAYLOAD[$ip]}
                if [ "$zero_count" -ge $((PACKET_ANOMALY_THRESHOLD / 2)) ]; then
                    if [ -z "${SEGNALATI[$ip]}" ]; then
                        echo "  [!] Pacchetti zero-payload da: $ip"
                        echo "      → Count: $zero_count"
                        
                        SEGNALATI[$ip]=1
                        risk_score=$((35 + (zero_count / 5) * 8))
                        [ "$risk_score" -gt 70 ] && risk_score=70
                        
                        aggiungi_blacklist "IP" "$ip" "COVERT_ZERO_PAYLOAD" "MEDIA" "$risk_score" \
                            "Trasmissione di pacchetti con payload zero: $zero_count pacchetti"
                        
                        log "P08 alert ZERO $ip"
                        ALERT_COUNT=$((ALERT_COUNT + 1))
                    fi
                fi
            done
        fi
        
    fi
fi

# METODO 2: Analizza log per BONIFICO con importo=0
echo ""
echo "  → Ricerca di operazioni fittizie nel log..."

if [ -f "$LOG_REALTIME" ]; then
    FAKE_OPS=$(tail -100 "$LOG_REALTIME" | grep "BONIFICO" | grep ",0," | awk -F',' '{print $3}' | sort -u)
    
    if [ -n "$FAKE_OPS" ]; then
        echo "  [!] Operazioni fittizie rilevate (importo=0)"
        echo ""
        
        while read -r customer_id; do
            echo "      → Customer: $customer_id"
            
            # Estrai informazioni dal log
            op_count=$(grep ",$customer_id," "$LOG_REALTIME" | grep -c "BONIFICO.*,0,")
            
            if [ "$op_count" -gt 0 ]; then
                echo "         Bonifici da 0€: $op_count"
                
                if [ -z "${SEGNALATI[$customer_id]}" ]; then
                    SEGNALATI[$customer_id]=1
                    
                    risk_score=$((20 + op_count * 5))
                    [ "$risk_score" -gt 65 ] && risk_score=65
                    
                    aggiungi_blacklist "CUSTOMER" "$customer_id" "FAKE_BONIFICO" "BASSA" "$risk_score" \
                        "Bonifici fittizi (importo=0) nel log: $op_count operazioni"
                    
                    log "P08 alert FAKE_OP $customer_id"
                fi
            fi
        done <<< "$FAKE_OPS"
    fi
else
    echo "  ⚠ Log realtime non disponibile"
fi

echo ""
echo "================================================================================"
echo "[✓] Rilevamento covert channels completato"
echo "[*] TotaleIP/Customer monitorati: ${#SEGNALATI[@]}"
echo "[*] Log: $LOG_COVERT"
echo "================================================================================"

# Log finale
{
    echo "═══════════════════════════════════════════"
    echo "COVERT CHANNELS - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "═══════════════════════════════════════════"
    echo "Pacchetti anomali rilevati"
} >> "$LOG_COVERT"

# Cleanup
rm -f "$CAPTURE_FILE" "$TSHARK_ANALYSIS"

log "P08 done"

