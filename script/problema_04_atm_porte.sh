#!/bin/bash

# PROBLEMA 4: RILEVAMENTO ATM CON PATTERN ANOMALI - NETWORK MONITORING
#
# SCOPO: Identificare ATM (range 192.168.30.x) con comportamento anomalo
#        tramite monitoraggio di socket e porte aperte
#
# METODO: Usa 'netstat -tn' per vedere connessioni TCP attive da IP ATM
#         Conta connessioni per ATM, segnala comportamenti anomali
#         Isolamento immediato se anomalia critica rilevata
#
# NETWORK TOOLS: netstat, nc (port scanning), awk, grep

# Output minimale
exec 3>&1
exec 1>/dev/null

log() {
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_ATM="/workspaces/SO/logs/atm_porte_alerts.log"

# Parametri
ATM_SUBNET="192.168.30"
SERVER_PORT=8000
DURATA_MONITORAGGIO=30
INTERVALLO_CHECK=3
RISK_BLOCK_THRESHOLD=100

mkdir -p $(dirname "$LOG_ATM")

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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_ATM"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},ATM_PORTE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_ATM"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},ATM_PORTE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# INIZIO MONITORAGGIO
log "P04 start"

echo "================================================================================" >> "$LOG_ATM"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO ATM (NETWORK)" >> "$LOG_ATM"
echo "================================================================================" >> "$LOG_ATM"

echo "[*] Monitoraggio subnet ATM: $ATM_SUBNET.0/24"
echo "[*] Porta server: $SERVER_PORT"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
    ITERAZIONI=$((ITERAZIONI + 1))
    ORA_ATTUALE=$(date '+%H:%M:%S')
    echo "[Check #$ITERAZIONI] $ORA_ATTUALE"
    
    # NETWORK MONITORING: Usa 'netstat -tn' per vedere connessioni TCP da ATM
    # netstat -tn: show TCP connections in numeric format
    # grep: filtra solo connessioni da subnet 192.168.30.x
    
    echo "  → Esecuzione: netstat -tn | grep $ATM_SUBNET"
    
    # Estrai connessioni da ATM verso server
    ATM_CONNECTIONS=$(netstat -tn 2>/dev/null | grep " $ATM_SUBNET\." | grep ":$SERVER_PORT " || echo "")
    
    if [ -n "$ATM_CONNECTIONS" ]; then
        echo "  → Analizzando connessioni ATM..."
        echo ""
        
        # Conta connessioni per IP ATM
        # Formato netstat: Proto Recv-Q Send-Q Local Address Foreign Address State
        # Estraiamo solo IP ATM (colonna 6) e contiamo
        
        ATM_IPS=$(echo "$ATM_CONNECTIONS" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c)
        
        while read -r count atm_ip; do
            
            if [ -z "$atm_ip" ]; then
                continue
            fi
            
            echo "  [!] ATM RILEVATO: $atm_ip (connessioni: $count)"
            
            # Anomalia se ATM ha troppo connessioni attive (soglia: 5+)
            if [ "$count" -ge 5 ]; then
                echo "      → PATTERN ANOMALO: $count connessioni simultanee"
                
                if [ -z "${SEGNALATI[$atm_ip]}" ]; then
                    SEGNALATI[$atm_ip]=1
                    
                    # Isolamento immediato con risk_score=100
                    aggiungi_blacklist "IP" "$atm_ip" "ATM_ANOMALO" "CRITICA" 100 \
                        "ATM da $atm_ip: $count connessioni - ISOLAMENTO IMMEDIATO"
                    
                    # Log dettagliato
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT ATM ANOMALO - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "IP ATM:        $atm_ip"
                        echo "Subnet:        $ATM_SUBNET.0/24"
                        echo "Connessioni:   $count"
                        echo "Azione:        ISOLAMENTO IMMEDIATO"
                        echo "Risk Score:    100 (BLOCKED)"
                    } >> "$LOG_ATM"
                    
                    log "P04 alert $atm_ip"
                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    break 2  # Esci da entrambi i loop
                fi
            else
                echo "      → Pattern normale (entro soglia)"
            fi
            
        done <<< "$ATM_IPS"
    else
        echo "  → Nessuna connessione ATM attiva verso porta $SERVER_PORT"
    fi
    
    echo ""
    sleep $INTERVALLO_CHECK
done

# REPORT FINALE
echo ""
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Iterazioni: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
if [ $ALERT_COUNT -eq 0 ]; then
    echo "[*] Nessun ATM anomalo rilevato"
fi
echo "[*] Log: $LOG_ATM"
echo "================================================================================"

log "P04 done"

