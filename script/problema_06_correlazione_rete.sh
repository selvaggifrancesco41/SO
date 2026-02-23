#!/bin/bash

# PROBLEMA 6: CORRELAZIONE RETE E SUBNET ANOMALE - NETWORK MONITORING
#
# SCOPO: Rilevare login da subnet inattese o IP pubblici
#
# METODO: Usa 'ip' per verificare la topologia di rete locale
#         Usa 'arp -a' per vedere dispositivi sulla rete
#         Usa 'ping' per verificare latenza da IP anomali
#         Se IP proviene da subnet inattesa, segnala
#
# NETWORK TOOLS: ip, arp, ping, ss

# Output minimale
exec 3>&1
exec 1>/dev/null

log() {
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_CORRELAZIONE="/workspaces/SO/logs/correlazione_alerts.log"

# Parametri
SERVER_PORT=8000
DURATA_MONITORAGGIO=30
INTERVALLO_CHECK=3
RISK_BLOCK_THRESHOLD=100

mkdir -p $(dirname "$LOG_CORRELAZIONE")

declare -A SEGNALATI

# Subnet attese (private netblock)
declare -A SUBNET_ATTESE=(
    ["10.0.0.0/8"]=1
    ["172.16.0.0/12"]=1
    ["192.168.0.0/16"]=1
)

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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_CORRELAZIONE"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},CORRELAZIONE_RETE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_CORRELAZIONE"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},CORRELAZIONE_RETE,${note}" >> "$BLACKLIST_PATH"
    fi
}

is_private_ip() {
    local ip="$1"
    # Controlla se IP è in un range privato
    if echo "$ip" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
        return 0  # È privato
    else
        return 1  # È pubblico o inatteso
    fi
}

# INIZIO MONITORAGGIO
log "P06 start"

echo "================================================================================" >> "$LOG_CORRELAZIONE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ANALISI CORRELAZIONE RETE (NETWORK)" >> "$LOG_CORRELAZIONE"
echo "================================================================================" >> "$LOG_CORRELAZIONE"

echo "[*] Porta server: $SERVER_PORT"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

# Raccogli info di rete locale iniziale
echo "  → Raccolta topologia rete locale..."
echo ""

INTERFACCE=$(ip addr show 2>/dev/null | grep "inet " | awk '{print $2}' | grep -v "127.0.0.1")
echo "  [*] Interfacce locali e subnet:"
while read -r subnet; do
    echo "      $subnet"
done <<< "$INTERFACCE"
echo ""

ARP_CACHE=$(arp -a 2>/dev/null || echo "")
if [ -n "$ARP_CACHE" ]; then
    echo "  [*] Dispositivi sulla rete (ARP):"
    echo "$ARP_CACHE" | grep -E "192.168|10\." | head -5 | while read -r line; do
        echo "      $line"
    done
    echo ""
fi

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
    ITERAZIONI=$((ITERAZIONI + 1))
    ORA_ATTUALE=$(date '+%H:%M:%S')
    echo "[Check #$ITERAZIONI] $ORA_ATTUALE"
    
    # NETWORK MONITORING: Estrai IP connessi verso porta server con 'ss'
    echo "  → Esecuzione: ss -tn | grep :$SERVER_PORT"
    
    CONNESSIONI=$(ss -tn state established 2>/dev/null | grep ":$SERVER_PORT " | awk '{print $4}' | cut -d: -f1 | sort -u)
    
    if [ -n "$CONNESSIONI" ]; then
        echo "  → Analizzando IP sorgente..."
        echo ""
        
        while read -r suspicious_ip; do
            
            if [ -z "$suspicious_ip" ] || [ "$suspicious_ip" = "127.0.0.1" ]; then
                continue
            fi
            
            echo "  [!] IP CONNESSO: $suspicious_ip"
            
            # Controlla se è in subnet attesa (privata)
            if is_private_ip "$suspicious_ip"; then
                echo "      → IP privato (atteso)"
            else
                echo "      → IP PUBBLICO O INATTESO!"
                
                # Test latenza con ping
                LATENCY=$(ping -c 1 -W 1 "$suspicious_ip" 2>/dev/null | grep "time=" | awk -F'time=' '{print $2}' | cut -d' ' -f1)
                if [ -n "$LATENCY" ]; then
                    echo "      → Latenza: ${LATENCY}ms"
                fi
                
                if [ -z "${SEGNALATI[$suspicious_ip]}" ]; then
                    SEGNALATI[$suspicious_ip]=1
                    
                    aggiungi_blacklist "IP" "$suspicious_ip" "SUBNET_ANOMALA" "MEDIA" 50 \
                        "Login da IP pubblico inatteso: $suspicious_ip; latenza: ${LATENCY}ms"
                    
                    # Log dettagliato
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT SUBNET ANOMALA - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "IP Sorgente:   $suspicious_ip"
                        echo "Tipo:          PUBBLICO/INATTESO"
                        echo "Latenza:       ${LATENCY}ms"
                        echo "Porta Server:  $SERVER_PORT"
                    } >> "$LOG_CORRELAZIONE"
                    
                    log "P06 alert $suspicious_ip"
                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    break
                fi
            fi
            
        done <<< "$CONNESSIONI"
    else
        echo "  → Nessuna connessione attiva"
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
    echo "[*] Nessuna anomalia di rete rilevata"
fi
echo "[*] Log: $LOG_CORRELAZIONE"
echo "================================================================================"

log "P06 done"

