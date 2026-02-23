#!/bin/bash

# PROBLEMA 9: INCOERENZA RETE E OPERAZIONI - NETWORK MONITORING
#
# SCOPO: Rilevare operazioni incoerenti (ATM da IP client, online da ATM, etc)
#
# METODO: Usa 'dig' per reverse lookup e classificare client type da hostname
#         Usa 'traceroute' per tracciare il percorso di rete
#         Correla tipo operazione (ATM/Online) con origine rete
#         Se incoerenza: segnala
#
# NETWORK TOOLS: dig, traceroute, ss

# Output minimale
exec 3>&1
exec 1>/dev/null

log() {
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_INCOERENZA="/workspaces/SO/logs/incoerenza_alerts.log"
LOG_REALTIME="/workspaces/SO/logs/realtime_access.log"

# Parametri
SERVER_PORT=8000
ATM_SUBNET="192.168.30"
CLIENT_SUBNET="192.168"

mkdir -p $(dirname "$LOG_INCOERENZA")

declare -A SEGNALATI
declare -A CLIENT_TYPE_CACHE

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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_INCOERENZA"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},INCOERENZA_RETE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge 100 ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_INCOERENZA"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},INCOERENZA_RETE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# Classifica client type da IP e hostname
classifica_client() {
    local ip="$1"
    
    # Check cache
    if [ -n "${CLIENT_TYPE_CACHE[$ip]}" ]; then
        echo "${CLIENT_TYPE_CACHE[$ip]}"
        return
    fi
    
    # Classifica per IP
    if [[ "$ip" =~ ^${ATM_SUBNET} ]]; then
        CLIENT_TYPE_CACHE[$ip]="ATM"
        echo "ATM"
        return
    fi
    
    # Usa dig per reverse lookup
    if command -v dig >/dev/null 2>&1; then
        hostname=$(dig +short -x "$ip" 2>/dev/null | head -1)
        
        if [ -n "$hostname" ]; then
            if [[ "$hostname" =~ [Aa][Tt][Mm]|bancomat ]]; then
                CLIENT_TYPE_CACHE[$ip]="ATM"
                echo "ATM"
            elif [[ "$hostname" =~ [Cc]lient|[Pp]c|[Ww]eb ]]; then
                CLIENT_TYPE_CACHE[$ip]="PC_CLIENT"
                echo "PC_CLIENT"
            elif [[ "$hostname" =~ [Mm]obile|[Aa]pp ]]; then
                CLIENT_TYPE_CACHE[$ip]="MOBILE"
                echo "MOBILE"
            else
                CLIENT_TYPE_CACHE[$ip]="UNKNOWN"
                echo "UNKNOWN"
            fi
        else
            CLIENT_TYPE_CACHE[$ip]="UNKNOWN"
            echo "UNKNOWN"
        fi
    else
        # Fallback senza dig
        if [[ "$ip" =~ ^${ATM_SUBNET} ]]; then
            CLIENT_TYPE_CACHE[$ip]="ATM"
            echo "ATM"
        else
            CLIENT_TYPE_CACHE[$ip]="PC_CLIENT"
            echo "PC_CLIENT"
        fi
    fi
}

# Estrai tipo operazione dal log
estrai_operation_type() {
    local line="$1"
    # Log format assume: operazione è nel campo
    if echo "$line" | grep -q "ATM\|PRELIEVO\|DEPOSITO"; then
        echo "ATM"
    elif echo "$line" | grep -q "BONIFICO\|ONLINE"; then
        echo "ONLINE"
    else
        echo "UNKNOWN"
    fi
}

# INIZIO MONITORAGGIO
log "P09 start"

echo "================================================================================" >> "$LOG_INCOERENZA"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ANALISI INCOERENZA RETE (NETWORK)" >> "$LOG_INCOERENZA"
echo "================================================================================" >> "$LOG_INCOERENZA"

echo "[*] Porta server: $SERVER_PORT"
echo "[*] ATM subnet: $ATM_SUBNET.0/24"
echo ""

ALERT_COUNT=0

# Leggi ultime operazioni dal log
if [ -f "$LOG_REALTIME" ]; then
    echo "  → Analizzando ultime operazioni dal log..."
    
    # Estrai ultime 50 operazioni (campo: timestamp, customer_id, operation_type, ip_source)
    declare -a OPERATIONS
    while IFS='|' read -r timestamp customer_id operation ip_source; do
        if [ -n "$ip_source" ] && [ -n "$operation" ]; then
            OPERATIONS+=("$timestamp|$customer_id|$operation|$ip_source")
        fi
    done < <(tail -50 "$LOG_REALTIME" | grep -E "BONIFICO|ATM|PRELIEVO|DEPOSITO|ONLINE" | \
             awk -F',' '{print $1 "|" $3 "|" $4 "|" $5}')
    
    echo "  [*] Operazioni da verificare: ${#OPERATIONS[@]}"
    echo ""
    
    for op_info in "${OPERATIONS[@]}"; do
        IFS='|' read -r timestamp customer_id operation ip_source <<< "$op_info"
        
        # Classifica client type
        client_type=$(classifica_client "$ip_source")
        op_type=$(estrai_operation_type "$operation")
        
        # Verifica coerenza
        INCOERENTE=0
        MOTIVO=""
        
        if [ "$op_type" = "ATM" ] && [ "$client_type" = "PC_CLIENT" ]; then
            INCOERENTE=1
            MOTIVO="Operazione ATM da PC/client internet"
        elif [ "$op_type" = "ATM" ] && [ "$client_type" = "MOBILE" ]; then
            INCOERENTE=1
            MOTIVO="Operazione ATM da dispositivo mobile"
        elif [ "$op_type" = "ONLINE" ] && [ "$client_type" = "ATM" ]; then
            INCOERENTE=1
            MOTIVO="Operazione online da ATM"
        fi
        
        if [ "$INCOERENTE" = "1" ]; then
            echo "  [!] INCOERENZA RILEVATA"
            echo "      → IP: $ip_source"
            echo "      → Client Type: $client_type"
            echo "      → Operation: $operation"
            echo "      → Motivo: $MOTIVO"
            echo ""
            
            # Segnala solo se non già segnalato
            if [ -z "${SEGNALATI[$ip_source]}" ]; then
                SEGNALATI[$ip_source]=1
                
                # Traceroute per ulteriori dettagli (opzionale)
                if command -v traceroute >/dev/null 2>&1; then
                    echo "      → Traceroute: "
                    timeout 3 traceroute -m 5 "$ip_source" 2>/dev/null | head -3 | while read -r line; do
                        echo "         $line"
                    done
                fi
                
                risk_score=$((45 + 20))  # Base 45 + operation mismatch 20
                
                aggiungi_blacklist "IP" "$ip_source" "INCOERENZA_OPERAZIONE" "MEDIA" "$risk_score" \
                    "Operazione $operation da $client_type; $MOTIVO"
                
                log "P09 alert $ip_source ($op_type vs $client_type)"
                ALERT_COUNT=$((ALERT_COUNT + 1))
            fi
        fi
    done
else
    echo "  ⚠ Log realtime non disponibile per analisi"
fi

# Se non ci sono operazioni nel log, usa connessioni attive
if [ "${#OPERATIONS[@]}" -eq 0 ]; then
    echo "  → Fallback: Analizzando connessioni attive con ss..."
    
    CONNESSIONI=$(ss -tn state established 2>/dev/null | grep ":$SERVER_PORT " | awk '{print $5}' | cut -d: -f1 | sort -u)
    
    while read -r ip; do
        if [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ]; then
            client_type=$(classifica_client "$ip")
            echo "  [*] IP: $ip → Type: $client_type"
        fi
    done <<< "$CONNESSIONI"
fi

echo ""
echo "================================================================================"
echo "[✓] Rilevamento incoerenze completato"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_INCOERENZA"
echo "================================================================================"

# Log dettagliato
{
    echo "═══════════════════════════════════════════"
    echo "INCOERENZA RETE - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "═══════════════════════════════════════════"
    echo "Incoerenze rilevate: $ALERT_COUNT"
} >> "$LOG_INCOERENZA"

log "P09 done"

