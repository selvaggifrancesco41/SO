#!/bin/bash

# PROBLEMA 3: RILEVAMENTO ACCESSI NOTTURNI SOSPETTI - NETWORK MONITORING
#
# SCOPO: Identificare login al server durante orario notturno (22:00-06:00)
#        che potrebbero indicare attività non autorizzate
#
# METODO: Usa 'ss -tn' per vedere connessioni TCP attive verso porta 8000
#         Filtra per orario notturno, risolve hostname con 'host'
#         Verifica IP sorgente e segnala quelli anomali
#
# NETWORK TOOLS: ss, host, awk, grep, date

# Output minimale
exec 3>&1
exec 1>/dev/null

log() {
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_NOTTURNI="/workspaces/SO/logs/notturni_alerts.log"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"
NOTIFY_LOG="/workspaces/SO/logs/notifiche_email.txt"

# Parametri
SERVER_PORT=8000
ORA_INIZIO_NOTTE=22
ORA_FINE_NOTTE=6
DURATA_MONITORAGGIO=30
INTERVALLO_CHECK=2
RISK_BLOCK_THRESHOLD=100

mkdir -p $(dirname "$LOG_NOTTURNI")
mkdir -p $(dirname "$NOTIFY_LOG")

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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_NOTTURNI"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},ACCESSI_NOTTURNI,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_NOTTURNI"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},ACCESSI_NOTTURNI,${note}" >> "$BLACKLIST_PATH"
    fi
}

get_cliente_info() {
    local customer_id="$1"
    python3 - "$customer_id" <<'PY'
import csv
import sys

cid = sys.argv[1]
email = "UNKNOWN"
twofa = "False"
name = "UNKNOWN"

with open("/workspaces/SO/clienti_banca.csv", "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row.get("customer_id") == cid:
            email = row.get("email", "UNKNOWN")
            twofa = row.get("two_factor_enabled", "False")
            first = row.get("first_name", "")
            last = row.get("last_name", "")
            full = (first + " " + last).strip()
            name = full if full else "UNKNOWN"
            break

print(f"{email}|{twofa}|{name}")
PY
}

notifica_cliente() {
    local customer_id="$1"
    local info=$(get_cliente_info "$customer_id")
    local email=$(echo "$info" | cut -d'|' -f1)
    local twofa=$(echo "$info" | cut -d'|' -f2)
    local nome=$(echo "$info" | cut -d'|' -f3)
    local twofa_lower=$(echo "$twofa" | tr 'A-Z' 'a-z')
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    if [ "$twofa_lower" = "false" ] || [ "$twofa_lower" = "0" ] || [ "$twofa_lower" = "no" ]; then
        echo "[$timestamp] TO:$email CUSTOMER:$customer_id NAME:$nome SUBJECT:Attiva 2FA - Accesso notturno BODY:Abbiamo rilevato un accesso notturno al tuo conto. Attiva subito l'autenticazione a due fattori." >> "$NOTIFY_LOG"
    else
        echo "[$timestamp] TO:$email CUSTOMER:$customer_id NAME:$nome SUBJECT:Accesso notturno rilevato BODY:Abbiamo rilevato un accesso notturno al tuo conto. Se non riconosci questa attività, contatta il supporto." >> "$NOTIFY_LOG"
    fi
}

# INIZIO MONITORAGGIO
log "P03 start"

echo "================================================================================" >> "$LOG_NOTTURNI"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO ACCESSI NOTTURNI (NETWORK)" >> "$LOG_NOTTURNI"
echo "================================================================================" >> "$LOG_NOTTURNI"

echo "[*] Monitoraggio connessioni TCP verso porta $SERVER_PORT"
echo "[*] Fascia notturna: ${ORA_INIZIO_NOTTE}:00 - 0${ORA_FINE_NOTTE}:00"
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
    
    # Verifica orario notturno
    ORA_CORRENTE=$(date +%H)
    ORA_CORRENTE=${ORA_CORRENTE#0}
    
    is_notturno=0
    if [ $ORA_CORRENTE -ge $ORA_INIZIO_NOTTE ] || [ $ORA_CORRENTE -lt $ORA_FINE_NOTTE ]; then
        is_notturno=1
        echo "  → ORARIO NOTTURNO - Analisi attiva"
    else
        echo "  → Non in orario notturno (skip)"
        sleep $INTERVALLO_CHECK
        continue
    fi
    
    # NETWORK MONITORING: Usa 'ss -tn' per vedere connessioni TCP attive
    # ss -tn: show TCP connections in numeric format (no DNS resolution)
    # grep :8000: filtra connessioni verso porta 8000
    # awk: estrae IP sorgente dalla 4a colonna (remote address)
    
    echo "  → Esecuzione: ss -tn | grep :8000"
    
    CONNESSIONI=$(ss -tn state established | grep ":$SERVER_PORT " | awk '{print $4}' | cut -d: -f1 | sort -u)
    
    if [ -n "$CONNESSIONI" ]; then
        NUM_IPS=$(echo "$CONNESSIONI" | wc -l)
        echo "  → IP sorgente connessi: $NUM_IPS"
        echo ""
        
        # Per ogni IP connesso
        while read -r suspicious_ip; do
            
            if [ -z "$suspicious_ip" ] || [ "$suspicious_ip" = "127.0.0.1" ]; then
                continue
            fi
            
            echo "  [!] CONNESSIONE NOTTURNA DA IP: $suspicious_ip"
            
            # Risolvi hostname con 'host' command
            HOSTNAME=$(host "$suspicious_ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' || echo "UNKNOWN")
            echo "      → Hostname: $HOSTNAME"
            
            # Segnala solo se non già fatto
            if [ -z "${SEGNALATI[$suspicious_ip]}" ]; then
                SEGNALATI[$suspicious_ip]=1
                
                echo "      → PRIMO RILEVAMENTO"
                
                # Aggiungi in blacklist
                if controlla_blacklist "IP" "$suspicious_ip"; then
                    aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_NOTTURNO" "ALTA" 50 \
                        "Connessione notturna da $suspicious_ip; hostname: $HOSTNAME"
                else
                    aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_NOTTURNO" "MEDIA" 30 \
                        "Connessione notturna da $suspicious_ip; hostname: $HOSTNAME"
                fi
                
                # Log dettagliato
                {
                    echo "═══════════════════════════════════════════"
                    echo "ALERT ACCESSO NOTTURNO - $(date '+%Y-%m-%d %H:%M:%S')"
                    echo "═══════════════════════════════════════════"
                    echo "IP Sorgente:  $suspicious_ip"
                    echo "Hostname:     $HOSTNAME"
                    echo "Porta Server: $SERVER_PORT"
                    echo "Ora:          $(date '+%H:%M:%S')"
                } >> "$LOG_NOTTURNI"
                
                log "P03 alert $suspicious_ip"
                ALERT_COUNT=$((ALERT_COUNT + 1))
                break
            fi
            
        done <<< "$CONNESSIONI"
    else
        echo "  → Nessuna connessione attiva verso porta $SERVER_PORT"
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
    echo "[*] Nessun accesso notturno anomalo rilevato"
fi
echo "[*] Log: $LOG_NOTTURNI"
echo "================================================================================"

log "P03 done"

