#!/bin/bash

# P02: Detect simultaneous logins from multiple IPs for the same account.

exec 3>&1
exec 1>/dev/null
# Keep only minimal logs on FD3.

log() { echo "$1" >&3; }

BLACKLIST="/workspaces/SO/blacklist.csv"
STATE="/workspaces/SO/logs/simultanei_state.tmp"
REALTIME="/workspaces/SO/logs/realtime_access.log"
NOTIFY="/workspaces/SO/logs/notifiche_email.txt"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

. /workspaces/SO/script/lib_blacklist.sh

mkdir -p $(dirname "$STATE") $(dirname "$NOTIFY")

# Legge info cliente dal CSV (email, 2FA, etc)
get_cliente_info() {
    # Lookup email and 2FA flag from CSV via Python (quoted CSV safe).
    local cid="$1"
    python3 << PYEOF
import csv
found = False
try:
    with open('/workspaces/SO/clienti_banca.csv') as f:
        for row in csv.DictReader(f):
            if str(row.get('customer_id','')).strip() == str($cid):
                email = row.get('email', 'unknown')
                twofa = row.get('two_factor_enabled', 'False').strip()
                print(f"{email}|{twofa}")
                found = True
                break
except:
    pass
if not found:
    print("unknown|False")
PYEOF
}

log "P02 start"

COUNTER=0
ALERTS=0
START=$(date +%s)
declare -A SEEN

# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Hard timeout to keep test runs short.
    ELAPSED=$(($(date +%s) - START))
    [ $ELAPSED -ge 60 ] && break
    
    [ -z "$cid" ] || [ -z "$ip" ] && continue
    
    echo "[+] Login: customer $cid da IP $ip" >&3
    echo "$cid|$ip|$(date +%s)" >> "$STATE"
    
    # Count unique IPs for this customer.
    # awk -F'|': separatore; -v: variabile; sort -u: unici; wc -l: conteggio
    ips_unici=$(awk -F'|' -v c="$cid" '$1==c {print $2}' "$STATE" 2>/dev/null | sort -u | wc -l)
    echo "  IP unici: $ips_unici" >&3
    
    if [ $ips_unici -ge 3 ] && [ -z "${SEEN[$cid]}" ]; then
        SEEN[$cid]=1
        log "P02 alert $ips_unici IPs rilevati"
        # Append with accumulated risk/recidivita.
        add_blacklist_entry "ACCOUNT" "$cid" "ACCESSO_SIMULTANEO" "ALTA" "40" "ACCESSI_RETE" "$ips_unici IP simultanei"
        
        # Leggi info cliente dal CSV
        INFO=$(get_cliente_info "$cid")
        # cut -d'|': separatore pipe; -f: campo
        EMAIL=$(echo "$INFO" | cut -d'|' -f1)
        TWO_FA=$(echo "$INFO" | cut -d'|' -f2)
        
        # Se 2FA non è abilitato, invia notifica
        if [ "$TWO_FA" != "True" ] && [ "$TWO_FA" != "true" ] && [ "$TWO_FA" != "Sì" ]; then
            {
                echo "═════════════════════════════════════════════════════"
                echo "EVENT: Accessi simultanei rilevati"
                echo "DATA: $(date '+%Y-%m-%d %H:%M:%S')"
                echo "CLIENTE: $cid"
                echo "EMAIL: $EMAIL"
                echo "IP_SIMULTANEI: $ips_unici"
                echo "AVVISO: Account compromesso? 2FA NON ABILITATO!"
                echo "ACTION: Abilitare 2FA e verificare attività"
                echo "═════════════════════════════════════════════════════"
                echo ""
            } >> "$NOTIFY"
            log "P02 notify $EMAIL 2FA disabled"
        fi
        
        ALERTS=$((ALERTS+1))
        kill %1 2>/dev/null
        exit 0
    fi
done &
wait $!

log "P02 done"
