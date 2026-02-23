#!/bin/bash

# P03: Flag logins during night hours (22-06); TEST_MODE bypasses time check.
exec 3>&1; exec 1>/dev/null
# Keep only minimal logs on FD3.
log() { echo "$1" >&3; }

BLACKLIST="/workspaces/SO/blacklist.csv"
REALTIME="/workspaces/SO/logs/realtime_access.log"
NOTIFY="/workspaces/SO/logs/notifiche_email.txt"

. /workspaces/SO/script/lib_blacklist.sh

mkdir -p $(dirname "$NOTIFY")

# Legge email dal CSV
get_email() {
    # CSV lookup for email by customer_id.
    local cid="$1"
    python3 << PYEOF
import csv
try:
    with open('/workspaces/SO/clienti_banca.csv') as f:
        for row in csv.DictReader(f):
            if str(row.get('customer_id','')).strip() == str($cid):
                print(row.get('email', 'unknown'))
                exit(0)
except:
    pass
print('unknown')
PYEOF
}

log "P03 start"
START=$(date +%s); declare -A SEEN
# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Stop after 60s for predictable tests.
    [ $(($(date +%s) - START)) -ge 60 ] && break
    [ -z "$cid" ] && continue
    
    # Se TEST_MODE=1, tutto è considerato "notturno" per testing
    # TEST_MODE lets tests run regardless of actual system time.
    if [ "$TEST_MODE" = "1" ]; then
        is_notturno=1
    else
        # date -d: parse data dal testo (timestamp log)
        hour=$(date -d "$ts" '+%H' 2>/dev/null || echo "12")
        if [ "$hour" -ge 22 ] || [ "$hour" -lt 6 ]; then
            is_notturno=1
        else
            is_notturno=0
        fi
    fi
    
    if [ "$is_notturno" = "1" ]; then
        [ -z "${SEEN[$cid]}" ] || continue
        SEEN[$cid]=1
        log "P03 alert $cid notturno"
        # Append with accumulated risk/recidivita.
        # date -d: formatta l'ora dal timestamp
        add_blacklist_entry "ACCOUNT" "$cid" "ACCESSO_NOTTURNO" "MEDIA" "30" "PROFILO_RETE" "Accesso anomalo $(date -d "$ts" '+%H:%M' 2>/dev/null || echo 'unknown')"
        
        EMAIL=$(get_email "$cid")
        {
            echo "═════════════════════════════════════════════════════"
            echo "EVENT: Accesso anomalo rilevato"
            echo "DATA: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "CLIENTE: $cid"
            echo "EMAIL: $EMAIL"
            echo "IP: $ip"
            echo "AVVISO: Accesso rilevato fuori dagli orari abituali"
            echo "ACTION: Verificare l'accesso o contattare il supporto"
            echo "═════════════════════════════════════════════════════"
            echo ""
        } >> "$NOTIFY"
        log "P03 notify $EMAIL anomalo"
        
        kill %1 2>/dev/null; exit 0
    fi
done &
wait $!; log "P03 done"
