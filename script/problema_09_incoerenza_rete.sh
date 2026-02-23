#!/bin/bash

# P09: Detect inconsistent operations (ATM subnet performing BONIFICO).
exec 3>&1; exec 1>/dev/null
# Keep only minimal logs on FD3.
log() { echo "$1" >&3; }
BLACKLIST="/workspaces/SO/blacklist.csv"
REALTIME="/workspaces/SO/logs/realtime_access.log"

. /workspaces/SO/script/lib_blacklist.sh
log "P09 start"
START=$(date +%s); declare -A SEEN
# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Stop after 60s for predictable tests.
    [ $(($(date +%s) - START)) -ge 60 ] && break
    # ATM subnet check.
    [[ "$ip" =~ ^192\.168\.30\. ]] || continue
    [ "$az" = "BONIFICO" ] || continue
    [ -z "${SEEN[$cid]}" ] || continue
    SEEN[$cid]=1; log "P09 alert $cid incoerente"
    # Append with accumulated risk/recidivita (likely blocks immediately at 100).
    add_blacklist_entry "IP" "$ip" "INCOERENZA_RETE" "ALTA" "100" "ATM_BONIFICO" "ATM (192.168.30.x) esegue BONIFICO"
    kill %1 2>/dev/null; exit 0
done &
wait $!; log "P09 done"
