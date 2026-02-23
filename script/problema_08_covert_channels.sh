#!/bin/bash

# P08: Detect zero-amount bonifici used as covert signals.
exec 3>&1; exec 1>/dev/null
# Keep only minimal logs on FD3.
log() { echo "$1" >&3; }
BLACKLIST="/workspaces/SO/blacklist.csv"
REALTIME="/workspaces/SO/logs/realtime_access.log"

. /workspaces/SO/script/lib_blacklist.sh
log "P08 start"
START=$(date +%s); declare -A SEEN
# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Stop after 60s for predictable tests.
    [ $(($(date +%s) - START)) -ge 60 ] && break
    [ "$az" != "BONIFICO" ] && continue
    [ "$imp" != "0" ] && continue
    [ -z "${SEEN[$cid]}" ] || continue
    SEEN[$cid]=1; log "P08 alert $cid covert"
    # Append with accumulated risk/recidivita.
    add_blacklist_entry "ACCOUNT" "$cid" "COVERT_CHANNEL" "MEDIA" "40" "BONIFICO_ZERO" "Bonifico con importo=0 (canale covert)"
    kill %1 2>/dev/null; exit 0
done &
wait $!; log "P08 done"
