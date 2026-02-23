#!/bin/bash

# P04: Detect ATM subnet traffic that should not appear on this channel.
exec 3>&1; exec 1>/dev/null
# Keep only minimal logs on FD3.
log() { echo "$1" >&3; }
BLACKLIST="/workspaces/SO/blacklist.csv"
REALTIME="/workspaces/SO/logs/realtime_access.log"

. /workspaces/SO/script/lib_blacklist.sh
log "P04 start"
START=$(date +%s); declare -A SEEN
# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Stop after 60s for predictable tests.
    [ $(($(date +%s) - START)) -ge 60 ] && break
    # ATM subnet range check.
    [[ "$ip" =~ ^192\.168\.30\. ]] || continue
    [ -z "${SEEN[$ip]}" ] || continue
    SEEN[$ip]=1; log "P04 alert $ip ATM"
    # Append with accumulated risk/recidivita.
    add_blacklist_entry "IP" "$ip" "ATM_ANOMALO" "MEDIA" "35" "RETE_ATM" "IP ATM subnet 192.168.30.x rilevato"
    kill %1 2>/dev/null; exit 0
done &
wait $!; log "P04 done"
