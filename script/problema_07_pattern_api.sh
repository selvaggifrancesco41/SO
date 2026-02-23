#!/bin/bash

# P07: Detect bursty API patterns from a single IP.
exec 3>&1; exec 1>/dev/null
# Keep only minimal logs on FD3.
log() { echo "$1" >&3; }
BLACKLIST="/workspaces/SO/blacklist.csv"
STATE="/workspaces/SO/logs/api_state.tmp"
REALTIME="/workspaces/SO/logs/realtime_access.log"

. /workspaces/SO/script/lib_blacklist.sh
mkdir -p $(dirname "$STATE")
log "P07 start"
START=$(date +%s); declare -A SEEN
# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Stop after 60s for predictable tests.
    [ $(($(date +%s) - START)) -ge 60 ] && break
    # Track per-IP requests to detect spammy patterns.
    echo "$ip|$az" >> "$STATE"
    requests=$(grep "^$ip|" "$STATE" 2>/dev/null | wc -l)
    [ $requests -lt 10 ] && continue
    [ -z "${SEEN[$ip]}" ] || continue
    SEEN[$ip]=1; log "P07 alert $ip API abuse"
    # Append with accumulated risk/recidivita.
    add_blacklist_entry "IP" "$ip" "PATTERN_API" "MEDIA" "35" "API_SPAM" "$requests richieste da $ip"
    kill %1 2>/dev/null; exit 0
done &
wait $!; log "P07 done"
