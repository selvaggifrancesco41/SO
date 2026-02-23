#!/bin/bash

# P05: Detect repeated LOGIN attempts from the same IP in short time.
exec 3>&1; exec 1>/dev/null
# Keep only minimal logs on FD3.
log() { echo "$1" >&3; }
BLACKLIST="/workspaces/SO/blacklist.csv"
STATE="/workspaces/SO/logs/bruteforce_state.tmp"
REALTIME="/workspaces/SO/logs/realtime_access.log"

. /workspaces/SO/script/lib_blacklist.sh
mkdir -p $(dirname "$STATE")
log "P05 start"
START=$(date +%s); declare -A SEEN
# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Stop after 60s for predictable tests.
    [ $(($(date +%s) - START)) -ge 60 ] && break
    [ "$az" != "LOGIN" ] && continue
    # Track attempt timestamps per IP.
    echo "$ip|$(date +%s)" >> "$STATE"
    attempts=$(grep "^$ip|" "$STATE" 2>/dev/null | wc -l)
    [ $attempts -lt 5 ] && continue
    [ -z "${SEEN[$ip]}" ] || continue
    SEEN[$ip]=1; log "P05 alert $ip bruteforce"
    # Append with accumulated risk/recidivita.
    add_blacklist_entry "IP" "$ip" "BRUTEFORCE_LOGIN" "ALTA" "50" "LOGIN_RETE" "$attempts tentativi LOGIN da $ip"
    kill %1 2>/dev/null; exit 0
done &
wait $!; log "P05 done"
