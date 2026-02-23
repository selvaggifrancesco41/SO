#!/bin/bash

# P10: Detect low-and-slow behavior (many small operations).
exec 3>&1; exec 1>/dev/null
# Keep only minimal logs on FD3.
log() { echo "$1" >&3; }
BLACKLIST="/workspaces/SO/blacklist.csv"
STATE="/workspaces/SO/logs/low_slow_state.tmp"
REALTIME="/workspaces/SO/logs/realtime_access.log"

. /workspaces/SO/script/lib_blacklist.sh
mkdir -p $(dirname "$STATE")
log "P10 start"
START=$(date +%s); declare -A SEEN
# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Stop after 60s for predictable tests.
    [ $(($(date +%s) - START)) -ge 60 ] && break # Solo per test prevedibili
    [ -z "$imp" ] || [ "$imp" -gt 100 ] && continue #-z vuol dire "importo vuoto"; se importo > 100 non è "low"
    # Track per-customer small operations.
    echo "$cid|$ts" >> "$STATE"
    count=$(grep "^$cid|" "$STATE" 2>/dev/null | wc -l)
    [ $count -lt 8 ] && continue
    [ -z "${SEEN[$cid]}" ] || continue
    SEEN[$cid]=1; log "P10 alert $cid low_slow"
    # Append with accumulated risk/recidivita.
    add_blacklist_entry "ACCOUNT" "$cid" "LOW_SLOW" "MEDIA" "35" "ATTACCO_LENTO" "$count operazioni lente/piccole da $cid"
    kill %1 2>/dev/null; exit 0
done &
wait $!; log "P10 done"
