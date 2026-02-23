#!/bin/bash

# P09: Detect inconsistent operations by network context.
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
    # Case 1: ATM subnet performing BONIFICO.
    if [[ "$ip" =~ ^192\.168\.30\. ]] && [ "$az" = "BONIFICO" ]; then
        [ -z "${SEEN[$cid]}" ] || continue
        SEEN[$cid]=1; log "P09 alert $cid incoerente"
        add_blacklist_entry "IP" "$ip" "INCOERENZA_RETE" "ALTA" "100" "ATM_BONIFICO" "ATM (192.168.30.x) esegue BONIFICO"
        kill %1 2>/dev/null; exit 0
    fi

    # Case 2: API subnet performing PRELIEVO.
    if [[ "$ip" =~ ^192\.168\.40\. ]] && [ "$az" = "PRELIEVO" ]; then
        [ -z "${SEEN[$cid]}" ] || continue
        SEEN[$cid]=1; log "P09 alert $cid incoerente"
        add_blacklist_entry "IP" "$ip" "INCOERENZA_RETE" "ALTA" "100" "API_PRELIEVO" "API (192.168.40.x) esegue PRELIEVO"
        kill %1 2>/dev/null; exit 0
    fi

    # Case 3: Public IP performing LOGIN.
    if [[ "$ip" =~ ^203\.0\.113\. ]] && [ "$az" = "LOGIN" ]; then
        [ -z "${SEEN[$cid]}" ] || continue
        SEEN[$cid]=1; log "P09 alert $cid incoerente"
        add_blacklist_entry "IP" "$ip" "INCOERENZA_RETE" "ALTA" "100" "PUBBLICO_LOGIN" "IP pubblico (203.0.113.x) esegue LOGIN"
        kill %1 2>/dev/null; exit 0
    fi
done &
wait $!; log "P09 done"
