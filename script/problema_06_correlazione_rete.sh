#!/bin/bash

# P06: Flag access from public IPs (outside RFC1918 ranges).
exec 3>&1; exec 1>/dev/null
# Keep only minimal logs on FD3.
log() { echo "$1" >&3; }
BLACKLIST="/workspaces/SO/blacklist.csv"
REALTIME="/workspaces/SO/logs/realtime_access.log"
is_public_ip() { [[ "$1" =~ ^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.) ]] && echo 0 || echo 1; }
 # Return 1 when the IP is public.

. /workspaces/SO/script/lib_blacklist.sh
log "P06 start"
START=$(date +%s); declare -A SEEN
# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Stop after 60s for predictable tests.
    [ $(($(date +%s) - START)) -ge 60 ] && break
    [ -z "$ip" ] && continue
    [ "$(is_public_ip "$ip")" != "1" ] && continue
    [ -z "${SEEN[$ip]}" ] || continue
    SEEN[$ip]=1; log "P06 alert $ip pubblico"
    # Append with accumulated risk/recidivita.
    add_blacklist_entry "IP" "$ip" "IP_PUBBLICO" "ALTA" "45" "RETE_PUBBLICA" "IP pubblico rilevato: $ip"
    kill %1 2>/dev/null; exit 0
done &
wait $!; log "P06 done"
