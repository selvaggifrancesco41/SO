#!/bin/bash

# P01: Detect AML pattern (many senders to same IBAN) from realtime stream.

exec 3>&1
exec 1>/dev/null
# Keep stderr/FD3 for minimal logs, silence normal stdout.

log() { echo "$1" >&3; }

BLACKLIST="/workspaces/SO/blacklist.csv"
LOG_AML="/workspaces/SO/logs/aml_alerts.log"
STATE="/workspaces/SO/logs/aml_state.tmp"
REALTIME="/workspaces/SO/logs/realtime_access.log"

. /workspaces/SO/script/lib_blacklist.sh

mkdir -p $(dirname "$LOG_AML") $(dirname "$STATE")

log "P01 start"

COUNTER=0
ALERTS=0 
START=$(date +%s)
declare -A SEEN

# tail -f: segue il file in tempo reale
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    # Stop after 60s to keep tests bounded.
    ELAPSED=$(($(date +%s) - START))
    [ $ELAPSED -ge 60 ] && break
    
    [ "$az" != "BONIFICO" ] && continue
    [ -z "$cid" ] || [ -z "$iban" ] || [ -z "$imp" ] && continue
    
    echo "[+] $cid → $iban €$imp" >&3
    echo "$cid|$iban|$imp|$(date +%s)" >> "$STATE"
    
    # Count unique senders for the same destination IBAN.
    # awk -F'|': separatore pipe; -v: variabile; sort -u: unici; wc -l: conteggio righe
    uniq=$(awk -F'|' -v i="$iban" '$2==i {print $1}' "$STATE" 2>/dev/null | sort -u | wc -l)
    echo "  Mittenti: $uniq" >&3
    
    if [ $uniq -ge 5 ] && [ -z "${SEEN[$iban]}" ]; then
        SEEN[$iban]=1
        log "P01 alert $iban"
        # Append with accumulated risk/recidivita.
        add_blacklist_entry "ACCOUNT" "$cid" "FLUSSO_AML" "ALTA" "50" "AML_RETE" "Schema AML: $uniq mittenti verso IBAN $iban"
        ALERTS=$((ALERTS+1))
        # ESCI SUBITO dopo primo alert (test veloce)
        kill $TAIL_PID 2>/dev/null
        exit 0
    fi
done &
TAIL_PID=$!

# Aspetta che tail-f termini (exit 0 quando trova anomalia)
wait $TAIL_PID 2>/dev/null

log "P01 done"
