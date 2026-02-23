#!/bin/bash

# Shared blacklist helpers: keep header, accumulate risk, set BLOCKED at 100.

BLACKLIST="/workspaces/SO/blacklist.csv"

ensure_blacklist_header() {
    # Ensure the CSV exists with the expected header line.
    local header="timestamp,tipo_elemento,elemento,azione_rilevata,gravita,recidivita,risk_score,stato,origine_rilevazione,note"
    if [ ! -f "$BLACKLIST" ] || [ ! -s "$BLACKLIST" ]; then
        echo "$header" > "$BLACKLIST"
        return 0
    fi
    local first
    # head -1: prima riga (header)
    first=$(head -1 "$BLACKLIST")
    if [ "$first" != "$header" ]; then
        {
            echo "$header"
            cat "$BLACKLIST"
        } > "${BLACKLIST}.tmp" && mv "${BLACKLIST}.tmp" "$BLACKLIST"
    fi
}

add_blacklist_entry() {
    # Append a new row, increasing recidivita and risk if element already exists.
    local tipo_elemento="$1"
    local elemento="$2"
    local azione="$3"
    local gravita="$4"
    local base_risk="$5"
    local origine="$6"
    local note="$7"

    ensure_blacklist_header

    local prev
    # Read last recidivita/risk for this element (if any).
    # awk -F',': separatore CSV; -v: passa variabili a awk
    prev=$(awk -F',' -v t="$tipo_elemento" -v e="$elemento" 'NR>1 && $2==t && $3==e {rec=$6; risk=$7} END {if (rec=="") print "0|0"; else print rec "|" risk}' "$BLACKLIST")
    local prev_rec
    local prev_risk
    # cut -d'|': separatore pipe; -f: campo
    prev_rec=$(echo "$prev" | cut -d'|' -f1)
    prev_risk=$(echo "$prev" | cut -d'|' -f2)

    prev_rec=${prev_rec:-0}
    prev_risk=${prev_risk:-0}

    local new_rec=$((prev_rec + 1))
    local new_risk=$((prev_risk + base_risk))
    local stato="ACTIVE"
    # Block once accumulated risk reaches 100.
    if [ "$new_risk" -ge 100 ]; then
        stato="BLOCKED"
    fi

    echo "$(date '+%Y-%m-%d %H:%M:%S'),$tipo_elemento,$elemento,$azione,$gravita,$new_rec,$new_risk,$stato,$origine,$note" >> "$BLACKLIST"
}
