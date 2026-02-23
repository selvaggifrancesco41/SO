#!/bin/bash

# Quick smoke test for P04-P10 using their generators.
cd /workspaces/SO

# Test each problem
for i in 4 5 6 7 8 9 10; do
    echo "═══════════════════════════════════════════"
    echo "Testing P0$i..."
    echo "═══════════════════════════════════════════"
    
    # Keep header and last line only to reduce noise.
    # tail -1: ultima riga; head -1: prima riga
    tail -1 blacklist.csv > blacklist.csv.tmp
    head -1 blacklist.csv > blacklist.csv.bak
    cat blacklist.csv.bak blacklist.csv.tmp > blacklist.csv.new 2>/dev/null && mv blacklist.csv.new blacklist.csv || true
    rm -f blacklist.csv.tmp blacklist.csv.bak
    
    # head -20: mostra solo le prime 20 righe di output
    TEST_MODE=1 timeout 15 ./script/run_problem.sh $i 2>&1 | head -20
    
    ALERTS=$(tail -1 blacklist.csv)
    if [ "$ALERTS" != "timestamp,tipo_elemento,elemento,azione_rilevata,gravita,recidivita,risk_score,stato,origine_rilevazione,note" ]; then
        echo "✓ P0$i: ALERT GENERATED"
        echo "  Alert: $ALERTS" | cut -c1-100
    else
        echo "✗ P0$i: NO ALERT"
    fi
    echo ""
done
