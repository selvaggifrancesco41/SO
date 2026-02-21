#!/bin/bash

# Test automatico problema 01 senza interazione
echo "[*] Test automatico problema 01 - AML Bonifici"
echo ""

# Pulisci log
rm -f /workspaces/SO/logs/realtime_access.log
rm -f /workspaces/SO/logs/aml_alerts.log
rm -f /workspaces/SO/logs/aml_state.tmp

# Avvia monitoraggio in background
echo "[*] Avvio monitoraggio..."
/workspaces/SO/script/problema_01_aml_bonifici.sh > /tmp/problema_01_output.log 2>&1 &
MONITOR_PID=$!

sleep 3
echo "[✓] Monitoraggio avviato (PID: $MONITOR_PID)"

# Lancia il test generator
echo "[*] Avvio test generator..."
/workspaces/SO/script/test_generators/test_01_aml_bonifici.sh

echo ""
echo "[*] Test completato, attendo 5 secondi..."
sleep 5

# Termina il monitoraggio
kill $MONITOR_PID 2>/dev/null

echo ""
echo "[✓] Risultati monitoraggio:"
cat /tmp/problema_01_output.log

echo ""
echo "[✓] Blacklist updates:"
tail -5 /workspaces/SO/blacklist.csv
