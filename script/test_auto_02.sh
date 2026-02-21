#!/bin/bash

# Test automatico problema 02 senza interazione
echo "[*] Test automatico problema 02 - Accessi simultanei"
echo ""

# Pulisci log
rm -f /workspaces/SO/logs/realtime_access.log
rm -f /workspaces/SO/logs/simultanei_alerts.log
rm -f /workspaces/SO/logs/simultanei_state.tmp
echo "timestamp,tipo_elemento,elemento,azione_rilevata,gravita,recidivita,risk_score,stato,origine_rilevazione,note" > /workspaces/SO/blacklist.csv

# Avvia monitoraggio in background
echo "[*] Avvio monitoraggio..."
/workspaces/SO/script/problema_02_accessi_simultanei.sh > /tmp/problema_02_output.log 2>&1 &
MONITOR_PID=$!

sleep 3
echo "[✓] Monitoraggio avviato (PID: $MONITOR_PID)"

# Lancia il test generator
echo "[*] Avvio test generator..."
/workspaces/SO/script/test_generators/test_02_accessi_simultanei.sh

echo ""
echo "[*] Test completato, attendo 10 secondi per rilevamento..."
sleep 10

# Termina il monitoraggio
kill $MONITOR_PID 2>/dev/null

echo ""
echo "[✓] Risultati monitoraggio (ultimi 40 righe):"
tail -40 /tmp/problema_02_output.log

echo ""
echo "[✓] Blacklist updates:"
grep -c "192.168.10" /workspaces/SO/blacklist.csv || echo "0"
echo "IP distinti in blacklist:"
grep "192.168.10" /workspaces/SO/blacklist.csv | awk -F',' '{print $3}' | sort -u
