#!/bin/bash

# TEST GENERATOR 06: Anomalia correlazione rete - degrado servizio
#
# SCOPO: Generare spike di connessioni TCP verso il server
#        per simulare degradazione progressiva del servizio
#        Viene rilevato da problema_06_correlazione_rete.sh
#
# METODO: Apre molte connessioni simultanee verso porte diverse

SERVER_IP="127.0.0.1"
SERVER_PORT=8000
NUM_CONNESSIONI=20

echo "================================================================================"
echo "[TEST 06] Generazione anomalia - spike di connessioni (degradazione)"
echo "================================================================================"
echo "[*] Target: $SERVER_IP:$SERVER_PORT"
echo "[*] Numero connessioni simultanee: $NUM_CONNESSIONI"
echo ""

echo "[TEST] Apertura spike di connessioni..."

for i in $(seq 1 $NUM_CONNESSIONI); do
    # Usa bash /dev/tcp per mantenere connessione TCP aperta
    # Mantiene socket fino a che non scade il timer
    (bash -c "exec 3<>/dev/tcp/$SERVER_IP/$SERVER_PORT; sleep 30; exec 3>&-" > /dev/null 2>&1) &
    
    echo "[+] Connessione #$i aperta (timerà 30s)"
    sleep 0.05
done

echo ""
echo "[✓] Spike di $NUM_CONNESSIONI connessioni generato"
echo "[*] Le connessioni rimangono aperte per 30 secondi"
echo "[*] Controlla con: ss -tan | grep :8000 | wc -l"
echo "[*] Log: tail -f logs/correlazione_rete.log"
wait
