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
    # Apre connessione curl verso /saldo (endpoint leggero)
    # --keepalive-time: mantiene connessione aperta
    # -m 30: timeout 30 secondi (mantiene socket attivo)
    curl -s --max-time 30 \
        -H "X-Forwarded-For: 192.168.50.$i" \
        "http://$SERVER_IP:$SERVER_PORT/saldo" > /dev/null 2>&1 &
    
    echo "[+] Connessione #$i aperta (timerà 30s)"
    sleep 0.2
done

echo ""
echo "[✓] Spike di $NUM_CONNESSIONI connessioni generato"
echo "[*] Le connessioni rimangono aperte per 30 secondi"
echo "[*] Controlla con: ss -tan | grep :8000 | wc -l"
echo "[*] Log: tail -f logs/correlazione_rete.log"
wait
