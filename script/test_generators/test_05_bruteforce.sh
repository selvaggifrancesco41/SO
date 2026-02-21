#!/bin/bash

# TEST GENERATOR 05: Anomalia brute-force su /login
#
# SCOPO: Generare 15+ tentativi falliti di login verso /login
#        da uno stesso IP in breve tempo (< 60 secondi)
#        Viene rilevato da problema_05_bruteforce.sh
#
# PREREQUISITO: server Flask in esecuzione su localhost:8000

SERVER="http://localhost:8000"
NUM_TENTATIVI=15
SLEEP_TRA_TENTATIVI=2  # secondi tra un tentativo e l'altro

echo "================================================================================"
echo "[TEST 05] Generazione anomalia - brute-force su endpoint /login"
echo "================================================================================"
echo "[*] Endpoint target: POST /login"
echo "[*] Numero tentativi: $NUM_TENTATIVI"
echo "[*] Intervallo tra tentativi: ${SLEEP_TRA_TENTATIVI}s"
echo "[*] Tempo totale: ~$((NUM_TENTATIVI * SLEEP_TRA_TENTATIVI))s"
echo ""

echo "[TEST] Generazione tentativi falliti da IP: 192.168.40.100"
echo "[!] Tutti gli username/password sono ERRATI (dovrebbero fallire)"
echo ""

for i in $(seq 1 $NUM_TENTATIVI); do
    # Genera username/password variabili per sembrare attacco sistematico
    USERNAME="admin_$i"
    IP_ATTACCANTE="192.168.40.100"
    
    echo "[+] Tentativo #$i: user=$USERNAME"
    
    # GET /login - parametri nella query string
    curl -s -G "$SERVER/login" \
        --data-urlencode "customer_id=$USERNAME" \
        --data-urlencode "session_duration=5" \
        -H "X-Forwarded-For: $IP_ATTACCANTE" 2>/dev/null &
    
    sleep $SLEEP_TRA_TENTATIVI
done

echo ""
echo "[✓] Tutti i tentativi brute-force generati"
echo "[*] Il problema_05 dovrebbe rilevare pattern di attacco"
echo "[*] Controlla il log: tail -f logs/bruteforce_alerts.log"
wait
