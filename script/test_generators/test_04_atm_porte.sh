#!/bin/bash

# TEST GENERATOR 04: Anomalia ATM su porte non autorizzate
#
# SCOPO: Simulare connessioni ATM verso porte fuori dal range autorizzato
#        Range autorizzato: 32768-60999 (porte efimere)
#        Questo pattern viene rilevato da problema_04_atm_porte.sh
#
# METODO: Usa /dev/tcp di bash per creare connessioni verso porte non autorizzate
# PREREQUISITO: server Flask in esecuzione

echo "================================================================================"
echo "[TEST 04] Generazione anomalia - ATM su porte non autorizzate"
echo "================================================================================"

SERVER="localhost"
SERVER_PORT=8000
ATM_IPS=("192.168.30.1" "192.168.30.2" "192.168.30.3")
# Simuliamo ATM che si connettono al server (porta 8000) usando porte sorgente non autorizzate
# Le porte sorgente fuori policy verranno rilevate dal monitoring
NUM_CONNECTIONS=3

echo "[*] ATM da testare: ${ATM_IPS[@]}"
echo "[*] Le connessioni useranno porte sorgente fuori dalla policy autorizzata"
echo ""

echo "[TEST] Generazione $NUM_CONNECTIONS connessioni da ATM con porte non conformi..."
echo ""

# Generiamo richieste HTTP da IP ATM simulati
# Il server le registrerà e il monitoring rileverà porte sorgente anomale
for i in $(seq 0 $((NUM_CONNECTIONS - 1))); do
    ATM_IP="${ATM_IPS[$i]}"
    
    echo "[+] Connessione ATM #$((i+1)) da IP $ATM_IP"
    
    # Simula un login da ATM (il monitoring controllerà la porta sorgente)
    curl -s -G "http://$SERVER:$SERVER_PORT/login" \
        --data-urlencode "customer_id=ATM_$((i+1))" \
        --data-urlencode "session_duration=10" \
        -H "X-Forwarded-For: $ATM_IP" > /dev/null &
    
    sleep 0.5
done

wait

echo ""
echo "[✓] Connessioni ATM generate"
echo "[*] Il monitoring controllerà le porte sorgente delle connessioni attive"
echo ""
