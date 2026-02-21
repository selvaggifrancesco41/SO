#!/bin/bash

# TEST GENERATOR 02: Anomalia accessi simultanei
#
# SCOPO: Generare 3+ login simultanei dello stesso account
#        da indirizzi IP diversi nello stesso momento
#        Questo pattern viene rilevato da problema_02_accessi_simultanei.sh
#
# PREREQUISITO: server Flask in esecuzione su localhost:8000

SERVER="http://localhost:8000"
ACCOUNT_TARGET="mario.rossi"
PASSWORD="Password123!"
NUM_SESSIONI=4

echo "================================================================================"
echo "[TEST 02] Generazione anomalia - accessi simultanei dallo stesso account"
echo "================================================================================"
echo "[*] Account target: $ACCOUNT_TARGET"
echo "[*] Password: $PASSWORD"
echo "[*] Numero sessioni simultanee: $NUM_SESSIONI"
echo "[*] Simula IP diverse tramite X-Forwarded-For"
echo ""

echo "[TEST] Apertura $NUM_SESSIONI connessioni simultanee..."

# Genera NUM_SESSIONI login simultanei
# Tutti nello stesso momento da "IP diversi"
for i in $(seq 1 $NUM_SESSIONI); do
    IP_MITTENTE="192.168.10.$i"  # Range diverso da test 01
    
    echo "[+] Sessione #$i da $IP_MITTENTE"
    
    # POST /login - simula login da IP diverso
    curl -s -X POST "$SERVER/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP_MITTENTE" \
        -d "{
            \"username\": \"$ACCOUNT_TARGET\",
            \"password\": \"$PASSWORD\"
        }" 2>/dev/null &
done

echo ""
echo "[✓] Accessi simultanei generati"
echo "[*] Durata: i login rimangono attivi per ~30 secondi"
echo "[*] Controlla il log: tail -f logs/accessi_simultanei.log"
wait
