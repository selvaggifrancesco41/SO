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
echo "[*] Mantenendo connessioni aperte per 30 secondi per sovrapporre i tempi..."
echo ""

# Genera NUM_SESSIONI login simultanei
# Tutti nello stesso momento da "IP diversi"
for i in $(seq 1 $NUM_SESSIONI); do
    IP_MITTENTE="192.168.10.$i"  # Range diverso da test 01
    
    echo "[+] Sessione #$i da $IP_MITTENTE (si aprirà per 30 secondi)"
    
    # GET /login - parametri nella query string
    # --max-time 30: mantiene la connessione aperta per 30 secondi
    curl -s --max-time 30 \
        -G "$SERVER/login" \
        --data-urlencode "customer_id=$ACCOUNT_TARGET" \
        --data-urlencode "session_duration=30" \
        -H "X-Forwarded-For: $IP_MITTENTE" 2>/dev/null &
done

echo ""
echo "[*] Tutte le 4 sessioni dovrebbero essere attive contemporaneamente"
echo "[*] Attendi che il monitoraggio le rilevi..."

echo ""
echo "[✓] Accessi simultanei generati"
echo "[*] Durata: i login rimangono attivi per ~30 secondi"
echo "[*] Controlla il log: tail -f logs/accessi_simultanei.log"
wait
