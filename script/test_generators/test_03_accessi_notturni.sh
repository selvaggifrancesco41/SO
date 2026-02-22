#!/bin/bash

# TEST GENERATOR 03: Anomalia accessi notturni
#
# SCOPO: Generare login durante orari notturni (22:00-06:00)
#        NOTA: Il monitoring script deve essere avviato con TEST_MODE=1
#              per bypassare il controllo orario reale
#        Viene rilevato da problema_03_accessi_notturni.sh
#
# PREREQUISITO: server Flask in esecuzione su localhost:8000

SERVER="http://localhost:8000"
NUM_ACCESSI=3

echo "================================================================================"
echo "[TEST 03] Generazione anomalia - accessi notturni fuori profilo"
echo "================================================================================"

CURRENT_HOUR=$(date +%H)
echo "[*] Ora attuale: $CURRENT_HOUR:00"

# Verifica se siamo in fascia notturna (22:00-06:00)
if [[ $CURRENT_HOUR -ge 22 || $CURRENT_HOUR -lt 6 ]]; then
    echo "[✓] Siamo in fascia notturna - test procede normalmente"
else
    echo "[!] Ora attuale NON è notturna (22:00-06:00)"
    echo "[!] NOTA: Il monitoring è stato avviato in MODALITÀ TEST"
    echo "[!]       Il controllo orario è bypassato per permettere il testing"
fi

echo ""
echo "[TEST] Generazione $NUM_ACCESSI login in orario notturno..."
echo ""

for i in $(seq 1 $NUM_ACCESSI); do
    USERNAME="user_notturno_$i"
    IP_MITTENTE="192.168.20.$i"
    
    echo "[+] Login #$i - User: $USERNAME da $IP_MITTENTE"
    
    # GET /login - parametri nella query string
    curl -s -G "$SERVER/login" \
        --data-urlencode "customer_id=$USERNAME" \
        --data-urlencode "session_duration=$((RANDOM % 60))" \
        -H "X-Forwarded-For: $IP_MITTENTE"
    
    echo ""
    sleep 1
done

echo ""
echo "[✓] Accessi notturni generati"
echo "[*] I login sono stati registrati nel database"
echo "[*] Il monitoring li rileverà nel prossimo check"
echo ""
