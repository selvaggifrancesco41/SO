#!/bin/bash

# TEST GENERATOR 08: Anomalia canali covert - traffico persistente nascosto
#
# SCOPO: Generare connessioni persistenti che rimangono aperte
#        senza generare dati, simulando canale covert
#        Viene rilevato da problema_08_covert_channels.sh
#
# METODO: Apre connessiones che rimangono in ESTABLISHED senza trasmissione dati

echo "================================================================================"
echo "[TEST 08] Generazione anomalia - canali covert (traffico persistente)"
echo "================================================================================"
echo "[*] Simula connessioni persistenti senza dati"
echo "[*] Tipico di esfiltrazione lenta e command & control"
echo ""

# Verifica netcat
if ! command -v nc &> /dev/null; then
    echo "[!] netcat non installato, uso sleep + /dev/tcp"
fi

echo "[TEST] Apertura connessioni persistenti verso porta 8000..."

NUM_COVERT=4

for i in $(seq 1 $NUM_COVERT); do
    echo "[+] Connessione covert #$i (rimarrà aperta 60 secondi)"
    
    # Metodo 1: netcat se disponibile
    if command -v nc &> /dev/null; then
        timeout 60 nc localhost 8000 < /dev/null > /dev/null 2>&1 &
    else
        # Metodo 2: bash con /dev/tcp
        (sleep 60 < /dev/null > /dev/tcp/localhost/8000 2>/dev/null) &
    fi
done

echo ""
echo "[✓] $NUM_COVERT connessioni covert aperte"
echo "[*] Rimangono attive per 60 secondi nello stato ESTABLISHED"
echo "[*] Controlla connessioni: ss -tan | grep 127.0.0.1:8000"
echo "[*] Log: tail -f logs/covert_channels.log"
wait
