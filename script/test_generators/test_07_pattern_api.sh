#!/bin/bash

# TEST GENERATOR 07: Anomalia pattern API - automazione non autorizzata
#
# SCOPO: Generare sequenze meccaniche e ripetitive di richieste API
#        senza variabilità (tipico di bot/automazione sospetta)
#        Viene rilevato da problema_07_pattern_api.sh
#
# METODO: Fa sempre la stessa sequenza di endpoint nello stesso ordine

SERVER="http://localhost:8000"
CICLI=5

echo "================================================================================"
echo "[TEST 07] Generazione anomalia - pattern API ripetitivo (bot/automazione)"
echo "================================================================================"
echo "[*] Sequenza API da ripetere: /saldo → /bonifico_info → /saldo"
echo "[*] Numero cicli: $CICLI"
echo "[*] Pattern: RIGIDO E MECCANICO (tipico di bot)"
echo ""

echo "[TEST] Generazione traffico API ripetitivo..."

for ciclo in $(seq 1 $CICLI); do
    echo "[+] Ciclo $ciclo: sequenza rigida di API"
    
    # Sequenza 1: /prelievo
    curl -s -G "$SERVER/prelievo" \
        --data-urlencode "customer_id=bot_pattern" \
        --data-urlencode "importo=100" \
        -H "X-Forwarded-For: 192.168.60.100" > /dev/null 2>&1 &
    sleep 0.5
    
    # Sequenza 2: /deposito (API correlata)
    curl -s -G "$SERVER/deposito" \
        --data-urlencode "customer_id=bot_pattern" \
        --data-urlencode "importo=50" \
        -H "X-Forwarded-For: 192.168.60.100" > /dev/null 2>&1 &
    sleep 0.5
    
    # Sequenza 3: /prelievo (identica a primo)
    curl -s -G "$SERVER/prelievo" \
        --data-urlencode "customer_id=bot_pattern" \
        --data-urlencode "importo=100" \
        -H "X-Forwarded-For: 192.168.60.100" > /dev/null 2>&1 &
    sleep 0.5
    
    # Attesa fra cicli
    sleep 1
done

echo ""
echo "[✓] Pattern ripetitivo generato"
echo "[*] Il pattern è SEMPRE IDENTICO (segno di automazione)"
echo "[*] Controlla il log: tail -f logs/pattern_api.log"
wait
