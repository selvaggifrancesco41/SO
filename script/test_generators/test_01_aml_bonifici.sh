#!/bin/bash

# TEST GENERATOR 01: Anomalia AML - Flussi anomali di bonifici
# 
# SCOPO: Generare 5+ bonifici verso lo stesso IBAN beneficiario
#        da indirizzi IP diversi in breve tempo
#        Questo pattern viene rilevato da problema_01_aml_bonifici.sh
#
# PREREQUISITO: server Flask in esecuzione su localhost:8000

SERVER="http://localhost:8000"
IBAN_TARGET="IT6012345678901234567890"  # IBAN fisso (beneficiario)
NUM_BONIFICI=6
IMPORTO=5000

echo "================================================================================"
echo "[TEST 01] Generazione anomalia AML - bonifici multipli verso stesso IBAN"
echo "================================================================================"
echo "[*] Target IBAN: $IBAN_TARGET"
echo "[*] Numero bonifici: $NUM_BONIFICI"
echo "[*] Importo caduno: €$IMPORTO"
echo "[*] Indirizzi mittenti: 192.168.1.10 - 192.168.1.15"
echo ""

# Genera NUM_BONIFICI bonifici da "IP diversi" (simulati tramite User-Agent)
# Nel test usiamo User-Agent differenti per simulare
for i in $(seq 1 $NUM_BONIFICI); do
    IP_MITTENTE="192.168.1.$((9 + i))"
    CUSTOMER_ID="mitente_aml_$i"
    
    echo "[+] Bonifico #$i da $IP_MITTENTE (customer: $CUSTOMER_ID)"
    
    # GET /bonifico - parametri nella query string
    curl -s -G "$SERVER/bonifico" \
        --data-urlencode "customer_id=$CUSTOMER_ID" \
        --data-urlencode "importo=$IMPORTO" \
        --data-urlencode "iban=$IBAN_TARGET" \
        -H "X-Forwarded-For: $IP_MITTENTE" 2>/dev/null &
    
    sleep 0.5
done

echo ""
echo "[✓] Tutti i bonifici generati - il problema_01 dovrebbe rilevarli"
echo "[*] Controlla il log: tail -f logs/aml_alerts.log"
wait
