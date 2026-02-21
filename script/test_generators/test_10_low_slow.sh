#!/bin/bash

# TEST GENERATOR 10: Anomalia low & slow - attacco lento e persistente
#
# SCOPO: Generare connessioni a BASSO TASSO (pochi dati per lungo tempo)
#        che non saturano risorse ma persistono nel tempo
#        Viene rilevato da problema_10_low_slow.sh
#
# METODO: Apre connessioni con trasferimento dati molto lento

SERVER="http://localhost:8000"

echo "================================================================================"
echo "[TEST 10] Generazione anomalia - attacco low & slow (lento e persistente)"
echo "================================================================================"
echo "[*] Pattern: Poche richieste, molto spaziate, su durata lunga"
echo "[*] Tipo: Attacco distribuito che degrada risorse senza saturarle"
echo ""

echo "[TEST] Generazione flusso low & slow..."

NUM_RICHIESTE=5
DURATA_TOTALE=120  # 2 minuti
INTERVALLO=$((DURATA_TOTALE / NUM_RICHIESTE))

echo "[*] Numero richieste: $NUM_RICHIESTE"
echo "[*] Durata totale: ${DURATA_TOTALE}s"
echo "[*] Intervallo tra richieste: ${INTERVALLO}s"
echo ""

# Genera richieste molto spaziate
for i in $(seq 1 $NUM_RICHIESTE); do
    echo "[+] Richiesta low-slow #$i da 192.168.70.100"
    
    # Richiesta lenta con timeout lungo
    # --max-time: tempo massimo per completare
    curl -s --max-time 30 \
        -G "$SERVER/prelievo" \
        --data-urlencode "customer_id=slow_client_$i" \
        --data-urlencode "importo=10" \
        -H "X-Forwarded-For: 192.168.70.100" > /dev/null 2>&1 &
    
    # Aspetta prima della prossima (crea pattern LOW & SLOW)
    sleep $INTERVALLO
done

echo ""
echo "[✓] Flusso low & slow generato"
echo "[*] Pattern: $NUM_RICHIESTE richieste in ${DURATA_TOTALE}s = molto basso tasso"
echo "[*] Ma PERSISTENTE nel tempo (tipico attacco distribuito)"
echo "[*] Log: tail -f logs/low_slow_alerts.log"
wait
