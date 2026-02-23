#!/bin/bash

# TEST GENERATOR 01: Anomalia AML - Flussi anomali di bonifici
# 
# SCOPO: Generare 5+ bonifici verso lo stesso IBAN beneficiario
#        da account diversi in breve tempo
#        Questo pattern viene rilevato da problema_01_aml_bonifici.sh
#
# PREREQUISITO: server Flask in esecuzione su localhost:8000

# Output minimale: poche righe, facile da leggere
log() {
    # Stampa una riga sintetica
    printf "%s\n" "$1"
}

# Endpoint del server e sorgente dati clienti
SERVER="http://localhost:8000"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

# Parametri del test
NUM_BONIFICI=6
IMPORTO=5000

# Estrai IBAN destinatario casuale dal CSV usando Python (CSV con campi quoted)
IBAN_TARGET=$(python3 -c "
import csv, random, time
random.seed(int(time.time() * 1000000))  # Seed basato su microsecondi
with open('$CSV_CLIENTI', 'r') as f:
    reader = csv.DictReader(f)
    rows = list(reader)
    random.shuffle(rows)
    print(rows[0]['iban'])
")

# Output minimale di avvio
log "T01 start"

# Estrai 6 righe casuali dal CSV (customer_id e iban mittente) usando Python
CLIENTI_DATA=$(python3 -c "
import csv, random, time
random.seed(int(time.time() * 1000000) + $$)  # Seed basato su microsecondi + PID
with open('$CSV_CLIENTI', 'r') as f:
    reader = csv.DictReader(f)
    rows = list(reader)
    random.shuffle(rows)
    for row in rows[:6]:
        print(f\"{row['customer_id']},{row['iban']}\")
")

# Popola array da output Python
ARRAY_CLIENTI=()
ARRAY_IBAN_MITTENTI=()
while IFS=',' read -r customer_id iban; do
    # Salva customer_id per il mittente
    ARRAY_CLIENTI+=("$customer_id")
    # Salva IBAN del mittente (non usato dal server, ma utile per tracciamento)
    ARRAY_IBAN_MITTENTI+=("$iban")
done <<< "$CLIENTI_DATA"

# Genera bonifici dai 6 account selezionati
for i in $(seq 0 $((NUM_BONIFICI - 1))); do
    # Seleziona il mittente corrente
    CUSTOMER_ID="${ARRAY_CLIENTI[$i]}"
    # IBAN del mittente (solo per contesto locale)
    IBAN_MITTENTE="${ARRAY_IBAN_MITTENTI[$i]}"
    # IP casuale ogni volta (subnet 192.168.1.X con X tra 10-250)
    IP_MITTENTE="192.168.1.$((10 + RANDOM % 241))"

    # Fire bonifico requests quickly to trigger AML threshold.
    # curl -s: silenzioso; -G: parametri in query string; --data-urlencode: URL-encode; -H: header
    curl -s -G "$SERVER/bonifico" \
        --data-urlencode "customer_id=$CUSTOMER_ID" \
        --data-urlencode "importo=$IMPORTO" \
        --data-urlencode "iban=$IBAN_TARGET" \
        -H "X-Forwarded-For: $IP_MITTENTE" 2>/dev/null &
    
    sleep 0.5
done

# Wait for background requests to finish.
wait

# Output minimale di fine
log "T01 done"
