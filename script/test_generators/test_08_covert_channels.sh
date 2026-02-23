#!/bin/bash

# TEST GENERATOR 08: Anomalia canali covert - operazioni fake
#
# SCOPO: Generare operazioni bancarie con importo 0 o NULL
#        che potrebbero essere usate come canali nascosti per comunicazioni
#        Viene rilevato da problema_08_covert_channels.sh
#
# METODO: Fa richieste HTTP con importo=0 (operazioni fake)

# Output minimale: poche righe, facile da leggere
log() {
    # Stampa una riga sintetica
    printf "%s\n" "$1"
}

# Endpoint server e sorgente dati
SERVER="http://localhost:8000"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

# Parametri del test
NUM_FAKE_OPS=7

# Genera IP casuale e account casuale
IP_COVERT="192.168.70.$((RANDOM % 254 + 1))"
# tail -n +2: salta header; shuf -n 1: una riga casuale; cut -d',' -f1: primo campo
COVERT_ACCOUNT=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)

# Output minimale di avvio
log "T08 start"

for i in $(seq 1 $NUM_FAKE_OPS); do
    # Repeated zero-amount transfers to trigger covert channel rule.
    # BONIFICO con importo=0 (covert channel)
    # curl -s: silenzioso; -G: query string; --data-urlencode: URL-encode; -H: header
    curl -s -G "$SERVER/bonifico" \
        --data-urlencode "customer_id=$COVERT_ACCOUNT" \
        --data-urlencode "importo=0" \
        --data-urlencode "iban=IT12A1234567890123456789" \
        -H "X-Forwarded-For: $IP_COVERT" > /dev/null 2>&1
    
    sleep 0.3
done

# Output minimale di fine
log "T08 done"
