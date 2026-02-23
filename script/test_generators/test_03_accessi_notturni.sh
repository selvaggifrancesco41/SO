#!/bin/bash

# TEST GENERATOR 03: Anomalia accessi notturni
#
# SCOPO: Generare login durante orari notturni (22:00-06:00)
#        NOTA: Il monitoring script deve essere avviato con TEST_MODE=1
#              per bypassare il controllo orario reale
#        Viene rilevato da problema_03_accessi_notturni.sh
#
# PREREQUISITO: server Flask in esecuzione su localhost:8000

# Output minimale: poche righe, facile da leggere
log() {
    # Stampa una riga sintetica
    printf "%s\n" "$1"
}

# Endpoint server e sorgente dati
SERVER="http://localhost:8000"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

# Parametri del test
NUM_ACCESSI=3

# Output minimale di avvio
log "T03 start"

for i in $(seq 1 $NUM_ACCESSI); do
    # Emit login events from random accounts and diverse IPs each time.
    # Seleziona un ACCOUNT casuale ad ogni iterazione
    ACCOUNT=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)
    # IP casuale ad ogni iterazione (subnet 192.168.X.Y con X,Y casuali)
    IP_MITTENTE="192.168.$((RANDOM % 160 + 1)).$((RANDOM % 256))"
    
    # GET /login - parametri nella query string
    # curl -s: silenzioso; -G: query string; --data-urlencode: URL-encode; -H: header
    curl -s -G "$SERVER/login" \
        --data-urlencode "customer_id=$ACCOUNT" \
        --data-urlencode "session_duration=$((RANDOM % 60))" \
        -H "X-Forwarded-For: $IP_MITTENTE"

    sleep 1
done

# Output minimale di fine
log "T03 done"
