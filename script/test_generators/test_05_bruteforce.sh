#!/bin/bash

# TEST GENERATOR 05: Anomalia brute-force su /login
#
# SCOPO: Generare 15+ tentativi falliti di login verso /login
#        da uno stesso IP in breve tempo (< 60 secondi)
#        Viene rilevato da problema_05_bruteforce.sh
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
NUM_TENTATIVI=15
SLEEP_TRA_TENTATIVI=0.5  # secondi tra un tentativo e l'altro

# Genera IP attaccante casuale nel range 192.168.40.x
IP_ATTACCANTE="192.168.40.$((RANDOM % 254 + 1))"

# Seleziona UN account vittima (stesso per tutti i tentativi - realistico per bruteforce)
# tail -n +2: salta header; shuf -n 1: una riga casuale; cut -d',' -f1: primo campo
ACCOUNT=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)

# Output minimale di avvio
log "T05 start"

for i in $(seq 1 $NUM_TENTATIVI); do
    # Rapid repeated logins from the same IP.
    
    # GET /login - parametri nella query string (sincrono per garantire ordine)
    # curl -s: silenzioso; -G: query string; --data-urlencode: URL-encode; -H: header
    RESPONSE=$(curl -s -G "$SERVER/login" \
        --data-urlencode "customer_id=$ACCOUNT" \
        --data-urlencode "session_duration=5" \
        -H "X-Forwarded-For: $IP_ATTACCANTE" 2>/dev/null)

    sleep $SLEEP_TRA_TENTATIVI
done

# Aspetta 2 secondi per essere sicuri che tutti i tentativi siano nel DB
sleep 2

# Output minimale di fine
log "T05 done"
