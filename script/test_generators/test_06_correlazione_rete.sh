#!/bin/bash

# TEST GENERATOR 06: Anomalia correlazione rete - IP da subnet non autorizzate
#
# SCOPO: Generare login da IP pubblici (fuori subnet private)
#        per simulare accessi da internet non autorizzati  
#        Viene rilevato da problema_06_correlazione_rete.sh
#
# METODO: Curl con X-Forwarded-For usando IP pubblici noti

# Output minimale: poche righe, facile da leggere
log() {
    # Stampa una riga sintetica
    printf "%s\n" "$1"
}

# Endpoint server e sorgente dati
SERVER="http://localhost:8000"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

# IP pubblici noti (DNS pubblici + altri server famosi)
IP_PUBBLICI_POOL=("8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1" "208.67.222.222" "208.67.220.220" "9.9.9.9" "149.112.112.112")

# Seleziona 1 IP pubblico casuale
IP_PUBBLICO="${IP_PUBBLICI_POOL[$((RANDOM % ${#IP_PUBBLICI_POOL[@]}))]}"

# Seleziona 1 account casuale
# tail -n +2: salta header; shuf -n 1: una riga casuale; cut -d',' -f1: primo campo
CUSTOMER_ID=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)

# Output minimale di avvio
log "T06 start"

 # Single login from a public IP to trigger the detector.
# curl -s: silenzioso; -G: query string; --data-urlencode: URL-encode; -H: header
RESPONSE=$(curl -s -G "$SERVER/login" \
    --data-urlencode "customer_id=$CUSTOMER_ID" \
    --data-urlencode "session_duration=10" \
    -H "X-Forwarded-For: $IP_PUBBLICO" 2>/dev/null)

# Risposta server ignorata per output minimale

# Attende la registrazione della richiesta
sleep 2

# Output minimale di fine
log "T06 done"
