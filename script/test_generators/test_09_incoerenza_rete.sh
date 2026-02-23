#!/bin/bash

# TEST GENERATOR 09: Anomalia incoerenza rete - operazione da contesto errato
#
# SCOPO: Simulare operazioni da indirizzi IP sospetti
#        es. bonifico da range ATM invece da range client
#        Viene rilevato da problema_09_incoerenza_rete.sh
#
# METODO: Operazioni da IP che non dovrebbero farle

# Output minimale: poche righe, facile da leggere
log() {
    # Stampa una riga sintetica
    printf "%s\n" "$1"
}

# Endpoint server e sorgente dati
SERVER="http://localhost:8000"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

# Seleziona 3 ACCOUNT CASUALI dal CSV (variano ogni esecuzione)
# tail -n +2: salta header; shuf -n 1: una riga casuale; cut -d',' -f1: primo campo
ACCOUNT1=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)
ACCOUNT2=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)
ACCOUNT3=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)

# IP casuali per ogni subnet
IP_ATM="192.168.30.$((RANDOM % 254 + 1))"        # Range ATM (anomalo per BONIFICO)
IP_API="192.168.40.$((RANDOM % 254 + 1))"        # Range API (anomalo per PRELIEVO)
IP_PUBBLICO="203.0.113.$((RANDOM % 254 + 1))"    # IP pubblico (anomalo per LOGIN)

# Output minimale di avvio
log "T09 start"

# Scegli una sola operazione tra le tre (random).
OP_RANDOM=$((RANDOM % 3))
case $OP_RANDOM in
    0)
        # Operazione 1: Bonifico da IP ATM (anomalo)
        # curl -s: silenzioso; -G: query string; --data-urlencode: URL-encode; -H: header
        curl -s -G "$SERVER/bonifico" \
            --data-urlencode "customer_id=$ACCOUNT1" \
            --data-urlencode "importo=50000" \
            --data-urlencode "iban=IT60X0542811101000000123456" \
            -H "X-Forwarded-For: $IP_ATM" > /dev/null 2>&1
        ;;
    1)
        # Operazione 2: Prelievo da IP API (anomalo)
        curl -s -G "$SERVER/prelievo" \
            --data-urlencode "customer_id=$ACCOUNT2" \
            --data-urlencode "importo=500" \
            -H "X-Forwarded-For: $IP_API" > /dev/null 2>&1
        ;;
    2)
        # Operazione 3: Login da IP pubblico (anomalo)
        curl -s -G "$SERVER/login" \
            --data-urlencode "customer_id=$ACCOUNT3" \
            --data-urlencode "session_duration=60" \
            -H "X-Forwarded-For: $IP_PUBBLICO" > /dev/null 2>&1
        ;;
esac

# Output minimale di fine
log "T09 done"
