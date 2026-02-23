#!/bin/bash

# TEST GENERATOR 07: Anomalia pattern API - automazione non autorizzata
#
# SCOPO: Generare sequenze meccaniche e ripetitive di richieste API
#        senza variabilità (tipico di bot/automazione sospetta)
#        Viene rilevato da problema_07_pattern_api.sh
#
# METODO: Fa sempre la stessa sequenza di endpoint nello stesso ordine

# Output minimale: poche righe, facile da leggere
log() {
    # Stampa una riga sintetica
    printf "%s\n" "$1"
}

# Endpoint server e sorgente dati
SERVER="http://localhost:8000"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

# Parametri del test
CICLI=5

# Genera IP casuale e account casuale
IP_BOT="192.168.60.$((RANDOM % 254 + 1))"
BOT_ACCOUNT=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)

# Output minimale di avvio
log "T07 start"

# Seleziona ACCOUNT CASUALE all'inizio (varia ogni volta)
# Già selezionato sopra: BOT_ACCOUNT

for ciclo in $(seq 1 $CICLI); do
    # Sequenza 1: /prelievo
    curl -s -G "$SERVER/prelievo" \
        --data-urlencode "customer_id=$BOT_ACCOUNT" \
        --data-urlencode "importo=100" \
        -H "X-Forwarded-For: $IP_BOT" > /dev/null 2>&1
    sleep 0.3
    
    # Sequenza 2: /deposito (API correlata)
    curl -s -G "$SERVER/deposito" \
        --data-urlencode "customer_id=$BOT_ACCOUNT" \
        --data-urlencode "importo=50" \
        -H "X-Forwarded-For: $IP_BOT" > /dev/null 2>&1
    sleep 0.3
    
    # Sequenza 3: /prelievo (identica a primo - pattern rigido!)
    curl -s -G "$SERVER/prelievo" \
        --data-urlencode "customer_id=$BOT_ACCOUNT" \
        --data-urlencode "importo=100" \
        -H "X-Forwarded-For: $IP_BOT" > /dev/null 2>&1
    sleep 0.3
    
    # Attesa fra cicli più breve per superare soglia velocità
    sleep 0.5
done

# Output minimale di fine
log "T07 done"

