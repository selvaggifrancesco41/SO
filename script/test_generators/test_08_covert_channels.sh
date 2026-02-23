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
COVERT_ACCOUNT=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)

# Output minimale di avvio
log "T08 start"

for i in $(seq 1 $NUM_FAKE_OPS); do
    # Alterna tra PRELIEVO e DEPOSITO con importo=0
    if [ $((i % 2)) -eq 0 ]; then
        AZIONE="prelievo"
    else
        AZIONE="deposito"
    fi
    
    # Richiesta con importo=0 (operazione fake)
    curl -s -G "$SERVER/$AZIONE" \
        --data-urlencode "customer_id=$COVERT_ACCOUNT" \
        --data-urlencode "importo=0" \
        -H "X-Forwarded-For: $IP_COVERT" > /dev/null 2>&1
    
    sleep 0.3
done

# Output minimale di fine
log "T08 done"
