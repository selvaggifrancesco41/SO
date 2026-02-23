#!/bin/bash

# TEST GENERATOR 02: Anomalia accessi simultanei
#
# SCOPO: Generare 3+ login simultanei dello stesso account
#        da indirizzi IP diversi nello stesso momento
#        Questo pattern viene rilevato da problema_02_accessi_simultanei.sh
#
# PREREQUISITO: server Flask in esecuzione su localhost:8000

# Output minimale: poche righe e stop
log() {
    # Stampa una riga sintetica
    printf "%s\n" "$1"
}

# Endpoint server e file clienti
SERVER="http://localhost:8000"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

# Parametri del test
NUM_SESSIONI=4

# Seleziona un account CASUALE dal CSV usando Python (gestisce CSV quoted)
ACCOUNT_TARGET=$(python3 -c "
import csv, random, time
random.seed(int(time.time() * 1000000))
with open('$CSV_CLIENTI', 'r') as f:
    reader = csv.DictReader(f)
    rows = list(reader)
    random.shuffle(rows)
    print(rows[0]['customer_id'])
")

# Output minimale di avvio
log "T02 start"

# Genera NUM_SESSIONI login simultanei
# Tutti nello stesso momento da "IP diversi"
for i in $(seq 1 $NUM_SESSIONI); do
    # IP casuale ogni volta (subnet 192.168.10.X con X tra 10-250)
    IP_MITTENTE="192.168.10.$((10 + RANDOM % 241))"

    # GET /login - parametri nella query string
    # --max-time 15: mantiene la connessione aperta per 15 secondi
    curl -s --max-time 15 \
        -G "$SERVER/login" \
        --data-urlencode "customer_id=$ACCOUNT_TARGET" \
        --data-urlencode "session_duration=15" \
        -H "X-Forwarded-For: $IP_MITTENTE" 2>/dev/null &
done

# Attende la fine delle richieste in background
wait

# Output minimale di fine
log "T02 done"
