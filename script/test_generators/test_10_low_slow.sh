#!/bin/bash

# TEST 10: Generatore traffico LOW & SLOW
#
# SIMULA: Attacco lento con poche richieste distribuite nel tempo
#         Rate basso ma persistente su periodo lungo

# Output minimale: poche righe, facile da leggere
log() {
    # Stampa una riga sintetica
    printf "%s\n" "$1"
}

# Endpoint server e sorgente dati
SERVER_URL="http://localhost:8000"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

# Parametri del test
NUM_RICHIESTE=5
DURATA_TOTALE=30   # 30 secondi totali
INTERVALLO=$((DURATA_TOTALE / NUM_RICHIESTE))   # ~6 secondi tra richieste

# IP RANDOMIZZATO subnet 192.168.80.X (low & slow attacks)
IP="192.168.80.$((RANDOM % 254 + 1))"

# ACCOUNT RANDOMIZZATO
if [ ! -f "$CSV_CLIENTI" ]; then
    echo "Errore: File clienti non trovato: $CSV_CLIENTI"
    exit 1
fi

ACCOUNT=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)

if [ -z "$ACCOUNT" ]; then
    echo "Errore: Impossibile selezionare account dal CSV"
    exit 1
fi

# Output minimale di avvio
log "T10 start"

for i in $(seq 1 $NUM_RICHIESTE); do
    # Alterna tra diverse azioni per sembrare realistico
    ENDPOINT_RANDOM=$((RANDOM % 4))
    case $ENDPOINT_RANDOM in
        0) ENDPOINT="/login" ;;
        1) ENDPOINT="/prelievo" ;;
        2) ENDPOINT="/deposito" ;;
        3) ENDPOINT="/bonifico" ;;
    esac
    
    IMPORTO=$((RANDOM % 1000 + 100))
    
    # Richiesta lenta con --max-time per simulare slow request
    curl -s -G "$SERVER_URL$ENDPOINT" \
        --data-urlencode "customer_id=$ACCOUNT" \
        --data-urlencode "importo=$IMPORTO" \
        -H "X-Forwarded-For: $IP" \
        --max-time 30 > /dev/null 2>&1 &
    
    # Aspetta tra le richieste (tranne l'ultima)
    if [ $i -lt $NUM_RICHIESTE ]; then
        sleep $INTERVALLO
    fi
done

# Aspetta completamento richieste in background
wait

# Output minimale di fine
log "T10 done"
