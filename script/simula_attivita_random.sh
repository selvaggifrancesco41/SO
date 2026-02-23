#!/bin/bash

# Generate randomized user activity against the local Flask server.

# =========================
# CONFIGURAZIONE
# =========================

SERVER="http://localhost:8000"

# Output minimale: riduce il rumore sul terminale
# FD 3 stays on terminal for essential logs.
exec 3>&1
# Silenzia stdout standard per tutte le stampe verbose
exec 1>/dev/null

# Stampa solo le righe essenziali su terminale
log() {
    # Usa FD 3 per non essere silenziato
    printf "%s\n" "$1" >&3
}

INTERVALLO_MIN=1
INTERVALLO_MAX=4

NUM_RICHIESTE=50


# =========================
# FUNZIONI RANDOM
# =========================

genera_ip() {
    # Random IPv4 for simulated clients - avoid loopback (127.x.x.x)
    # Generate realistic private IP ranges: 192.168.x.x, 10.x.x.x, 172.16-31.x.x
    local primo_ottetto
    case $((RANDOM % 3)) in
        0) primo_ottetto="192" ;;
        1) primo_ottetto="10" ;;
        2) primo_ottetto="172" ;;
    esac
    
    local secondo_ottetto
    if [ "$primo_ottetto" = "172" ]; then
        # Range 172.16-31.x.x
        secondo_ottetto=$((16 + RANDOM % 16))
    elif [ "$primo_ottetto" = "192" ]; then
        # Range 192.168.x.x
        secondo_ottetto="168"
    else
        # Range 10.x.x.x
        secondo_ottetto=$((RANDOM % 256))
    fi
    
    echo "$primo_ottetto.$secondo_ottetto.$((RANDOM%256)).$((RANDOM%256))"
}

genera_porta() {
    echo $((1024 + RANDOM % 55000))
}

genera_importo() {
    echo $((10 + RANDOM % 5000))
}

get_random_cliente() {
    # Estrae un cliente casuale dal CSV (salta l'header)
    # tail -n +2: salta header; shuf -n 1: una riga casuale
    tail -n +2 /workspaces/SO/clienti_banca.csv | shuf -n 1
}

verifica_server() {
    # Abort if the server is not reachable.
    # Verifica se il server è raggiungibile
    # curl -s: silenzioso; -m 2: timeout totale 2s
    if ! curl -s -m 2 "$SERVER/login?customer_id=test&porta=test" > /dev/null 2>&1; then
        echo "ERRORE: Il server su $SERVER non è raggiungibile"
        exit 1
    fi
}

salva_nel_db() {
    # Mirror events into the local SQLite log for reference.
    local customer_id=$1
    local azione=$2
    local importo=$3
    local iban=$4
    local ip=$5

    python3 << EOF
import sqlite3
from datetime import datetime

DB_PATH = "/workspaces/SO/data/bank_logs.db"
timestamp = datetime.now().isoformat()

raw_importo = "$importo"
raw_iban = "$iban"

if not raw_importo or raw_importo == "NULL":
    importo_val = None
else:
    importo_val = float(raw_importo)

if not raw_iban or raw_iban == "NULL":
    iban_val = None
else:
    iban_val = raw_iban

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("""
    INSERT INTO logs
    (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration)
    VALUES (?, ?, ?, ?, ?, ?, ?)
""", ("$timestamp", "$customer_id", "$ip", "$azione", importo_val, iban_val, None))
conn.commit()
conn.close()
EOF
}

sleep_random() {
    sleep $((INTERVALLO_MIN + RANDOM % (INTERVALLO_MAX - INTERVALLO_MIN + 1)))
}


# =========================
# AZIONI POSSIBILI
# =========================

azione_login() {
    # Login action triggers server + DB write.
    salva_nel_db "$USER_ID" "LOGIN" "NULL" "NULL" "$IP"
    # curl -s: silenzioso; -X GET: forza metodo; -H: header
    curl -s -X GET "$SERVER/login?customer_id=$USER_ID&porta=$PORTA" \
    -H "X-Forwarded-For: $IP"
}

azione_prelievo() {
    # Prelievo action with a random amount.
    IMPORTO=$(genera_importo)
    echo "Importo prelievo: €$IMPORTO"
    salva_nel_db "$USER_ID" "PRELIEVO" "$IMPORTO" "NULL" "$IP"

    # curl -s: silenzioso; -X GET: forza metodo; -H: header
    curl -s -X GET "$SERVER/prelievo?customer_id=$USER_ID&importo=$IMPORTO&porta=$PORTA" \
    -H "X-Forwarded-For: $IP"
}

azione_bonifico() {
    # Bonifico action with a random target IBAN.
    IMPORTO=$(genera_importo)
    # Estrae un cliente casuale per l'IBAN destinatario
    CLIENTE_DEST=$(get_random_cliente)
    IBAN=$(echo "$CLIENTE_DEST" | python3 -c "import sys, csv; row = next(csv.reader(sys.stdin)); print(row[14])")
    echo "Importo bonifico: €$IMPORTO | IBAN destinatario: $IBAN"
    salva_nel_db "$USER_ID" "BONIFICO" "$IMPORTO" "$IBAN" "$IP"

    # curl -s: silenzioso; -X GET: forza metodo; -H: header
    curl -s -X GET "$SERVER/bonifico?customer_id=$USER_ID&importo=$IMPORTO&iban_destinatario=$IBAN&porta=$PORTA" \
    -H "X-Forwarded-For: $IP"
}


# =========================
# CICLO PRINCIPALE
# =========================

# Messaggio minimo di avvio
log "sim start"

verifica_server

for ((i=1; i<=NUM_RICHIESTE; i++))
do
    # Iterate a fixed number of random requests.
    # Estrae un cliente casuale dal CSV
    CLIENTE=$(get_random_cliente)
    # awk -F',': separatore CSV
    USER_ID=$(echo "$CLIENTE" | awk -F',' '{print $1}')
    
    IP=$(genera_ip)
    PORTA=$(genera_porta)

    AZIONE=$((RANDOM % 3))

    echo ""
    echo "Richiesta $i"
    echo "IP: $IP | USER: $USER_ID | PORTA: $PORTA"

    case $AZIONE in
        0)
            echo "Azione: LOGIN"
            azione_login
            ;;
        1)
            echo "Azione: PRELIEVO"
            azione_prelievo
            ;;
        2)
            echo "Azione: BONIFICO"
            azione_bonifico
            ;;
    esac

    sleep_random
done

# Messaggio minimo di fine
log "sim done"
