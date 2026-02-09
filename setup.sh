#!/bin/bash
# setup.sh - prepara l'ambiente e avvia il server

set -e

BASE_DIR=$(pwd)
LOGS_DIR="$BASE_DIR/logs"
DATA_DIR="$BASE_DIR/data"
DB_FILE="$DATA_DIR/bank_logs.db"
LOG_FILE="$LOGS_DIR/server.log"

echo "[+] Preparazione ambiente..."

mkdir -p "$LOGS_DIR" "$DATA_DIR"
touch "$LOG_FILE"

# --- Virtualenv ---
if [ ! -d "venv" ]; then
    echo "❌ Virtualenv non trovato. Crealo con:"
    echo "   python3 -m venv venv"
    exit 1
fi

echo "[+] Attivazione virtualenv..."
source venv/bin/activate

# --- Dipendenze ---
if ! python3 -c "import flask" &>/dev/null; then
    echo "❌ Flask non installato nel virtualenv"
    echo "   Esegui: pip install flask"
    exit 1
fi

# --- Database ---
if [ ! -f "$DB_FILE" ]; then
    echo "[+] Creazione database..."
    sqlite3 "$DB_FILE" "
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        customer_id INTEGER,
        ip_address TEXT,
        azione TEXT,
        importo REAL,
        iban_destinatario TEXT,
        session_duration INTEGER
    );"
fi

# --- Avvio server ---
echo "[+] Avvio server Flask..."
nohup python3 server/server.py > logs/flask.out 2>&1 &

sleep 3
echo "[✓] Setup completato"
