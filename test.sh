#!/bin/bash

echo "=== TEST SISTEMA BANCA SIMULATA ==="

BASE_DIR=$(pwd)
SERVER_FILE="$BASE_DIR/server/server.py"
DB_FILE="$BASE_DIR/data/bank_logs.db"
LOG_FILE="$BASE_DIR/logs/server.log"

ERRORS=0

# 1️⃣ Controllo file fondamentali
echo "[1] Controllo file fondamentali..."

for file in "$SERVER_FILE" "$DB_FILE" "$LOG_FILE"; do
    if [ ! -f "$file" ]; then
        echo "❌ File mancante: $file"
        ERRORS=$((ERRORS+1))
    else
        echo "✅ Trovato: $file"
    fi
done

# 2️⃣ Controllo che SQLite sia accessibile
echo
echo "[2] Controllo database SQLite..."

if sqlite3 "$DB_FILE" ".tables" | grep -q logs; then
    echo "✅ Tabella logs presente"
else
    echo "❌ Tabella logs NON trovata"
    ERRORS=$((ERRORS+1))
fi

# 3️⃣ Controllo che il server risponda
echo
echo "[3] Controllo risposta server Flask..."

RESPONSE=$(curl -s "http://localhost:8000/login?customer_id=999&session_duration=10")

if echo "$RESPONSE" | grep -q '"status":"ok"'; then
    echo "✅ Server risponde correttamente"
else
    echo "❌ Server NON risponde"
    ERRORS=$((ERRORS+1))
fi

# 4️⃣ Controllo che il log venga scritto
echo
echo "[4] Controllo scrittura log..."

sleep 1

if tail -n 5 "$LOG_FILE" | grep -q LOGIN; then
    echo "✅ Evento scritto nel log"
else
    echo "❌ Nessun evento nel log"
    ERRORS=$((ERRORS+1))
fi

# 5️⃣ Controllo inserimento DB
echo
echo "[5] Controllo inserimento nel database..."

COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM logs;")

if [ "$COUNT" -gt 0 ]; then
    echo "✅ Database popolato ($COUNT record)"
else
    echo "❌ Database vuoto"
    ERRORS=$((ERRORS+1))
fi

# RISULTATO FINALE
echo
if [ "$ERRORS" -eq 0 ]; then
    echo "🎉 TUTTI I TEST SUPERATI"
    exit 0
else
    echo "⚠️ Test falliti: $ERRORS"
    exit 1
fi

