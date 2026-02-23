#!/bin/bash

################################################################################
# SETUP.SH - INIZIALIZZAZIONE COMPLETA SISTEMA BANCARIO
################################################################################
#
# DESCRIZIONE:
# Script di setup automatico che:
# 1. Prepara l'ambiente (virtualenv, dipendenze)
# 2. Inizializza il database eventi_bancari.db
# 3. Popola il database con dati realistici (se necessario)
# 4. Avvia il server Flask
# 5. Mostra la dashboard di sicurezza
# 6. Offre opzioni per eseguire controlli o generare traffico
#
################################################################################

set -e
# Fail fast on errors to avoid partial setup.

# Stampa solo le righe essenziali su terminale
log() {
    printf "%s\n" "$1"
}

BASE_DIR=$(pwd)
# Resolve key paths once for reuse.
LOGS_DIR="$BASE_DIR/logs"
DATA_DIR="$BASE_DIR/data"
SCRIPT_DIR="$BASE_DIR/script"
DB_FILE="$DATA_DIR/eventi_bancari.db"
LOG_FILE="$LOGS_DIR/server.log"
SERVER_PID_FILE="$LOGS_DIR/server.pid"

# Messaggio minimo di avvio
log "setup start"

# ============================================================================
# FASE 1: PREPARAZIONE AMBIENTE
# ============================================================================

# Fase 1: preparazione ambiente
log "setup env"

# Crea directory necessarie
mkdir -p "$LOGS_DIR" "$DATA_DIR" "$SCRIPT_DIR/logs"
touch "$LOG_FILE"

# Verifica virtualenv - crealo con pip/setuptools/wheel
if [ ! -d "venv" ]; then
    log "[*] Virtualenv non trovato. Creazione in corso..."
    # python3 -m: esegue il modulo; --upgrade-deps: aggiorna pip/setuptools/wheel
    # grep -v: esclude righe vuote
    python3 -m venv --upgrade-deps venv 2>&1 | grep -v "^$" || true
    log "[✓] Virtualenv creato con pip incluso"
fi

log "[*] Attivazione virtualenv..."
source venv/bin/activate

# Installa Flask via pip dal venv
if ! python3 -c "import flask" &>/dev/null; then
    log "[*] Installazione Flask..."
    # pip -q: output silenzioso
    pip install -q flask
    log "[✓] Flask installato"
else
    log "[✓] Flask già installato"
fi

# Installa tool di cattura rete (tcpdump, tshark) per monitoraggio
log "[*] Installazione tool di cattura rete..."
# command -v: verifica se il comando esiste nel PATH
if ! command -v tcpdump >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then
        # apk add --no-cache: installa senza cache del repository
        # grep -v: esclude righe vuote
        apk add --no-cache tcpdump tshark 2>&1 | grep -v "^$" || true
        log "[✓] tcpdump e tshark installati"
    fi
fi

echo ""

# ============================================================================
# FASE 2: INIZIALIZZAZIONE DATABASE
# ============================================================================

# Fase 2: inizializzazione database
log "setup db"

# Inizializza il database eventi_bancari.db
python3 << 'EOF'
import sqlite3
import os

DB_PATH = "data/eventi_bancari.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Crea tabella eventi se non esiste
cur.execute("""
    CREATE TABLE IF NOT EXISTS eventi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        customer_id INTEGER,
        ip_address TEXT,
        azione TEXT,
        importo REAL,
        iban_destinatario TEXT,
        session_duration INTEGER,
        porta INTEGER,
        source_type TEXT
    )
""")

conn.commit()
conn.close()
print("[✓] Database eventi_bancari.db inizializzato")
EOF

echo ""

# ============================================================================
# FASE 3: POPOLAMENTO DATABASE (SE NECESSARIO)
# ============================================================================

# Fase 3: verifica dati
log "setup data"

NUM_EVENTI=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM eventi;" 2>/dev/null || echo 0)

if [ "$NUM_EVENTI" -lt 10 ]; then
    echo "[*] Database vuoto o con pochi dati ($NUM_EVENTI eventi)"
    echo "[*] Popolamento con dati realistici..."
    
    if [ -f "$SCRIPT_DIR/popola_database_test.sh" ]; then
        bash "$SCRIPT_DIR/popola_database_test.sh" > /dev/null 2>&1
        echo "[✓] Database popolato con dati di test"
    else
        echo "[!] Script di popolamento non trovato, saltato"
    fi
else
    echo "[✓] Database già popolato con $NUM_EVENTI eventi"
fi

echo ""

# ============================================================================
# FASE 4: AVVIO SERVER FLASK
# ============================================================================

# Fase 4: avvio server
log "setup server"

# Verifica se il server è già in esecuzione
if [ -f "$SERVER_PID_FILE" ]; then
    OLD_PID=$(cat "$SERVER_PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "[!] Server già in esecuzione (PID: $OLD_PID)"
        echo "[*] Arresto server precedente..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 2
    fi
fi

# Avvia il server in background
# nohup: ignora SIGHUP; output su file
nohup python3 server/server.py > logs/flask.out 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > "$SERVER_PID_FILE"

# Attendi che il server sia pronto
echo -n "[*] Attesa avvio server"
for i in {1..10}; do
    # curl -s: silenzioso
    if curl -s http://localhost:8000/login?customer_id=test&porta=test > /dev/null 2>&1; then
        echo ""
        echo "[✓] Server Flask avviato correttamente (PID: $SERVER_PID)"
        break
    fi
    echo -n "."
    sleep 1
done

if ! curl -s http://localhost:8000/login?customer_id=test&porta=test > /dev/null 2>&1; then
    echo ""
    echo "[!] Server potrebbe non essere disponibile, ma proseguo..."
fi

echo ""

# ============================================================================
# FASE 5: DASHBOARD DI SICUREZZA
# ============================================================================

# Fase 5: dashboard
log "setup dashboard"

if [ -f "$SCRIPT_DIR/dashboard_sicurezza.sh" ]; then
    bash "$SCRIPT_DIR/dashboard_sicurezza.sh"
else
    echo "[!] Dashboard non trovata"
fi

echo ""

# ============================================================================
# FASE 6: OPZIONI INTERATTIVE
# ============================================================================

# Fase 6: opzioni finali (output minimo)
log "setup done"
echo "  2) Generare traffico casuale continuo (richiede Ctrl+C per fermare)"
echo "  3) Visualizzare solo la dashboard"
echo "  4) Niente, lasciare solo il server attivo"
echo ""
read -p "Scelta [1-4]: " SCELTA

case $SCELTA in
    1)
        echo ""
        echo "[*] Esecuzione controlli di sicurezza..."
        if [ -f "$SCRIPT_DIR/esegui_tutti_controlli.sh" ]; then
            cd "$SCRIPT_DIR"
            bash esegui_tutti_controlli.sh
        else
            echo "[!] Script non trovato: $SCRIPT_DIR/esegui_tutti_controlli.sh"
        fi
        ;;
    2)
        echo ""
        echo "[*] Avvio generatore di traffico casuale..."
        echo "[*] Premi Ctrl+C per fermare"
        if [ -f "$SCRIPT_DIR/simula_attivita_random.sh" ]; then
            cd "$SCRIPT_DIR"
            bash simula_attivita_random.sh
        else
            echo "[!] Script non trovato: $SCRIPT_DIR/simula_attivita_random.sh"
        fi
        ;;
    3)
        echo ""
        if [ -f "$SCRIPT_DIR/dashboard_sicurezza.sh" ]; then
            bash "$SCRIPT_DIR/dashboard_sicurezza.sh"
        fi
        ;;
    4)
        echo ""
        echo "[✓] Server in esecuzione in background"
        ;;
    *)
        echo ""
        echo "[!] Scelta non valida, server lasciato attivo"
        ;;
esac

echo ""
echo "================================================================================"
echo "COMANDI UTILI:"
echo "================================================================================"
echo ""
echo "# Fermare il server:"
echo "  kill $SERVER_PID"
echo ""
echo "# Visualizzare log server:"
echo "  tail -f $LOGS_DIR/flask.out"
echo ""
echo "# Eseguire controlli di sicurezza:"
echo "  cd script && ./esegui_tutti_controlli.sh"
echo ""
echo "# Generare traffico:"
echo "  cd script && ./simula_attivita_random.sh"
echo ""
echo "# Dashboard:"
echo "  cd script && ./dashboard_sicurezza.sh"
echo ""
echo "================================================================================"