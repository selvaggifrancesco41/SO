#!/bin/bash

# Run a monitor + its test generator, ensuring the server is available.

# ORCHESTRATORE PRINCIPALE
# Avvia il monitoraggio e il test generatore per un problema specifico
#
# Uso: ./run_problem.sh <numero_problema>
# Es.: ./run_problem.sh 5   # Avvia problema_05 + test_05

# Output minimale: poche righe, chiaro e veloce
log() {
    # Stampa una sola riga sintetica
    printf "%s\n" "$1"
}

ensure_server_running() {
    # Start server if port 8000 is not listening.
    local pid_file="/workspaces/SO/logs/server.pid"
    # ss -ltn: -l in ascolto, -t TCP, -n numerico (niente DNS)
    # grep -q: non stampa, usa solo l'exit status
    if ss -ltn 2>/dev/null | grep -q ":8000"; then
        return 0
    fi

    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null)
        # ps -p: filtra per PID
        if [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1; then
            return 0
        fi
    fi

    log "server start"
    python3 /workspaces/SO/server/server.py > /workspaces/SO/logs/server.out 2>&1 &
    echo $! > "$pid_file"
    sleep 1
}

# Verifica argomento: serve un solo numero problema
if [ $# -ne 1 ]; then
    # Messaggio essenziale di uso
    log "Uso: ./run_problem.sh <1-10>"
    exit 1
fi

# Numero del problema richiesto
NUMERO=$1

# Resolve script paths regardless of current working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBLEMA_SCRIPT="$SCRIPT_DIR/problema_$(printf '%02d' $NUMERO)_*.sh"
TEST_SCRIPT="$SCRIPT_DIR/test_generators/test_$(printf '%02d' $NUMERO)_*.sh"

# Verifica che gli script esistono
if ! ls $PROBLEMA_SCRIPT > /dev/null 2>&1; then
    # Errore essenziale per script mancante
    log "Errore: monitor non trovato"
    exit 1
fi

if ! ls $TEST_SCRIPT > /dev/null 2>&1; then
    # Errore essenziale per script mancante
    log "Errore: test non trovato"
    exit 1
fi

# Nomi completi
PROBLEMA_FULL=$(ls $PROBLEMA_SCRIPT)
TEST_FULL=$(ls $TEST_SCRIPT)

# Output essenziale di avvio
log "P$(printf '%02d' $NUMERO) start"

# Avvia monitoraggio in background
log "monitor start"

# Assicura che il server sia in esecuzione per i test
ensure_server_running

# Reset per-problem state to avoid stale detections.
if [ "$NUMERO" = "1" ]; then
    # Pulisce log realtime per evitare dati vecchi
    > /workspaces/SO/logs/realtime_access.log
    # Rimuove stato AML per ripartenza pulita
    rm -f /workspaces/SO/logs/aml_state.tmp
fi
if [ "$NUMERO" = "2" ]; then
    # Pulisce log realtime per problema 02
    > /workspaces/SO/logs/realtime_access.log
fi

# Resetta timestamp per problema 03, 04, 05, 06, 07, 08 e 09 (evita rilevamento vecchi record)
if [ "$NUMERO" = "3" ]; then
    # Pulisce log realtime per evitare dati vecchi
    > /workspaces/SO/logs/realtime_access.log
    # Imposta timestamp di ultimo controllo
    # date -u: usa UTC
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema03_last_check.txt
fi
if [ "$NUMERO" = "4" ]; then
    # Pulisce log realtime per problema 04
    > /workspaces/SO/logs/realtime_access.log
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema04_last_check.txt
fi
if [ "$NUMERO" = "5" ]; then
    # Pulisce log realtime per problema 05
    > /workspaces/SO/logs/realtime_access.log
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema05_last_check.txt
fi
if [ "$NUMERO" = "6" ]; then
    # Pulisce log realtime per problema 06
    > /workspaces/SO/logs/realtime_access.log
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema06_last_check.txt
fi
if [ "$NUMERO" = "7" ]; then
    # Pulisce log realtime per problema 07
    > /workspaces/SO/logs/realtime_access.log
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema07_last_check.txt
fi
if [ "$NUMERO" = "8" ]; then
    # Pulisce log realtime per problema 08
    > /workspaces/SO/logs/realtime_access.log
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema08_last_check.txt
fi
if [ "$NUMERO" = "9" ]; then
    # Pulisce log realtime per problema 09
    > /workspaces/SO/logs/realtime_access.log
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema09_last_check.txt
fi
if [ "$NUMERO" = "10" ]; then
    # Pulisce log realtime per problema 10
    > /workspaces/SO/logs/realtime_access.log
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema10_last_check.txt
fi

# TEST_MODE accelerates checks for specific problems.
if [ "$NUMERO" = "3" ] || [ "$NUMERO" = "5" ]; then
    # Avvia monitor con TEST_MODE per timing piu rapido
    env TEST_MODE=1 bash "$PROBLEMA_FULL" &
else
    # Avvia monitor standard
    bash "$PROBLEMA_FULL" &
fi
MONITOR_PID=$!

# Aspetta che il monitoraggio sia pronto
sleep 2

# Avvio test generatore dopo breve pausa
sleep 3
log "test start"
$TEST_FULL

# Attendi completamento test
wait $!

# Test terminato
log "test done"

# Termina automaticamente il monitoraggio
if ps -p $MONITOR_PID > /dev/null 2>&1; then
    # Chiude il processo monitor
    kill $MONITOR_PID 2>/dev/null
    # Attende la chiusura del monitor
    wait $MONITOR_PID 2>/dev/null
fi

# Fine orchestrazione
log "done"
