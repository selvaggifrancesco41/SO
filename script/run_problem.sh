#!/bin/bash

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

# Verifica argomento: serve un solo numero problema
if [ $# -ne 1 ]; then
    # Messaggio essenziale di uso
    log "Uso: ./run_problem.sh <1-10>"
    exit 1
fi

# Numero del problema richiesto
NUMERO=$1

# Determina il percorso dello script corrente (robusto per qualsiasi cartella)
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

# Resetta log realtime e state file per problema 01 e 02 (usano realtime_access.log)
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
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema03_last_check.txt
fi
if [ "$NUMERO" = "4" ]; then
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema04_last_check.txt
fi
if [ "$NUMERO" = "5" ]; then
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema05_last_check.txt
fi
if [ "$NUMERO" = "6" ]; then
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema06_last_check.txt
fi
if [ "$NUMERO" = "7" ]; then
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema07_last_check.txt
fi
if [ "$NUMERO" = "8" ]; then
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema08_last_check.txt
fi
if [ "$NUMERO" = "9" ]; then
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema09_last_check.txt
fi
if [ "$NUMERO" = "10" ]; then
    # Imposta timestamp di ultimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > /tmp/problema10_last_check.txt
fi

# Per problema 03 e 05, abilita TEST_MODE per parametri ottimizzati
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
