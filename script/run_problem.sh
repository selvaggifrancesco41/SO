#!/bin/bash

# ORCHESTRATORE PRINCIPALE
# Avvia il monitoraggio e il test generatore per un problema specifico
#
# Uso: ./run_problem.sh <numero_problema>
# Es.: ./run_problem.sh 5   # Avvia problema_05 + test_05

if [ $# -ne 1 ]; then
    echo "================================================================================"
    echo "ORCHESTRATORE TEST - SISTEMA SICUREZZA BANCARIA"
    echo "================================================================================"
    echo ""
    echo "Uso: ./run_problem.sh <numero_problema>"
    echo ""
    echo "Problemi disponibili:"
    echo "  1 - AML bonifici anomali"
    echo "  2 - Accessi simultanei"
    echo "  3 - Accessi notturni"
    echo "  4 - ATM su porte non autorizzate"
    echo "  5 - Brute-force login"
    echo "  6 - Correlazione rete - degradazione"
    echo "  7 - Pattern API anomali"
    echo "  8 - Canali covert"
    echo "  9 - Incoerenza rete"
    echo " 10 - Attacchi low & slow"
    echo ""
    echo "Esempi:"
    echo "  ./run_problem.sh 5    # Problema 05 brute-force"
    echo "  ./run_problem.sh 1    # Problema 01 AML"
    echo ""
    exit 1
fi

NUMERO=$1

# Determina il percorso dello script corrente (robusto per qualsiasi cartella)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBLEMA_SCRIPT="$SCRIPT_DIR/problema_$(printf '%02d' $NUMERO)_*.sh"
TEST_SCRIPT="$SCRIPT_DIR/test_generators/test_$(printf '%02d' $NUMERO)_*.sh"

# Verifica che gli script esistono
if ! ls $PROBLEMA_SCRIPT > /dev/null 2>&1; then
    echo "[!] ERRORE: Script di monitoraggio non trovato: $PROBLEMA_SCRIPT"
    exit 1
fi

if ! ls $TEST_SCRIPT > /dev/null 2>&1; then
    echo "[!] ERRORE: Script test non trovato: $TEST_SCRIPT"
    exit 1
fi

# Nomi completi
PROBLEMA_FULL=$(ls $PROBLEMA_SCRIPT)
TEST_FULL=$(ls $TEST_SCRIPT)

echo "================================================================================"
echo "AVVIO ORCHESTRATO - PROBLEMA $(printf '%02d' $NUMERO)"
echo "================================================================================"
echo "[*] Monitoraggio:     $PROBLEMA_FULL"
echo "[*] Test generatore:  $TEST_FULL"
echo ""
echo "[*] ISTRUZIONI:"
echo "    1. Questo script avvierà prima il MONITORAGGIO"
echo "    2. Aspetta il messaggio '[✓] In ascolto' o '[✓] Cattura avviata'"
echo "    3. Premi INVIO quando pronto ad iniziare il TEST"
echo "    4. Il test genererà anomalie"
echo "    5. Il monitoraggio le rileverà in TEMPO REALE"
echo ""
# Problemi 3, 4 e 5 sono completamente automatici
if [ "$NUMERO" != "3" ] && [ "$NUMERO" != "4" ] && [ "$NUMERO" != "5" ]; then
    read -p "Premi INVIO per continuare..." continua
fi

# Avvia monitoraggio in background
echo ""
echo "[●] AVVIANDO MONITORAGGIO..."
# Per problema 03 e 05, abilita TEST_MODE per parametri ottimizzati
if [ "$NUMERO" = "3" ] || [ "$NUMERO" = "5" ]; then
    TEST_MODE=1 $PROBLEMA_FULL &
else
    $PROBLEMA_FULL &
fi
MONITOR_PID=$!

# Aspetta che il monitoraggio sia pronto
sleep 2

echo ""
echo "[✓] Monitoraggio in esecuzione (PID: $MONITOR_PID)"
echo ""

# Problemi 03, 04 e 05: avvio automatico del test dopo 3 secondi
if [ "$NUMERO" = "3" ] || [ "$NUMERO" = "4" ] || [ "$NUMERO" = "5" ]; then
    echo "[*] Test si avvierà automaticamente tra 3 secondi..."
    sleep 3
    echo ""
    echo "[●] AVVIANDO TEST GENERATORE..."
    $TEST_FULL
else
    read -p "Premi INVIO per avviare il TEST GENERATORE..." continua
    echo ""
    echo "[●] AVVIANDO TEST GENERATORE..."
    $TEST_FULL
fi

# Attendi completamento test
wait $!

echo ""
echo "[✓] Test completato"
echo "[*] Il monitoraggio continua in esecuzione (PID: $MONITOR_PID)"
echo "[*] Premi Ctrl+C per terminare il monitoraggio"

# Attendi che l'utente termini il monitoraggio
wait $MONITOR_PID
echo "[✓] Orchestrazione terminata"
