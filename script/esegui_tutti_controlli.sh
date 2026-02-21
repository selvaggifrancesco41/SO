#!/bin/bash

################################################################################
# SCRIPT MASTER: ESECUZIONE COMPLETA DI TUTTI I 10 PROBLEMI DI SICUREZZA
################################################################################
#
# DESCRIZIONE:
# Questo script master esegue in sequenza tutti i 10 script di analisi della
# sicurezza bancaria, generando report completi e aggiornando la blacklist.
#
# FUNZIONALITÀ:
# - Esecuzione sequenziale di tutti i controlli di sicurezza
# - Generazione di un report riepilogativo finale
# - Analisi dello stato della blacklist
# - Statistiche aggregate delle anomalie rilevate
#
################################################################################

SCRIPT_DIR="/workspaces/SO/script"
LOG_MASTER="/workspaces/SO/logs/master_execution.log"
REPORT_MASTER="/workspaces/SO/logs/master_report.txt"
BLACKLIST_PATH="/workspaces/SO/blacklist.csv"

mkdir -p /workspaces/SO/logs

echo "================================================================================"
echo "     SISTEMA DI SICUREZZA BANCARIA - ANALISI COMPLETA"
echo "================================================================================"
echo ""
echo "Data e ora inizio:        $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo "Questo script eseguirà in sequenza i seguenti controlli di sicurezza:"
echo ""
echo "  1. Rilevamento flussi anomali bonifici (AML)"
echo "  2. Individuazione accessi simultanei sospetti"
echo "  3. Analisi accessi notturni fuori profilo"
echo "  4. Rilevamento ATM con porte non autorizzate"
echo "  5. Rilevamento tentativi brute-force sulle API"
echo "  6. Correlazione anomalie rete e degrado servizio"
echo "  7. Rilevamento pattern anomali utilizzo API"
echo "  8. Rilevamento canali di comunicazione covert"
echo "  9. Rilevamento incoerenze rete-operazione"
echo " 10. Rilevamento comportamenti Low & Slow"
echo ""
echo "================================================================================"
echo ""

# Inizializza il log master
echo "================================================================================" > "$LOG_MASTER"
echo "ESECUZIONE MASTER - $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_MASTER"
echo "================================================================================" >> "$LOG_MASTER"
echo "" >> "$LOG_MASTER"

# Conta elementi in blacklist prima dell'esecuzione
BLACKLIST_PRIMA=$(grep -c "^" "$BLACKLIST_PATH" 2>/dev/null || echo 0)

echo "Elementi in blacklist prima dell'analisi: $BLACKLIST_PRIMA"
echo "Elementi in blacklist prima: $BLACKLIST_PRIMA" >> "$LOG_MASTER"
echo ""
echo "Premere INVIO per avviare l'analisi completa, oppure CTRL+C per annullare..."
read -r

START_TIME=$(date +%s)

# ============================================================================
# ESECUZIONE SEQUENZIALE DEI 10 PROBLEMI
# ============================================================================

for i in {01..10}; do
    SCRIPT_PATH="${SCRIPT_DIR}/problema_${i}_*.sh"
    SCRIPT_NAME=$(ls $SCRIPT_PATH 2>/dev/null | head -1)
    
    if [ -f "$SCRIPT_NAME" ]; then
        echo ""
        echo "────────────────────────────────────────────────────────────────────────────"
        echo "ESECUZIONE PROBLEMA $i: $(basename $SCRIPT_NAME)"
        echo "────────────────────────────────────────────────────────────────────────────"
        echo ""
        
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Esecuzione: $SCRIPT_NAME" >> "$LOG_MASTER"
        
        # Esegui lo script
        bash "$SCRIPT_NAME"
        EXIT_CODE=$?
        
        if [ $EXIT_CODE -eq 0 ]; then
            echo "[✓] Completato con successo" >> "$LOG_MASTER"
        else
            echo "[✗] Terminato con errori (exit code: $EXIT_CODE)" >> "$LOG_MASTER"
        fi
        
        echo "" >> "$LOG_MASTER"
        
        # Pausa tra esecuzioni
        sleep 1
    else
        echo "[!] Script per problema $i non trovato: $SCRIPT_PATH"
        echo "[!] Script mancante: $SCRIPT_PATH" >> "$LOG_MASTER"
    fi
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# ============================================================================
# ANALISI POST-ESECUZIONE
# ============================================================================

echo ""
echo "================================================================================"
echo "ANALISI COMPLETATA"
echo "================================================================================"
echo ""

BLACKLIST_DOPO=$(grep -c "^" "$BLACKLIST_PATH" 2>/dev/null || echo 0)
NUOVI_ELEMENTI=$((BLACKLIST_DOPO - BLACKLIST_PRIMA))

echo "Elementi in blacklist dopo l'analisi:  $BLACKLIST_DOPO"
echo "Nuovi elementi aggiunti:               $NUOVI_ELEMENTI"
echo "Durata totale dell'analisi:            ${DURATION} secondi"
echo ""

# ============================================================================
# STATISTICHE BLACKLIST
# ============================================================================

echo "┌──────────────────────────────────────────────────────────────┐"
echo "│ STATISTICHE BLACKLIST                                        │"
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

if [ -f "$BLACKLIST_PATH" ] && [ "$BLACKLIST_DOPO" -gt 1 ]; then
    # Conta per tipologia
    echo "Distribuzione per tipo di elemento:"
    echo "────────────────────────────────────────────────────────────"
    awk -F',' 'NR>1 {count[$3]++} END {for (tipo in count) printf "  %-15s: %3d\n", tipo, count[tipo]}' "$BLACKLIST_PATH" | sort -k2 -rn
    echo ""
    
    echo "Distribuzione per origine rilevazione:"
    echo "────────────────────────────────────────────────────────────"
    awk -F',' 'NR>1 {count[$10]++} END {for (orig in count) printf "  %-20s: %3d\n", orig, count[orig]}' "$BLACKLIST_PATH" | sort -k2 -rn
    echo ""
    
    echo "Top 5 elementi con risk score più alto:"
    echo "────────────────────────────────────────────────────────────"
    awk -F',' 'NR>1 {print $8, $3, $4, $5}' "$BLACKLIST_PATH" | sort -rn | head -5 | \
        awk '{printf "  Risk: %3s | Tipo: %-10s | Elemento: %-20s | Azione: %s\n", $1, $2, $3, $4}'
    echo ""
    
    echo "Distribuzione per gravità:"
    echo "────────────────────────────────────────────────────────────"
    awk -F',' 'NR>1 {count[$5]++} END {for (grav in count) printf "  %-15s: %3d\n", grav, count[grav]}' "$BLACKLIST_PATH" | sort -k2 -rn
    echo ""
fi

# ============================================================================
# GENERAZIONE REPORT FINALE
# ============================================================================

{
    echo "================================================================================"
    echo "REPORT MASTER - ANALISI COMPLETA SICUREZZA BANCARIA"
    echo "================================================================================"
    echo ""
    echo "Data e ora esecuzione:       $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Durata totale:               ${DURATION} secondi"
    echo ""
    echo "RISULTATI GLOBALI:"
    echo "────────────────────────────────────────────────────────────"
    echo "Elementi blacklist iniziali: $BLACKLIST_PRIMA"
    echo "Elementi blacklist finali:   $BLACKLIST_DOPO"
    echo "Nuovi elementi aggiunti:     $NUOVI_ELEMENTI"
    echo ""
    echo "SCRIPT ESEGUITI:"
    echo "────────────────────────────────────────────────────────────"
    echo "  1. AML - Bonifici anomali"
    echo "  2. Accessi simultanei sospetti"
    echo "  3. Accessi notturni fuori profilo"
    echo "  4. ATM porte non autorizzate"
    echo "  5. Brute-force sulle API"
    echo "  6. Correlazione rete-servizio"
    echo "  7. Pattern anomali API"
    echo "  8. Canali covert"
    echo "  9. Incoerenze rete-operazione"
    echo " 10. Comportamenti Low & Slow"
    echo ""
    echo "RACCOMANDAZIONI:"
    echo "────────────────────────────────────────────────────────────"
    echo "• Revisionare la blacklist per confermare le minacce rilevate"
    echo "• Implementare azioni correttive per gli elementi ad alto rischio"
    echo "• Verificare manualmente gli alert critici"
    echo "• Schedulare esecuzioni periodiche di questo script"
    echo "• Aggiornare le policy di sicurezza basandosi sui risultati"
    echo ""
    echo "LOG DETTAGLIATI:"
    echo "────────────────────────────────────────────────────────────"
    echo "Ogni problema ha generato il proprio log e report in /workspaces/SO/logs/"
    echo ""
    
    if [ "$NUOVI_ELEMENTI" -eq 0 ]; then
        echo "✓ STATO: NESSUNA NUOVA MINACCIA RILEVATA"
    elif [ "$NUOVI_ELEMENTI" -lt 5 ]; then
        echo "⚠  STATO: MINACCE RILEVATE - LIVELLO BASSO"
    elif [ "$NUOVI_ELEMENTI" -lt 15 ]; then
        echo "⚠️  STATO: MINACCE RILEVATE - LIVELLO MEDIO"
    else
        echo "🚨 STATO: MINACCE RILEVATE - LIVELLO ALTO - AZIONE IMMEDIATA RICHIESTA"
    fi
    echo ""
    
} > "$REPORT_MASTER"

echo "================================================================================"
echo "[✓] ESECUZIONE MASTER COMPLETATA"
echo ""
echo "Report master salvato in:    $REPORT_MASTER"
echo "Log esecuzione salvato in:   $LOG_MASTER"
echo "Blacklist aggiornata in:     $BLACKLIST_PATH"
echo ""
echo "Per visualizzare il report completo:"
echo "  cat $REPORT_MASTER"
echo ""
echo "================================================================================"
