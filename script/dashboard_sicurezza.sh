#!/bin/bash

################################################################################
# DASHBOARD DI SICUREZZA BANCARIA - STATO ATTUALE DEL SISTEMA
################################################################################

DB_PATH="/workspaces/SO/data/bank_logs.db"
BLACKLIST_PATH="/workspaces/SO/blacklist.csv"

echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo "┃                   DASHBOARD SICUREZZA BANCARIA                        ┃"
echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
echo ""
echo "Data e ora: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# ============================================================================
# STATO DATABASE EVENTI
# ============================================================================

echo "┌────────────────────────────────────────────────────────────────────────┐"
echo "│ DATABASE EVENTI BANCARI                                                │"
echo "└────────────────────────────────────────────────────────────────────────┘"
echo ""

if [ -f "$DB_PATH" ]; then
    TOTALE_EVENTI=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM logs;" 2>/dev/null || echo 0)
    
    echo "Totale eventi registrati:     $TOTALE_EVENTI"
    echo ""
    
    if [ "$TOTALE_EVENTI" -gt 0 ]; then
        echo "Distribuzione per azione:"
        sqlite3 "$DB_PATH" "SELECT azione, COUNT(*) as count FROM logs GROUP BY azione ORDER BY count DESC;" 2>/dev/null | \
            awk -F'|' '{printf "  %-15s: %6s eventi\n", $1, $2}'
        echo ""
        
        echo "Eventi ultimi 7 giorni:       $(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM logs WHERE datetime(timestamp) >= datetime('now', '-7 days');" 2>/dev/null)"
        echo "Eventi ultime 24 ore:         $(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM logs WHERE datetime(timestamp) >= datetime('now', '-1 day');" 2>/dev/null)"
        echo ""
        
        echo "IP unici registrati:          $(sqlite3 "$DB_PATH" "SELECT COUNT(DISTINCT ip_address) FROM logs;" 2>/dev/null)"
        echo "Account unici attivi:         $(sqlite3 "$DB_PATH" "SELECT COUNT(DISTINCT customer_id) FROM logs;" 2>/dev/null)"
        echo ""
    fi
else
    echo "⚠️  Database non trovato: $DB_PATH"
    echo "Esegui: ./popola_database_test.sh"
fi

# ============================================================================
# STATO BLACKLIST
# ============================================================================

echo "┌────────────────────────────────────────────────────────────────────────┐"
echo "│ BLACKLIST SICUREZZA                                                    │"
echo "└────────────────────────────────────────────────────────────────────────┘"
echo ""

if [ -f "$BLACKLIST_PATH" ] && [ -s "$BLACKLIST_PATH" ]; then
    TOTALE_BLACKLIST=$(($(wc -l < "$BLACKLIST_PATH") - 1))
    
    if [ "$TOTALE_BLACKLIST" -gt 0 ]; then
        echo "Elementi in blacklist:        $TOTALE_BLACKLIST"
        echo ""
        
        echo "Distribuzione per tipo:"
        awk -F',' 'NR>1 {count[$3]++} END {for (tipo in count) printf "  %-15s: %6d\n", tipo, count[tipo]}' "$BLACKLIST_PATH" | sort -k2 -rn
        echo ""
        
        echo "Distribuzione per gravità:"
        awk -F',' 'NR>1 {count[$5]++} END {for (grav in count) printf "  %-15s: %6d\n", grav, count[grav]}' "$BLACKLIST_PATH" | sort -k2 -rn
        echo ""
        
        # Elementi critici
        CRITICI=$(awk -F',' 'NR>1 && $5=="CRITICA"' "$BLACKLIST_PATH" | wc -l)
        ALTI=$(awk -F',' 'NR>1 && $5=="ALTA"' "$BLACKLIST_PATH" | wc -l)
        
        echo "Livello di allerta:"
        if [ "$CRITICI" -gt 0 ]; then
            echo "  🚨 CRITICO: $CRITICI elementi ad alto rischio"
        elif [ "$ALTI" -gt 5 ]; then
            echo "  ⚠️  ELEVATO: $ALTI elementi a rischio alto"
        elif [ "$TOTALE_BLACKLIST" -gt 10 ]; then
            echo "  ⚠  MEDIO: Sistema sotto monitoraggio"
        else
            echo "  ✓ BASSO: Situazione sotto controllo"
        fi
        echo ""
        
        echo "Top 5 elementi più rischiosi:"
        awk -F',' 'NR>1 {printf "%03d|%s|%s|%s\n", $8, $3, $4, $5}' "$BLACKLIST_PATH" | \
            sort -t'|' -k1 -rn | head -5 | \
            awk -F'|' '{printf "  Risk %3s | %-10s | %-25s | %s\n", $1, $2, substr($3,1,25), $4}'
        echo ""
        
    else
        echo "✓ Nessun elemento in blacklist"
        echo "  Sistema pulito - nessuna minaccia rilevata"
        echo ""
    fi
else
    echo "✓ Blacklist vuota o non inizializzata"
    echo "  Esegui: ./esegui_tutti_controlli.sh"
    echo ""
fi

# ============================================================================
# LOG E REPORT DISPONIBILI
# ============================================================================

echo "┌────────────────────────────────────────────────────────────────────────┐"
echo "│ LOG E REPORT                                                           │"
echo "└────────────────────────────────────────────────────────────────────────┘"
echo ""

LOG_DIR="/workspaces/SO/logs"

if [ -d "$LOG_DIR" ]; then
    NUM_LOG=$(find "$LOG_DIR" -type f -name "*.log" 2>/dev/null | wc -l)
    NUM_REPORT=$(find "$LOG_DIR" -type f -name "*.txt" 2>/dev/null | wc -l)
    
    echo "File di log disponibili:      $NUM_LOG"
    echo "Report disponibili:           $NUM_REPORT"
    echo ""
    
    if [ "$NUM_LOG" -gt 0 ] || [ "$NUM_REPORT" -gt 0 ]; then
        echo "Ultimi file generati:"
        ls -lt "$LOG_DIR"/*.{log,txt} 2>/dev/null | head -5 | \
            awk '{print "  " $9 " (" $6 " " $7 " " $8 ")"}'
        echo ""
    fi
else
    echo "Nessun log disponibile"
    echo ""
fi

# ============================================================================
# AZIONI CONSIGLIATE
# ============================================================================

echo "┌────────────────────────────────────────────────────────────────────────┐"
echo "│ AZIONI CONSIGLIATE                                                     │"
echo "└────────────────────────────────────────────────────────────────────────┘"
echo ""

if [ ! -f "$DB_PATH" ] || [ "$TOTALE_EVENTI" -eq 0 ]; then
    echo "1. Popola il database con dati di test:"
    echo "   ./popola_database_test.sh"
    echo ""
fi

if [ ! -f "$BLACKLIST_PATH" ] || [ "$TOTALE_BLACKLIST" -eq 0 ]; then
    echo "2. Esegui i controlli di sicurezza:"
    echo "   ./esegui_tutti_controlli.sh"
    echo ""
fi

if [ "$CRITICI" -gt 0 ]; then
    echo "⚠️  URGENTE: Elementi critici rilevati"
    echo "   Revisiona: cat /workspaces/SO/blacklist.csv | grep CRITICA"
    echo ""
fi

echo "Per maggiori dettagli:"
echo "  cat /workspaces/SO/logs/master_report.txt"
echo "  cat /workspaces/SO/GUIDA_SISTEMA_SICUREZZA.md"
echo ""

echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo "┃                    Fine Dashboard                                      ┃"
echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
