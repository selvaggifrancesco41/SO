#!/bin/bash

# PROBLEMA 5: RILEVAMENTO BRUTE-FORCE LOGIN - DATABASE ANALYSIS
#
# SCOPO: Rilevare tentativi di brute-force sulle API /login del server
#        monitorando frequenza richieste HTTP da stessi IP sorgente
#
# METODO: Analizza database per contare login per IP in finestra temporale,
#         rileva pattern di attacco (10+ tentativi in 10s)
#
# DATABASE: Query periodiche per eventi LOGIN da stessi IP
# BLACKLIST: Controlla e registra IP che eseguono brute-force
#
# DIPENDENZE: sqlite3, date, awk

# Output minimale: riduce il rumore sul terminale
# FD 3 resta collegato al terminale per messaggi essenziali
exec 3>&1
# Silenzia stdout standard per tutte le stampe verbose
exec 1>/dev/null

# Stampa solo le righe essenziali su terminale
log() {
    # Usa FD 3 per non essere silenziato
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_BRUTEFORCE="/workspaces/SO/logs/bruteforce_alerts.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"
LAST_CHECK_FILE="/tmp/problema05_last_check.txt"

# Parametri rilevamento
SOGLIA_TENTATIVI=10                # Max tentativi login da stesso IP in finestra
FINESTRA_SECONDI=10                # Finestra temporale di analisi
INTERVALLO_CHECK=2                 # Intervallo tra check (secondi)
DURATA_MONITORAGGIO=60             # Durata totale monitoraggio

# Soglia di blocco per risk_score (IP)
RISK_BLOCK_THRESHOLD=100

mkdir -p $(dirname "$LOG_BRUTEFORCE")

# Inizializza timestamp ultimo check (solo se non esiste)
if [ ! -f "$LAST_CHECK_FILE" ]; then
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
fi

# Array per tracciare IP già segnalati in questa sessione
declare -A SEGNALATI

# FUNZIONE: controlla_blacklist
# ARG1: tipo (IP, USER_ID, IBAN, PORTA, ATM_ID)
# ARG2: valore elemento
# RETURN: 0 se presente in blacklist, 1 se assente
# NOTE: grep -q silent mode, 2>/dev/null scarta errori
controlla_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    grep -q "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH" 2>/dev/null
    return $?
}

# FUNZIONE: get_risk_score
# ARG1: tipo_elemento
# ARG2: elemento
# OUTPUT: risk_score (numero) oppure 0 se non trovato
# NOTE: awk separa CSV con -F',', $7 è colonna risk_score
get_risk_score() {
    local tipo_elemento="$1"
    local elemento="$2"
    
    local score=$(awk -F',' -v tipo="$tipo_elemento" -v elem="$elemento" \
        '$3==tipo && $4==elem {print $7}' "$BLACKLIST_PATH" | tail -1)
    
    # -z: controllo se stringa vuota (zero length)
    if [ -z "$score" ]; then
        echo 0
    else
        echo "$score"
    fi
}

# FUNZIONE: aggiungi_blacklist
# ARGS: tipo, elemento, azione, gravita, risk_score, note
# COMPORTAMENTO: Aggiunge a blacklist, se recidivo incrementa risk e recidivita
aggiungi_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    local azione="$3"
    local gravita="$4"
    local risk_score="$5"
    local note="$6"
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local stato="blacklisted"
    local final_risk="$risk_score"
    
    if controlla_blacklist "$tipo_elemento" "$elemento"; then
        # RECIDIVO
        local current_risk=$(get_risk_score "$tipo_elemento" "$elemento")
        # grep -c conta numero di match
        local recidivita=$(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH")
        recidivita=$((recidivita + 1))
        # $(( )) arithmetic expansion per somma
        local new_risk=$((current_risk + risk_score))
        final_risk="$new_risk"
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_con_iptables "$elemento"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_BRUTEFORCE"
        fi
        
        # >> append al file senza sovrascrivere
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},BRUTEFORCE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        # NUOVO
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_con_iptables "$elemento"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_BRUTEFORCE"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},BRUTEFORCE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: blocca_ip_con_iptables
# ARG1: IP da bloccare
# AZIONE: Aggiunge regola iptables DROP per quell'IP
# NOTE: Richiede sudo, verifica prima se iptables disponibile
blocca_ip_con_iptables() {
    local ip_to_block="$1"
    
    # command -v verifica se comando esiste nel PATH
    if command -v iptables &> /dev/null; then
        echo "[*] Tentativo blocco IP $ip_to_block con iptables..."
        
        # iptables -A INPUT: append regola alla chain INPUT
        # -s: source IP
        # -j DROP: jump to DROP target (scarta pacchetto)
        # 2>&1: redirige stderr su stdout per catturare errori
        sudo iptables -A INPUT -s "$ip_to_block" -j DROP 2>&1
        
        # $?: exit code del comando precedente (0 = success, != 0 = error)
        if [ $? -eq 0 ]; then
            echo "[✓] IP $ip_to_block bloccato con iptables"
        else
            echo "[!] Errore blocco (potrebbe servire sudo o permessi)"
        fi
    else
        echo "[!] iptables non disponibile, skip blocco"
    fi
}

# AVVIO MONITORAGGIO
# Messaggio minimo di avvio
log "P05 start"
# Log dettagliato su file
echo "================================================================================" >> "$LOG_BRUTEFORCE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] RILEVAMENTO BRUTE-FORCE AVVIATO" >> "$LOG_BRUTEFORCE"
echo "================================================================================" >> "$LOG_BRUTEFORCE"

# Output verbose silenziato da exec 1>/dev/null
echo "[*] Soglia tentativi: $SOGLIA_TENTATIVI in $FINESTRA_SECONDI secondi"
echo "[*] Intervallo check: $INTERVALLO_CHECK secondi"
echo "[*] Durata monitoraggio: $DURATA_MONITORAGGIO secondi"
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
    ORA_ATTUALE=$(date '+%H:%M:%S')
    echo "[Check #$ITERAZIONI] $ORA_ATTUALE"
    
    # Leggi timestamp ultimo check
    LAST_CHECK=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo "1970-01-01T00:00:00")
    
    # Query: trova tutti i login recenti dall'ultimo check
    QUERY="SELECT timestamp, customer_id, ip_address 
           FROM logs 
           WHERE azione = 'LOGIN' 
           AND timestamp > '$LAST_CHECK'
           ORDER BY timestamp DESC"
    
    LOGIN_RECENTI=$(sqlite3 "$DB_PATH" "$QUERY" 2>/dev/null)
    
    if [ -n "$LOGIN_RECENTI" ]; then
        # Estrai IP unici
        IPS_UNICI=$(echo "$LOGIN_RECENTI" | cut -d'|' -f3 | sort -u)
        
        echo "  → Login rilevati: $(echo "$LOGIN_RECENTI" | wc -l)"
        echo "  → IP unici: $(echo "$IPS_UNICI" | wc -l)"
        echo ""
        
        # Per ogni IP unico, conta tentativi negli ultimi FINESTRA_SECONDI
        while read -r suspicious_ip; do
            
            if [ -z "$suspicious_ip" ]; then
                continue
            fi
            
            # Calcola timestamp inizio finestra (FINESTRA_SECONDI fa)
            WINDOW_START=$(date -u -d "$FINESTRA_SECONDI seconds ago" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null)
            if [ -z "$WINDOW_START" ]; then
                # Fallback per sistemi senza GNU date
                WINDOW_START=$(date -u '+%Y-%m-%dT%H:%M:%S')
            fi
            
            # Conta login da questo IP nella finestra temporale
            COUNT_QUERY="SELECT COUNT(*) 
                         FROM logs 
                         WHERE azione = 'LOGIN' 
                         AND ip_address = '$suspicious_ip'
                         AND timestamp >= '$WINDOW_START'"
            
            TENTATIVI=$(sqlite3 "$DB_PATH" "$COUNT_QUERY" 2>/dev/null)
            
            # Query per customer_id associati
            CUSTOMER_QUERY="SELECT DISTINCT customer_id 
                            FROM logs 
                            WHERE azione = 'LOGIN' 
                            AND ip_address = '$suspicious_ip'
                            AND timestamp >= '$WINDOW_START'
                            ORDER BY customer_id 
                            LIMIT 10"
            
            CUSTOMER_IDS=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null | paste -sd ',' -)
            
            echo "  → IP: $suspicious_ip | Tentativi ultimi ${FINESTRA_SECONDI}s: $TENTATIVI"
            
            # Controllo soglia
            if [ "$TENTATIVI" -ge "$SOGLIA_TENTATIVI" ]; then
                echo ""
                echo "  [!!!] BRUTE-FORCE RILEVATO DA $suspicious_ip!"
                echo "  [!!!] $TENTATIVI tentativi in $FINESTRA_SECONDI secondi"
                
                if [ -n "$CUSTOMER_IDS" ]; then
                    echo "  [!!!] Account vittima: $CUSTOMER_IDS"
                else
                    CUSTOMER_IDS="UNKNOWN"
                fi
                echo ""
                
                # Segnala solo se non già fatto in questa sessione
                if [ -z "${SEGNALATI[$suspicious_ip]}" ]; then
                    SEGNALATI[$suspicious_ip]=1
                    
                    # Controlla blacklist
                    if controlla_blacklist "IP" "$suspicious_ip"; then
                        echo "  → GIÀ IN BLACKLIST (RECIDIVO, gravità CRITICA)"
                        aggiungi_blacklist "IP" "$suspicious_ip" "BRUTE_FORCE_LOGIN" \
                            "CRITICA" 100 "Attacco brute-force: $TENTATIVI tentativi in ${FINESTRA_SECONDI}s, account vittima: $CUSTOMER_IDS"
                    else
                        echo "  → PRIMO RILEVAMENTO"
                        aggiungi_blacklist "IP" "$suspicious_ip" "BRUTE_FORCE_LOGIN" \
                            "ALTA" 70 "Attacco brute-force: $TENTATIVI tentativi in ${FINESTRA_SECONDI}s, account vittima: $CUSTOMER_IDS"
                    fi
                    
                    # Messaggio minimo di alert
                    log "P05 alert $suspicious_ip"

                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    
                    # Log dettagliato
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT BRUTE-FORCE - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "IP attaccante:      $suspicious_ip"
                        echo "Account vittima:    $CUSTOMER_IDS"
                        echo "Tentativi:          $TENTATIVI"
                        echo "Finestra:           $FINESTRA_SECONDI secondi"
                        echo "Soglia:             $SOGLIA_TENTATIVI"
                        echo ""
                    } >> "$LOG_BRUTEFORCE"
                    
                    break
                else
                    echo "  → Già segnalato in questa sessione (SKIP)"
                fi
                
                echo ""
            fi
        done < <(echo "$IPS_UNICI")
    else
        echo "  → Nessun login recente rilevato"
    fi
    
    # Aggiorna timestamp ultimo check
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
    
    echo ""
    ITERAZIONI=$((ITERAZIONI + 1))
    
    if [ $ITERAZIONI -lt $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; then
        sleep $INTERVALLO_CHECK
    fi
done

# Report finale (verbose, silenziato)
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert brute-force: $ALERT_COUNT"
echo "[*] Log: $LOG_BRUTEFORCE"
echo "================================================================================"

# Messaggio minimo di fine
log "P05 done"

