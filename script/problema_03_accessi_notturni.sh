#!/bin/bash

# PROBLEMA 3: RILEVAMENTO ACCESSI NOTTURNI SOSPETTI - DATABASE ANALYSIS
#
# SCOPO: Identificare login al server durante orario notturno (22:00-06:00)
#        che potrebbero indicare attività non autorizzate o compromissione
#
# METODO: Analizza periodicamente il database eventi per trovare eventi di tipo 'login'
#         con timestamp in orario notturno. Verifica IP sorgente e customer_id
#
# DATABASE: Query periodiche per eventi recenti in fascia oraria sospetta
# BLACKLIST: Registra IP che fanno login in orari anomali
#
# DIPENDENZE: sqlite3, date, awk

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_NOTTURNI="/workspaces/SO/logs/notturni_alerts.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"
LAST_CHECK_FILE="/tmp/problema03_last_check.txt"

# Parametri
SERVER_PORT=8000
ORA_INIZIO_NOTTE=22    # 22:00 (10 PM)
ORA_FINE_NOTTE=6       # 06:00 (6 AM)
INTERVALLO_CHECK=2     # Secondi tra controlli
DURATA_MONITORAGGIO=30   # 30 secondi totale

mkdir -p $(dirname "$LOG_NOTTURNI")

# Inizializza timestamp ultimo check (solo se non esiste)
if [ ! -f "$LAST_CHECK_FILE" ]; then
    # Primo avvio: usa timestamp corrente in formato ISO
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
fi

# FUNZIONE: controlla_blacklist
controlla_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    # grep -q: quiet mode, ritorna solo exit code (0=trovato, 1=non trovato)
    grep -q "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH" 2>/dev/null
    return $?
}

# FUNZIONE: get_risk_score
get_risk_score() {
    local tipo_elemento="$1"
    local elemento="$2"
    # awk: estrae campo 7 (risk_score) dalla blacklist CSV
    local score=$(awk -F',' -v tipo="$tipo_elemento" -v elem="$elemento" \
        '$3==tipo && $4==elem {print $7}' "$BLACKLIST_PATH" | tail -1)
    # -z: verifica se stringa vuota (zero-length)
    if [ -z "$score" ]; then
        echo 0
    else
        echo "$score"
    fi
}

# FUNZIONE: aggiungi_blacklist
aggiungi_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    local azione="$3"
    local gravita="$4"
    local risk_score="$5"
    local note="$6"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if controlla_blacklist "$tipo_elemento" "$elemento"; then
        local current_risk=$(get_risk_score "$tipo_elemento" "$elemento")
        # grep -c: conta occorrenze (-c = count)
        local recidivita=$(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH")
        recidivita=$((recidivita + 1))
        local new_risk=$((current_risk + risk_score))
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,ACCESSI_NOTTURNI,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,ACCESSI_NOTTURNI,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: verifica_orario_notturno
# RETURN: 0 se è orario notturno, 1 se diurno
verifica_orario_notturno() {
    # Se TEST_MODE è attivo, forza sempre modalità notturna
    if [ "${TEST_MODE:-0}" = "1" ]; then
        return 0  # Modalità test - forza orario notturno
    fi
    
    # date +%H: estrae ora corrente in formato 24h (00-23)
    local ora_corrente=$(date +%H)
    # Rimuovi zero iniziale per confronto numerico
    # ${var#0}: rimuove 0 iniziale (bash parameter expansion)
    ora_corrente=${ora_corrente#0}
    
    # -ge: greater or equal (>=)
    # -lt: less than (<)
    if [ $ora_corrente -ge $ORA_INIZIO_NOTTE ] || [ $ora_corrente -lt $ORA_FINE_NOTTE ]; then
        return 0  # È notte
    else
        return 1  # È giorno
    fi
}

# FUNZIONE: resolve_hostname
# Tenta di risolvere IP in hostname per identificare provider/organizzazione
resolve_hostname() {
    local ip="$1"
    # host: DNS lookup (più veloce di nslookup)
    # grep "domain name pointer": filtra solo righe PTR record
    # awk: estrae ultimo campo (hostname)
    local hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}')
    
    # -z: se vuoto
    if [ -z "$hostname" ]; then
        echo "UNKNOWN"
    else
        echo "$hostname"
    fi
}

# AVVIO MONITORAGGIO
echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO ACCESSI NOTTURNI AVVIATO"
echo "================================================================================" | tee -a "$LOG_NOTTURNI"

echo "[*] Porta monitorata: $SERVER_PORT"
echo "[*] Orario notturno: ${ORA_INIZIO_NOTTE}:00 - 0${ORA_FINE_NOTTE}:00"
echo "[*] Intervallo check: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
if [ "${TEST_MODE:-0}" = "1" ]; then
    echo "[*] MODALITÀ TEST: controllo orario bypassato"
fi
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ]; do
    
    ORA_ATTUALE=$(date '+%H:%M:%S')
    echo "[Check #$ITERAZIONI] $ORA_ATTUALE"
    
    # Leggi timestamp ultimo check
    LAST_CHECK=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo "1970-01-01T00:00:00")
    
    # Verifica se siamo in orario notturno (o in modalità TEST)
    if verifica_orario_notturno; then
        if [ "${TEST_MODE:-0}" = "1" ]; then
            echo "  → MODALITÀ TEST - Analisi attiva"
        else
            echo "  → ORARIO NOTTURNO - Analisi attiva"
        fi
        
        # Query: trova login recenti in orario notturno
        # In modalità TEST, considera tutti i login
        # Altrimenti, filtra solo quelli con ora tra 22:00-06:00
        if [ "${TEST_MODE:-0}" = "1" ]; then
            # Modalità test: rileva tutti i login recenti
            QUERY="SELECT timestamp, customer_id, ip_address, session_duration 
                   FROM logs 
                   WHERE azione = 'LOGIN' 
                   AND timestamp > '$LAST_CHECK'
                   ORDER BY timestamp DESC"
        else
            # Modalità normale: solo login in orario notturno (22:00-06:00)
            QUERY="SELECT timestamp, customer_id, ip_address, session_duration 
                   FROM logs 
                   WHERE azione = 'LOGIN' 
                   AND timestamp > '$LAST_CHECK'
                   AND (CAST(strftime('%H', timestamp) AS INTEGER) >= $ORA_INIZIO_NOTTE 
                        OR CAST(strftime('%H', timestamp) AS INTEGER) < $ORA_FINE_NOTTE)
                   ORDER BY timestamp DESC"
        fi
        
        # Esegui query e processa risultati
        LOGIN_NOTTURNI=$(sqlite3 "$DB_PATH" "$QUERY" 2>/dev/null)
        
        if [ -n "$LOGIN_NOTTURNI" ]; then
            NUM_LOGIN=$(echo "$LOGIN_NOTTURNI" | wc -l)
            echo "  → Login rilevati: $NUM_LOGIN"
            echo ""
            
            # Processa ogni login (formato: timestamp|customer_id|ip_address|session_duration)
            echo "$LOGIN_NOTTURNI" | while IFS='|' read -r timestamp customer_id suspicious_ip session_dur; do
                
                if [ -n "$suspicious_ip" ]; then
                    
                    echo "  [!] LOGIN NOTTURNO RILEVATO"
                    echo "      → Timestamp: $timestamp"
                    echo "      → Customer: $customer_id"
                    echo "      → IP: $suspicious_ip"
                    echo "      → Durata sessione: ${session_dur}s"
                    
                    # Risolvi hostname per identificare provider
                    HOSTNAME=$(resolve_hostname "$suspicious_ip")
                    echo "      → Hostname: $HOSTNAME"
                    
                    # Controlla blacklist
                    if controlla_blacklist "IP" "$suspicious_ip"; then
                        echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                        aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_NOTTURNO" \
                            "ALTA" 50 "Login notturno ($timestamp), customer: $customer_id, hostname: $HOSTNAME"
                    else
                        echo "      → PRIMO RILEVAMENTO"
                        aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_NOTTURNO" \
                            "MEDIA" 30 "Login notturno ($timestamp), customer: $customer_id, hostname: $HOSTNAME"
                    fi
                    
                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    
                    # Log dettagliato
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT NOTTURNO - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "IP:           $suspicious_ip"
                        echo "Hostname:     $HOSTNAME"
                        echo "Customer:     $customer_id"
                        echo "Timestamp:    $timestamp"
                        echo "Sessione:     ${session_dur}s"
                        echo ""
                    } >> "$LOG_NOTTURNI"
                    
                    echo ""
                fi
            done
        else
            echo "  → Nessun login rilevato"
        fi
    else
        echo "  → Orario diurno - Skip analisi"
    fi
    
    # Aggiorna timestamp ultimo check (formato ISO compatibile con DB)
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
    
    echo ""
    ITERAZIONI=$((ITERAZIONI + 1))
    
    # -lt: less than (<)
    if [ $ITERAZIONI -lt $MAX_ITERAZIONI ]; then
        sleep $INTERVALLO_CHECK
    fi
done

echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_NOTTURNI"
echo "================================================================================"
