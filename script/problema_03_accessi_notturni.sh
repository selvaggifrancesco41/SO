#!/bin/bash

# PROBLEMA 3: RILEVAMENTO ACCESSI NOTTURNI SOSPETTI - NETWORK MONITORING
#
# SCOPO: Identificare connessioni al server durante orario notturno (22:00-06:00)
#        che potrebbero indicare attività non autorizzate o compromissione
#
# METODO: Usa ss/netstat per monitorare connessioni attive durante fasce orarie
#         sospette, verifica IP sorgente con nslookup/host per geolocalizzazione
#
# DATABASE: Usato SOLO per lookup puntuale customer_id (opzionale)
# BLACKLIST: Registra IP che si connettono in orari anomali
#
# DIPENDENZE: ss, date, host/nslookup, awk

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_NOTTURNI="/workspaces/SO/logs/notturni_alerts.log"
DB_PATH="/workspaces/SO/data/eventi_bancari.db"

# Parametri
SERVER_PORT=8000
ORA_INIZIO_NOTTE=22    # 22:00 (10 PM)
ORA_FINE_NOTTE=6       # 06:00 (6 AM)
INTERVALLO_CHECK=10    # Secondi tra controlli
DURATA_MONITORAGGIO=180  # 3 minuti totali

mkdir -p $(dirname "$LOG_NOTTURNI")

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
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ]; do
    
    ORA_ATTUALE=$(date '+%H:%M:%S')
    echo "[Check #$ITERAZIONI] $ORA_ATTUALE"
    
    # Verifica se siamo in orario notturno
    if verifica_orario_notturno; then
        echo "  → ORARIO NOTTURNO - Analisi attiva"
        
        # ss: socket statistics
        # -t: TCP sockets only
        # -n: numeric (no DNS resolution, più veloce)
        # state established: solo connessioni stabilite
        # sport = :8000: source port (porta del server)
        # awk NR>1: salta header (Number of Record > 1)
        # $5: campo 5 contiene IP:porta remoto
        IPS_CONNESSI=$(ss -tn state established sport = :$SERVER_PORT 2>/dev/null | \
            awk 'NR>1 {print $5}' | cut -d':' -f1 | sort -u)
        
        # wc -l: conta linee (word count lines)
        NUM_CONNESSIONI=$(echo "$IPS_CONNESSI" | grep -c '^' 2>/dev/null || echo 0)
        
        # -gt: greater than (>)
        if [ $NUM_CONNESSIONI -gt 0 ]; then
            echo "  → Connessioni attive in orario notturno: $NUM_CONNESSIONI"
            echo ""
            
            # Analizza ogni IP connesso
            echo "$IPS_CONNESSI" | while read -r suspicious_ip; do
                
                # -n: verifica stringa NON vuota
                if [ -n "$suspicious_ip" ]; then
                    
                    echo "  [!] IP NOTTURNO: $suspicious_ip"
                    
                    # Risolvi hostname per identificare provider
                    HOSTNAME=$(resolve_hostname "$suspicious_ip")
                    echo "      → Hostname: $HOSTNAME"
                    
                    # Lookup customer_id dal database (SOLO query puntuale)
                    CUSTOMER_QUERY="SELECT customer_id FROM eventi 
                                    WHERE ip_address='$suspicious_ip' 
                                    ORDER BY timestamp DESC LIMIT 1"
                    customer_id=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null)
                    
                    if [ -z "$customer_id" ]; then
                        customer_id="UNKNOWN"
                    fi
                    echo "      → Customer: $customer_id"
                    
                    # Controlla blacklist
                    if controlla_blacklist "IP" "$suspicious_ip"; then
                        echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                        aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_NOTTURNO" \
                            "ALTA" 50 "Connessione in orario notturno ($ORA_ATTUALE), hostname: $HOSTNAME, customer: $customer_id"
                    else
                        echo "      → PRIMO RILEVAMENTO"
                        aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_NOTTURNO" \
                            "MEDIA" 30 "Connessione in orario notturno ($ORA_ATTUALE), hostname: $HOSTNAME, customer: $customer_id"
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
                        echo "Orario:       $ORA_ATTUALE"
                        echo ""
                    } >> "$LOG_NOTTURNI"
                    
                    echo ""
                fi
            done
        else
            echo "  → Nessuna connessione attiva"
        fi
    else
        echo "  → Orario diurno - Skip analisi"
    fi
    
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
