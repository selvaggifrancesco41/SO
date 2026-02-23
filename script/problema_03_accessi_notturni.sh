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
LOG_NOTTURNI="/workspaces/SO/logs/notturni_alerts.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"
LAST_CHECK_FILE="/tmp/problema03_last_check.txt"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"
NOTIFY_LOG="/workspaces/SO/logs/notifiche_email.txt"

# Parametri
SERVER_PORT=8000
ORA_INIZIO_NOTTE=22    # 22:00 (10 PM)
ORA_FINE_NOTTE=6       # 06:00 (6 AM)
INTERVALLO_CHECK=2     # Secondi tra controlli
DURATA_MONITORAGGIO=30   # 30 secondi totale

# Soglia di blocco per risk_score (IP)
RISK_BLOCK_THRESHOLD=100

# Crea directory log se non esistono
mkdir -p $(dirname "$LOG_NOTTURNI")
mkdir -p $(dirname "$NOTIFY_LOG")

# Inizializza timestamp ultimo check (solo se non esiste)
if [ ! -f "$LAST_CHECK_FILE" ]; then
    # Primo avvio: usa timestamp corrente in formato ISO
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
fi

# Array per tracciare IP già segnalati in questa sessione
declare -A SEGNALATI

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

# FUNZIONE: blocca_ip_se_necessario
# Blocca l'IP con iptables quando il risk_score supera la soglia
blocca_ip_se_necessario() {
    local ip_to_block="$1"
    local risk_score="$2"

    # Blocca solo se supera la soglia e iptables e' disponibile
    if [ "$risk_score" -ge "$RISK_BLOCK_THRESHOLD" ] && command -v iptables >/dev/null 2>&1; then
        # Evita duplicati: -C verifica se la regola esiste gia'
        if ! iptables -C INPUT -s "$ip_to_block" -j DROP 2>/dev/null; then
            iptables -A INPUT -s "$ip_to_block" -j DROP 2>/dev/null
        fi
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
    local stato="blacklisted"
    local final_risk="$risk_score"
    
    if controlla_blacklist "$tipo_elemento" "$elemento"; then
        local current_risk=$(get_risk_score "$tipo_elemento" "$elemento")
        # grep -c: conta occorrenze (-c = count)
        local recidivita=$(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH")
        recidivita=$((recidivita + 1))
        local new_risk=$((current_risk + risk_score))
        final_risk="$new_risk"
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_NOTTURNI"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},ACCESSI_NOTTURNI,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_NOTTURNI"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},ACCESSI_NOTTURNI,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: get_cliente_info
# Recupera email, 2FA e nome dal CSV clienti_banca.csv
# OUTPUT: email|two_factor_enabled|nome
get_cliente_info() {
    local customer_id="$1"

    # Usa Python per leggere CSV con campi quoted
    python3 - "$customer_id" <<'PY'
import csv
import sys

cid = sys.argv[1]
email = "UNKNOWN"
twofa = "False"
name = "UNKNOWN"

with open("/workspaces/SO/clienti_banca.csv", "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row.get("customer_id") == cid:
            email = row.get("email", "UNKNOWN")
            twofa = row.get("two_factor_enabled", "False")
            first = row.get("first_name", "")
            last = row.get("last_name", "")
            full = (first + " " + last).strip()
            name = full if full else "UNKNOWN"
            break

print(f"{email}|{twofa}|{name}")
PY
}

# FUNZIONE: notifica_cliente
# Scrive una notifica email simulata in logs/notifiche_email.txt
notifica_cliente() {
    local customer_id="$1"
    local info
    local email
    local twofa
    local nome
    local twofa_lower
    local timestamp

    # Estrae info cliente dal CSV
    info=$(get_cliente_info "$customer_id")
    email=$(echo "$info" | cut -d'|' -f1)
    twofa=$(echo "$info" | cut -d'|' -f2)
    nome=$(echo "$info" | cut -d'|' -f3)

    # Normalizza il valore 2FA a minuscolo
    twofa_lower=$(echo "$twofa" | tr 'A-Z' 'a-z')
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Se 2FA non attiva: chiedi attivazione
    if [ "$twofa_lower" = "false" ] || [ "$twofa_lower" = "0" ] || [ "$twofa_lower" = "no" ]; then
        echo "[$timestamp] TO:$email CUSTOMER:$customer_id NAME:$nome SUBJECT:Attiva 2FA BODY:Abbiamo rilevato un accesso notturno sul tuo conto. Attiva subito l'autenticazione a due fattori." >> "$NOTIFY_LOG"
    else
        # Se 2FA attiva: notifica movimenti sospetti
        echo "[$timestamp] TO:$email CUSTOMER:$customer_id NAME:$nome SUBJECT:Movimenti sospetti BODY:Abbiamo rilevato un accesso notturno sul tuo conto. Se non riconosci queste operazioni contatta il supporto." >> "$NOTIFY_LOG"
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
# Messaggio minimo di avvio
log "P03 start"
# Log dettagliato su file
echo "================================================================================" >> "$LOG_NOTTURNI"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO ACCESSI NOTTURNI AVVIATO" >> "$LOG_NOTTURNI"
echo "================================================================================" >> "$LOG_NOTTURNI"

# Output verbose silenziato da exec 1>/dev/null
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

while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
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
            # Usa process substitution per evitare subshell (mantiene SEGNALATI e ALERT_COUNT)
            while IFS='|' read -r timestamp customer_id suspicious_ip session_dur; do
                
                if [ -n "$suspicious_ip" ]; then
                    
                    echo "  [!] LOGIN NOTTURNO RILEVATO"
                    echo "      → Timestamp: $timestamp"
                    echo "      → Customer: $customer_id"
                    echo "      → IP: $suspicious_ip"
                    echo "      → Durata sessione: ${session_dur}s"
                    
                    # Risolvi hostname per identificare provider
                    HOSTNAME=$(resolve_hostname "$suspicious_ip")
                    echo "      → Hostname: $HOSTNAME"
                    
                    # Segnala solo se non già fatto in questa sessione
                    if [ -z "${SEGNALATI[$suspicious_ip]}" ]; then
                        SEGNALATI[$suspicious_ip]=1
                        
                        # Controlla blacklist
                        if controlla_blacklist "IP" "$suspicious_ip"; then
                            echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                            aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_NOTTURNO" \
                                "ALTA" 50 "Login notturno ($timestamp); customer: $customer_id; hostname: $HOSTNAME"
                        else
                            echo "      → PRIMO RILEVAMENTO"
                            aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_NOTTURNO" \
                                "MEDIA" 30 "Login notturno ($timestamp); customer: $customer_id; hostname: $HOSTNAME"
                        fi

                        # Notifica cliente (2FA o movimenti sospetti)
                        notifica_cliente "$customer_id"
                        
                        # Messaggio minimo di alert
                        log "P03 alert $suspicious_ip"

                        ALERT_COUNT=$((ALERT_COUNT + 1))
                        
                        # Log dettagliato - solo al primo rilevamento
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
                        
                        # Esci dal while dopo il primo alert (anomalia trovata)
                        break
                    else
                        echo "      → Già segnalato in questa sessione (SKIP)"
                    fi
                    
                    echo ""
                fi
            done < <(echo "$LOGIN_NOTTURNI")
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

# Report finale (verbose, silenziato)
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_NOTTURNI"
echo "================================================================================"

# Messaggio minimo di fine
log "P03 done"
