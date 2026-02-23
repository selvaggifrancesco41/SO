#!/bin/bash

# PROBLEMA 2: RILEVAMENTO ACCESSI SIMULTANEI SOSPETTI - NETWORK MONITORING
#
# SCOPO: Identificare connessioni TCP simultanee allo stesso server da IP diversi
#        che potrebbero indicare account compromessi o session hijacking
#
# METODO: Usa netstat/ss per listare connessioni TCP attive in tempo reale,
#         analizza pattern di connessioni simultanee da multiple sorgenti
#
# DATABASE: Usato SOLO per lookup customer_id associato a IP specifico (opzionale)
# BLACKLIST: Verifica se IP già segnalato come sospetto
#
# DIPENDENZE: netstat o ss (iproute2), awk, grep

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
LOG_SIMULTANEI="/workspaces/SO/logs/simultanei_alerts.log"
STATE_FILE="/workspaces/SO/logs/simultanei_state.tmp"
DB_PATH="/workspaces/SO/data/bank_logs.db"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"
NOTIFY_LOG="/workspaces/SO/logs/notifiche_email.txt"

# Parametri di rilevamento
SERVER_PORT=8000                # Porta del server Flask da monitorare
SOGLIA_IP_SIMULTANEI=3          # Max IP diversi simultanei per stesso customer
INTERVALLO_CHECK=2              # Secondi tra ogni check
DURATA_MONITORAGGIO=60          # Durata totale monitoraggio (1 minuto)

# Crea directory log se non esistono
mkdir -p $(dirname "$LOG_SIMULTANEI")
mkdir -p $(dirname "$STATE_FILE")
mkdir -p $(dirname "$NOTIFY_LOG")

# Pulisci file di stato ad ogni avvio (per tracciare IP segnalati nel NUOVO ciclo)
> "$STATE_FILE"

# Array per tracciare IP già segnalati in questa sessione (evita duplicati)
declare -A SEGNALATI

# FUNZIONE: controlla_blacklist
# ARG1: tipo_elemento (IP, USER_ID, IBAN, etc)
# ARG2: elemento (valore da cercare)
# RETURN: 0 se trovato in blacklist, 1 se non trovato
# NOTE: grep -q esegue ricerca silenziosa, 2>/dev/null sopprime errori
controlla_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    grep -q "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH" 2>/dev/null
    return $?
}

# FUNZIONE: get_risk_score
# ARG1: tipo_elemento
# ARG2: elemento
# OUTPUT: Stampa risk_score dalla blacklist (0 se non trovato)
# NOTE: awk -F',' separa campi CSV, tail -1 prende ultima occorrenza
get_risk_score() {
    local tipo_elemento="$1"
    local elemento="$2"
    
    local score=$(awk -F',' -v tipo="$tipo_elemento" -v elem="$elemento" \
        '$3==tipo && $4==elem {print $7}' "$BLACKLIST_PATH" | tail -1)
    
    # -z: test if string has zero length (empty)
    if [ -z "$score" ]; then
        echo 0
    else
        echo "$score"
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
        echo "[$timestamp] TO:$email CUSTOMER:$customer_id NAME:$nome SUBJECT:Attiva 2FA BODY:Abbiamo rilevato accessi simultanei sul tuo conto. Attiva subito l'autenticazione a due fattori." >> "$NOTIFY_LOG"
    else
        # Se 2FA attiva: notifica movimenti sospetti
        echo "[$timestamp] TO:$email CUSTOMER:$customer_id NAME:$nome SUBJECT:Movimenti sospetti BODY:Abbiamo rilevato accessi simultanei sul tuo conto. Se non riconosci queste operazioni contatta il supporto." >> "$NOTIFY_LOG"
    fi
}

# FUNZIONE: aggiungi_blacklist
# ARG1-6: tipo_elemento, elemento, azione, gravita, risk_score, note
# COMPORTAMENTO: Aggiunge entry a blacklist, incrementa risk se recidivo
aggiungi_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    local azione="$3"
    local gravita="$4"
    local risk_score="$5"
    local note="$6"
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if controlla_blacklist "$tipo_elemento" "$elemento"; then
        # RECIDIVO: elemento già segnalato in passato
        local current_risk=$(get_risk_score "$tipo_elemento" "$elemento")
        local recidivita=$(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH")
        recidivita=$((recidivita + 1))
        local new_risk=$((current_risk + risk_score))
        
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,ACCESSI_SIMULTANEI,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        # NUOVO elemento
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,ACCESSI_SIMULTANEI,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: estrai_connessioni_attive
# OUTPUT: Lista di customer_id con accessi simultanei (dall'ultimo minuto)
# TECNICA: Legge realtime_access.log, groupa per customer_id, conta IP diversi
estrai_connessioni_attive() {
    # Legge le 50 linee più recenti dal file di log
    # Format: timestamp|customer_id|ip|azione|...
    # Estrae records di LOGIN
    # Grouppa per customer_id, conta IP diversi
    # Ritorna: customer_id|num_ips_diversi|ip_list
    
    if [ -f "/workspaces/SO/logs/realtime_access.log" ]; then
        tail -50 /workspaces/SO/logs/realtime_access.log | \
            grep "|LOGIN|" | \
            awk -F'|' '{print $2"|"$3}' | \
            awk -F'|' '
                {
                    customer=$1
                    ip=$2
                    if (customer != "" && ip != "" && ip != "127.0.0.1") {
                        key = customer SUBSEP ip
                        seen[key] = 1
                    }
                }
                END {
                    for (k in seen) {
                        split(k, a, SUBSEP)
                        customer = a[1]
                        ip = a[2]
                        
                        # Conta IP diversi per questo customer
                        if (!customer_ips[customer][ip]++) {
                            customer_count[customer]++
                            if (customer_list[customer] == "")
                                customer_list[customer] = ip
                            else
                                customer_list[customer] = customer_list[customer]","ip
                        }
                    }
                    
                    # Stampa customer_id|num_ips|ips (ips separati da virgola)
                    for (c in customer_count) {
                        print c"|"customer_count[c]"|"customer_list[c]
                    }
                }
            ' | sort -u
    fi
}

# ANALISI IN TEMPO REALE
# Messaggio minimo di avvio
log "P02 start"
# Log dettagliato su file
echo "================================================================================" >> "$LOG_SIMULTANEI"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO ACCESSI SIMULTANEI AVVIATO" >> "$LOG_SIMULTANEI"
echo "================================================================================" >> "$LOG_SIMULTANEI"

# Output verbose silenziato da exec 1>/dev/null
echo "[*] Server monitorato: porta $SERVER_PORT"
echo "[*] Soglia IP simultanei: $SOGLIA_IP_SIMULTANEI"
echo "[*] Intervallo check: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo "[*] Premi Ctrl+C per terminare anticipatamente"
echo ""

# Inizializza contatori
ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

# date +%s: timestamp Unix (secondi da epoch 1970)
START_TIME=$(date +%s)

# Loop di monitoraggio
# Continua fintanto che: non ha superato MAX iterazioni AND non ha generato alert
# -le: less than or equal (<=)
# Una volta trovata un'anomalia (ALERT_COUNT > 0), esce
while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    
    echo "[Check #$ITERAZIONI] $(date '+%H:%M:%S') - Elapsed: ${ELAPSED}s"
    
    # Estrai connessioni ed esegui analisi
    CONNESSIONI=$(estrai_connessioni_attive)
    
    # Conta quanti account hanno accessi simultanei >= soglia
    NUM_ACCOUNTS=$(echo "$CONNESSIONI" | awk -F'|' -v soglia="$SOGLIA_IP_SIMULTANEI" '$2 >= soglia {count++} END {print count+0}')
    
    echo "  → Account con accessi simultanei anomali: $NUM_ACCOUNTS"
    
    if [ "$NUM_ACCOUNTS" -gt 0 ]; then
        echo "$CONNESSIONI" | awk -F'|' -v soglia="$SOGLIA_IP_SIMULTANEI" '$2 >= soglia {print "    - "$1" da "$2" IP"}' || true
    fi
    
    # CONTROLLO SOGLIA
    if [ "$NUM_ACCOUNTS" -gt 0 ]; then
        # Messaggio minimo di alert
        log "P02 alert $NUM_ACCOUNTS"

        echo ""
        echo "  [!!!] ALERT: $NUM_ACCOUNTS account con accessi simultanei rilevati!"
        echo ""
        
        # Analizza ogni account con accessi simultanei
        # Format: customer_id|num_ips_diversi|ips (comma-separated)
        while IFS='|' read -r customer_id num_ips ips_list; do
            
            if [ -n "$customer_id" ] && [ "$num_ips" -ge "$SOGLIA_IP_SIMULTANEI" ]; then
                
                echo "  [!] ACCOUNT: $customer_id con $num_ips IP diversi"
                echo "      IPs: $ips_list"
                
                # Segnala solo se non già fatto in questa sessione
                if [ -z "${SEGNALATI[$customer_id]}" ]; then
                    SEGNALATI[$customer_id]=1
                    
                    # Verifica se ACCOUNT già in blacklist GLOBALE (da cicli precedenti)
                    if controlla_blacklist "ACCOUNT" "$customer_id"; then
                        echo "      → ACCOUNT già in blacklist (RECIDIVO)"
                        aggiungi_blacklist "ACCOUNT" "$customer_id" "ACCESSO_SIMULTANEO" \
                            "CRITICA" 60 "Connessioni simultanee da $num_ips IP; lista: ${ips_list//,/ }"
                    else
                        echo "      → Primo rilevamento"
                        aggiungi_blacklist "ACCOUNT" "$customer_id" "ACCESSO_SIMULTANEO" \
                            "ALTA" 40 "Connessioni simultanee da $num_ips IP; lista: ${ips_list//,/ }"
                    fi

                    # Notifica cliente (2FA o movimenti sospetti)
                    notifica_cliente "$customer_id"
                    
                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    
                    # Log dettagliato - SOLO per primo rilevamento
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT ACCESSI SIMULTANEI - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "Account:           $customer_id"
                        echo "IP diversi:        $num_ips"
                        echo "IPs:               $ips_list"
                        echo "Soglia:            $SOGLIA_IP_SIMULTANEI"
                        echo ""
                    } >> "$LOG_SIMULTANEI"
                else
                    echo "      → Già segnalato in questa sessione (SKIP)"
                fi
                
            fi
        done < <(estrai_connessioni_attive)
    fi
    
    echo ""
    
    # Incrementa iterazioni e attendi prossimo check
    ITERAZIONI=$((ITERAZIONI + 1))
    
    # -lt: less than (<)
    # Non dormire nell'ultima iterazione
    if [ $ITERAZIONI -lt $MAX_ITERAZIONI ]; then
        sleep $INTERVALLO_CHECK
    fi
done

# Report finale (verbose, silenziato)
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_SIMULTANEI"
echo "================================================================================"

# Messaggio minimo di fine
log "P02 done"
