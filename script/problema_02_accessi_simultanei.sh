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

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_SIMULTANEI="/workspaces/SO/logs/simultanei_alerts.log"
STATE_FILE="/workspaces/SO/logs/simultanei_state.tmp"
DB_PATH="/workspaces/SO/data/eventi_bancari.db"

# Parametri di rilevamento
SERVER_PORT=8000                # Porta del server Flask da monitorare
SOGLIA_IP_SIMULTANEI=3          # Max IP diversi simultanei per stesso customer
INTERVALLO_CHECK=5              # Secondi tra ogni check
DURATA_MONITORAGGIO=300         # Durata totale monitoraggio (5 minuti)

mkdir -p $(dirname "$LOG_SIMULTANEI")
mkdir -p $(dirname "$STATE_FILE")

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
# OUTPUT: Lista connessioni TCP ESTABLISHED verso server porta 8000
# FORMAT: ip_remoto:porta_remota
# TECNICA: ss -tn mostra socket TCP (-t) in formato numerico (-n, no DNS lookup)
#          state established: solo connessioni stabilite (non LISTEN, SYN_SENT, etc)
#          sport = :8000: filtra per source port 8000 (connessioni al nostro server)
#          awk estrae campo IP:porta remoto
estrai_connessioni_attive() {
    # ss: socket statistics (moderno sostituto di netstat)
    # -t: TCP sockets
    # -n: numeric addresses (no DNS resolution per performance)
    # state established: filtra solo connessioni completamente stabilite
    # sport = :8000: source port (porta del nostro server)
    
    ss -tn state established sport = :$SERVER_PORT 2>/dev/null | \
        awk 'NR>1 {print $5}' | \
        cut -d':' -f1 | \
        sort -u
    # NR>1: skip header line (NR = number of record)
    # $5: campo 5 contiene IP:porta remoto
    # cut -d':' -f1: estrae solo IP (field 1, delimitato da :)
    # sort -u: ordina e rimuove duplicati
}

# ANALISI IN TEMPO REALE
echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO ACCESSI SIMULTANEI AVVIATO"
echo "================================================================================" | tee -a "$LOG_SIMULTANEI"

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
# -le: less than or equal (<=)
while [ $ITERAZIONI -le $MAX_ITERAZIONI ]; do
    
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    
    echo "[Check #$ITERAZIONI] $(date '+%H:%M:%S') - Elapsed: ${ELAPSED}s"
    
    # Estrai connessioni TCP attive al server
    IPS_CONNESSI=$(estrai_connessioni_attive)
    
    # wc -l: word count lines (conta numero di righe)
    NUM_IPS=$(echo "$IPS_CONNESSI" | grep -c '^')  # conta righe non vuote
    
    echo "  → IP connessi simultaneamente: $NUM_IPS"
    
    # -gt: greater than (>)
    if [ $NUM_IPS -gt 0 ]; then
        echo "$IPS_CONNESSI" | while read -r ip; do
            # -n: test if string is NOT empty
            [ -n "$ip" ] && echo "    - $ip"
        done
    fi
    
    # CONTROLLO SOGLIA
    if [ $NUM_IPS -ge $SOGLIA_IP_SIMULTANEI ]; then
        echo ""
        echo "  [!!!] ALERT: $NUM_IPS connessioni simultanee rilevate!"
        echo ""
        
        ALERT_COUNT=$((ALERT_COUNT + 1))
        
        # Analizza ogni IP connesso
        echo "$IPS_CONNESSI" | while read -r suspicious_ip; do
            
            # -n: verifica stringa non vuota
            if [ -n "$suspicious_ip" ]; then
                
                # Cerca nel database se questo IP ha fatto login recentemente
                # NOTA: Query SQL PUNTUALE solo per lookup specifico, non analisi massiva
                # LIMIT 1: restituisce solo il primo match (performance)
                CUSTOMER_QUERY="SELECT customer_id FROM eventi 
                                WHERE ip_address='$suspicious_ip' 
                                AND azione='LOGIN' 
                                ORDER BY timestamp DESC LIMIT 1"
                
                customer_id=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null)
                
                # -z: verifica se stringa vuota
                if [ -z "$customer_id" ]; then
                    customer_id="UNKNOWN"
                fi
                
                echo "  [!] IP: $suspicious_ip → Customer: $customer_id"
                
                # Verifica se IP già in blacklist
                if controlla_blacklist "IP" "$suspicious_ip"; then
                    echo "      → IP già in blacklist (RECIDIVO)"
                    aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_SIMULTANEO" \
                        "CRITICA" 60 "Connessione simultanea rilevata, customer_id: $customer_id"
                else
                    echo "      → Primo rilevamento"
                    aggiungi_blacklist "IP" "$suspicious_ip" "ACCESSO_SIMULTANEO" \
                        "ALTA" 40 "Connessione simultanea rilevata, customer_id: $customer_id"
                fi
                
                # Log dettagliato
                {
                    echo "═══════════════════════════════════════════"
                    echo "ALERT SIMULTANEO - $(date '+%Y-%m-%d %H:%M:%S')"
                    echo "═══════════════════════════════════════════"
                    echo "IP sospetto:       $suspicious_ip"
                    echo "Customer ID:       $customer_id"
                    echo "IP simultanei:     $NUM_IPS"
                    echo "Soglia:            $SOGLIA_IP_SIMULTANEI"
                    echo ""
                } >> "$LOG_SIMULTANEI"
                
            fi
        done
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

# Report finale
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Durata: $ELAPSED secondi"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_SIMULTANEI"
echo "================================================================================"
