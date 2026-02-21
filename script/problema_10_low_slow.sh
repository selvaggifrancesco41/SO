#!/bin/bash

# PROBLEMA 10: RILEVAMENTO ATTACCHI LOW & SLOW - RATE LIMITING
#
# SCOPO: Identificare attacchi distribuiti lenti (DDoS low-bandwidth, slowloris)
#        che inviano richieste a rate costante basso per evitare detection
#
# METODO: Usa ss per monitorare connessioni persistenti, wget/curl per timing,
#         analizza durata connessioni e pattern temporali
#
# DATABASE: Usato SOLO per lookup puntuale
# BLACKLIST: Registra IP con connessioni anomalmente lunghe
#
# DIPENDENZE: ss, awk, date

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_LOWSLOW="/workspaces/SO/logs/low_slow_alerts.log"
STATE_FILE="/workspaces/SO/logs/lowslow_state.tmp"
DB_PATH="/workspaces/SO/data/eventi_bancari.db"

# Parametri
SERVER_PORT=8000
SOGLIA_CONNESSIONE_LUNGA=60    # Connessioni > 60 secondi sono sospette
SOGLIA_RICHIESTE_MINIME=2      # Min 2 richieste in finestra (troppo lente)
FINESTRA_SECONDI=120
INTERVALLO_CHECK=15
DURATA_MONITORAGGIO=180

mkdir -p $(dirname "$LOG_LOWSLOW")

controlla_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    grep -q "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH" 2>/dev/null
    return $?
}

get_risk_score() {
    local tipo_elemento="$1"
    local elemento="$2"
    local score=$(awk -F',' -v tipo="$tipo_elemento" -v elem="$elemento" \
        '$3==tipo && $4==elem {print $7}' "$BLACKLIST_PATH" | tail -1)
    if [ -z "$score" ]; then
        echo 0
    else
        echo "$score"
    fi
}

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
        local recidivita=$(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH")
        recidivita=$((recidivita + 1))
        local new_risk=$((current_risk + risk_score))
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,LOW_SLOW,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,LOW_SLOW,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: ottieni_tempo_connessione
# Estrae durata connessione da ss timer (se disponibile)
# ARG1: riga output ss con timer info
# RETURN: secondi (o 0 se non disponibile)
ottieni_tempo_connessione() {
    local ss_line="$1"
    
    # ss output può contenere timer info con formato:
    # timer:(keepalive,XXXms,0)
    # Estrae XXX millisecondi e converte in secondi
    
    local ms=$(echo "$ss_line" | grep -oP 'timer:\([^,]+,\K\d+' 2>/dev/null)
    
    if [ -n "$ms" ]; then
        # Converti ms in secondi
        # expr: expression evaluator (calcolo aritmetico)
        local sec=$(expr "$ms" / 1000 2>/dev/null || echo 0)
        echo "$sec"
    else
        echo 0
    fi
}

echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] RILEVAMENTO LOW & SLOW AVVIATO"
echo "================================================================================" | tee -a "$LOG_LOWSLOW"

echo "[*] Porta: $SERVER_PORT"
echo "[*] Soglia connessione lunga: >$SOGLIA_CONNESSIONE_LUNGA secondi"
echo "[*] Rate minimo: <$SOGLIA_RICHIESTE_MINIME richieste/${FINESTRA_SECONDI}s"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

# Inizializza state file per tracciare connessioni
echo "# Low&Slow state - $(date)" > "$STATE_FILE"
# Format: timestamp_first_seen|ip|durata_stimata|num_richieste

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ]; do
    
    TIMESTAMP_CURRENT=$(date +%s)
    echo "[Check #$ITERAZIONI] $(date '+%H:%M:%S')"
    
    # ss con opzioni estese per vedere timer
    # ss:
    # -t: TCP
    # -n: numeric
    # -o: show timer information
    # state established: solo connessioni stabilite
    # sport = :8000: source port (server)
    
    CONNESSIONI=$(ss -tno state established sport = :$SERVER_PORT 2>/dev/null)
    
    NUM_CONN=$(echo "$CONNESSIONI" | grep -c "^tcp" 2>/dev/null || echo 0)
    
    echo "  → Connessioni attive: $NUM_CONN"
    
    if [ $NUM_CONN -gt 0 ]; then
        
        # Analizza ogni connessione
        echo "$CONNESSIONI" | grep "^tcp" | while read -r conn_line; do
            
            # Estrai IP remoto
            # awk: campo con IP:porta remota
            IP_REMOTO=$(echo "$conn_line" | awk '{print $5}' | cut -d':' -f1)
            
            if [ -n "$IP_REMOTO" ]; then
                
                # Verifica se IP già tracciato in state file
                # grep -q: quiet search
                if grep -q "^.*|$IP_REMOTO|" "$STATE_FILE" 2>/dev/null; then
                    # IP già visto, recupera timestamp prima vista
                    FIRST_SEEN=$(grep "^.*|$IP_REMOTO|" "$STATE_FILE" | cut -d'|' -f1 | tail -1)
                    
                    # Calcola durata connessione
                    # $(( )): arithmetic expansion
                    DURATA=$((TIMESTAMP_CURRENT - FIRST_SEEN))
                    
                    # Aggiorna num richieste (simplified: incrementa)
                    NUM_REQ=$(grep "^.*|$IP_REMOTO|" "$STATE_FILE" | cut -d'|' -f4 | tail -1)
                    NUM_REQ=$((NUM_REQ + 1))
                    
                    # Aggiorna entry in state file
                    # sed -i: in-place edit
                    # Rimuovi vecchia entry e aggiungi nuova
                    sed -i "/^.*|$IP_REMOTO|/d" "$STATE_FILE" 2>/dev/null
                    echo "$FIRST_SEEN|$IP_REMOTO|$DURATA|$NUM_REQ" >> "$STATE_FILE"
                    
                else
                    # Nuova connessione, aggiungi a state
                    echo "$TIMESTAMP_CURRENT|$IP_REMOTO|0|1" >> "$STATE_FILE"
                    DURATA=0
                    NUM_REQ=1
                fi
                
                # VERIFICA PATTERN LOW & SLOW
                # Pattern: connessione lunga + poche richieste
                
                # -gt: greater than
                # -lt: less than
                if [ $DURATA -gt $SOGLIA_CONNESSIONE_LUNGA ]; then
                    
                    # Calcola rate: richieste/secondo
                    # awk per calcolo decimale (bash non supporta float nativamente)
                    RATE=$(awk "BEGIN {print $NUM_REQ / $DURATA}")
                    
                    echo ""
                    echo "  [+] Connessione LUNGA: $IP_REMOTO"
                    echo "      Durata: ${DURATA}s | Richieste: $NUM_REQ | Rate: $RATE req/s"
                    
                    # Se rate molto basso, è sospetto (low & slow)
                    # awk per confronto float
                    IS_LOW=$(awk "BEGIN {print ($RATE < 0.5) ? 1 : 0}")
                    
                    # -eq 1: equal to 1 (true)
                    if [ "$IS_LOW" -eq 1 ]; then
                        echo ""
                        echo "  [!!!] PATTERN LOW & SLOW RILEVATO!"
                        echo "  [!!!] Rate troppo basso: $RATE req/s"
                        
                        # Lookup customer
                        CUSTOMER_QUERY="SELECT customer_id FROM eventi 
                                        WHERE ip_address='$IP_REMOTO' 
                                        ORDER BY timestamp DESC LIMIT 1"
                        customer_id=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null)
                        
                        if [ -z "$customer_id" ]; then
                            customer_id="UNKNOWN"
                        fi
                        
                        # Blacklist
                        if controlla_blacklist "IP" "$IP_REMOTO"; then
                            echo "  [!] GIÀ IN BLACKLIST (RECIDIVO)"
                            aggiungi_blacklist "IP" "$IP_REMOTO" "LOW_SLOW_ATTACK" \
                                "CRITICA" 90 "Conn. lunga: ${DURATA}s, solo $NUM_REQ richieste, rate: $RATE req/s, customer: $customer_id"
                        else
                            echo "  [!] PRIMO RILEVAMENTO"
                            aggiungi_blacklist "IP" "$IP_REMOTO" "LOW_SLOW_ATTACK" \
                                "ALTA" 70 "Conn. lunga: ${DURATA}s, solo $NUM_REQ richieste, rate: $RATE req/s, customer: $customer_id"
                        fi
                        
                        ALERT_COUNT=$((ALERT_COUNT + 1))
                        
                        # Log
                        {
                            echo "═══════════════════════════════════════════"
                            echo "ALERT LOW & SLOW - $(date '+%Y-%m-%d %H:%M:%S')"
                            echo "═══════════════════════════════════════════"
                            echo "IP:              $IP_REMOTO"
                            echo "Durata conn:     ${DURATA}s"
                            echo "Richieste:       $NUM_REQ"
                            echo "Rate:            $RATE req/s"
                            echo "Customer:        $customer_id"
                            echo ""
                        } >> "$LOG_LOWSLOW"
                        
                        echo ""
                    fi
                fi
                
            fi
        done
    fi
    
    echo ""
    ITERAZIONI=$((ITERAZIONI + 1))
    
    if [ $ITERAZIONI -lt $MAX_ITERAZIONI ]; then
        sleep $INTERVALLO_CHECK
    fi
done

echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_LOWSLOW"
echo "[*] State file: $STATE_FILE"
echo "================================================================================"
