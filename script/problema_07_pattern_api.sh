#!/bin/bash

# PROBLEMA 7: ANALISI PATTERN API - HTTP REQUEST MONITORING
#
# SCOPO: Identificare pattern anomali nelle richieste API (sequenze sospette,
#        timing irregolari, user-agent strani)
#
# METODO: Usa curl/wget per testare endpoint API e tshark per catturare headers,
#         analizza user-agent, timing, sequenze di richieste
#
# DATABASE: Usato SOLO per lookup puntuale customer_id
# BLACKLIST: Registra IP con pattern di richieste anomali
#
# DIPENDENZE: tshark, curl, awk

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_PATTERN="/workspaces/SO/logs/pattern_api_alerts.log"
STATE_FILE="/workspaces/SO/logs/pattern_state.tmp"
DB_PATH="/workspaces/SO/data/bank_logs.db"

# Parametri
SERVER_PORT=8000
SERVER_URL="http://localhost:$SERVER_PORT"
SOGLIA_RICHIESTE_RAPIDE=15   # Max richieste in finestra
FINESTRA_SECONDI=30
DURATA_CATTURA=120

mkdir -p $(dirname "$LOG_PATTERN")

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
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,PATTERN_API,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,PATTERN_API,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: verifica_endpoint_disponibile
# Testa se API endpoint risponde
verifica_endpoint_disponibile() {
    # curl:
    # -s: silent mode (no progress bar)
    # -o /dev/null: scarta output body
    # -w "%{http_code}": write-out solo HTTP status code
    # -m 5: max-time 5 secondi timeout
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$SERVER_URL/login?customer_id=test&porta=5000" 2>/dev/null)
    
    # 200-299: success codes
    # ${var:0:1}: substring, primo carattere
    if [ "${http_code:0:1}" == "2" ] || [ "${http_code:0:1}" == "3" ]; then
        return 0  # Disponibile
    else
        return 1  # Non disponibile
    fi
}

# FUNZIONE: identifica_user_agent_sospetto
# Verifica se user-agent è sospetto (bot, scanner, tool automatici)
# ARG1: user-agent string
identifica_user_agent_sospetto() {
    local ua="$1"
    
    # User-agent sospetti comuni
    # grep -i: case-insensitive
    # -E: extended regex (alternation con |)
    echo "$ua" | grep -iE "curl|wget|python|scanner|nikto|sqlmap|nmap|masscan|bot|crawler" > /dev/null
    
    # $?: exit code del grep (0=match, 1=no match)
    if [ $? -eq 0 ]; then
        return 0  # Sospetto
    else
        return 1  # Normale
    fi
}

echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO PATTERN API AVVIATO"
echo "================================================================================" | tee -a "$LOG_PATTERN"

# Test connettività API
echo "[*] Test endpoint API..."
if verifica_endpoint_disponibile; then
    echo "  ✓ Server API raggiungibile su $SERVER_URL"
else
    echo "  ✗ Server API NON raggiungibile"
    echo "  [!] Avvia il server prima di eseguire questo script"
    exit 1
fi

echo ""
echo "[*] Porta: $SERVER_PORT"
echo "[*] Soglia: $SOGLIA_RICHIESTE_RAPIDE richieste in $FINESTRA_SECONDI secondi"
echo "[*] Durata: $DURATA_CATTURA secondi"
echo "[*] Premi Ctrl+C per terminare"
echo ""

# Verifica tshark
if ! command -v tshark &> /dev/null; then
    echo "[!] ERRORE: tshark non installato"
    exit 1
fi

# Inizializza state file
echo "# Pattern API state - $(date)" > "$STATE_FILE"

COUNTER=0
ALERT_COUNT=0

# CATTURA RICHIESTE HTTP
# tshark:
# -i any: tutte le interfacce
# -f "tcp port 8000": filtra TCP porta 8000
# -Y "http.request": solo richieste HTTP (non risposte)
# -T fields: output formattato
# -e frame.time_epoch: timestamp Unix
# -e ip.src: IP sorgente
# -e http.request.method: metodo HTTP (GET, POST, etc)
# -e http.request.uri: URI richiesta
# -e http.user_agent: User-Agent header
# -l: line-buffered output
timeout $DURATA_CATTURA tshark -i any -f "tcp port $SERVER_PORT" \
    -Y "http.request" \
    -T fields -e frame.time_epoch -e ip.src -e http.request.method -e http.request.uri -e http.user_agent \
    -l 2>/dev/null | \
while IFS=$'\t' read -r timestamp ip_src method uri user_agent; do
    
    COUNTER=$((COUNTER + 1))
    
    echo "[+] Richiesta #$COUNTER: $method $uri"
    echo "    IP: $ip_src | UA: ${user_agent:0:50}..."
    
    # Salva in state file
    echo "$(date +%s)|$ip_src|$method|$uri|$user_agent" >> "$STATE_FILE"
    
    # ANALISI USER-AGENT
    if identifica_user_agent_sospetto "$user_agent"; then
        echo ""
        echo "  [!!!] USER-AGENT SOSPETTO rilevato!"
        echo "  [!!!] $user_agent"
        
        # Conta richieste da questo IP
        CURRENT_TIME=$(date +%s)
        WINDOW_START=$((CURRENT_TIME - FINESTRA_SECONDI))
        
        RICHIESTE_IP=$(awk -F'|' -v window="$WINDOW_START" -v ip="$ip_src" \
            '$1>=window && $2==ip {count++} END{print count+0}' "$STATE_FILE")
        
        echo "  [*] Richieste da $ip_src ultimi ${FINESTRA_SECONDI}s: $RICHIESTE_IP"
        
        # Lookup customer
        CUSTOMER_QUERY="SELECT customer_id FROM logs 
                        WHERE ip_address='$ip_src' 
                        ORDER BY timestamp DESC LIMIT 1"
        customer_id=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null)
        
        if [ -z "$customer_id" ]; then
            customer_id="UNKNOWN"
        fi
        
        # Blacklist
        if controlla_blacklist "IP" "$ip_src"; then
            echo "  [!] GIÀ IN BLACKLIST (RECIDIVO)"
            aggiungi_blacklist "IP" "$ip_src" "USER_AGENT_SOSPETTO" \
                "ALTA" 70 "UA: $user_agent, $RICHIESTE_IP richieste, customer: $customer_id"
        else
            echo "  [!] PRIMO RILEVAMENTO"
            aggiungi_blacklist "IP" "$ip_src" "USER_AGENT_SOSPETTO" \
                "MEDIA" 50 "UA: $user_agent, $RICHIESTE_IP richieste, customer: $customer_id"
        fi
        
        ALERT_COUNT=$((ALERT_COUNT + 1))
        
        # Log
        {
            echo "═══════════════════════════════════════════"
            echo "ALERT PATTERN API - $(date '+%Y-%m-%d %H:%M:%S')"
            echo "═══════════════════════════════════════════"
            echo "IP:              $ip_src"
            echo "User-Agent:      $user_agent"
            echo "Metodo:          $method"
            echo "URI:             $uri"
            echo "Richieste/30s:   $RICHIESTE_IP"
            echo "Customer:        $customer_id"
            echo ""
        } >> "$LOG_PATTERN"
        
        echo ""
    fi
    
    # ANALISI FREQUENZA RICHIESTE (indipendente da UA)
    CURRENT_TIME=$(date +%s)
    WINDOW_START=$((CURRENT_TIME - FINESTRA_SECONDI))
    
    RICHIESTE_TOTALI=$(awk -F'|' -v window="$WINDOW_START" -v ip="$ip_src" \
        '$1>=window && $2==ip {count++} END{print count+0}' "$STATE_FILE")
    
    # -ge: greater or equal
    if [ $RICHIESTE_TOTALI -ge $SOGLIA_RICHIESTE_RAPIDE ]; then
        echo ""
        echo "  [!!!] PATTERN RAPIDO: $RICHIESTE_TOTALI richieste da $ip_src in ${FINESTRA_SECONDI}s"
        
        # Blacklist (se non già fatto per UA)
        if ! identifica_user_agent_sospetto "$user_agent"; then
            
            CUSTOMER_QUERY="SELECT customer_id FROM logs 
                            WHERE ip_address='$ip_src' 
                            ORDER BY timestamp DESC LIMIT 1"
            customer_id=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null)
            
            if [ -z "$customer_id" ]; then
                customer_id="UNKNOWN"
            fi
            
            if controlla_blacklist "IP" "$ip_src"; then
                aggiungi_blacklist "IP" "$ip_src" "RICHIESTE_RAPIDE" \
                    "ALTA" 60 "$RICHIESTE_TOTALI richieste in ${FINESTRA_SECONDI}s, customer: $customer_id"
            else
                aggiungi_blacklist "IP" "$ip_src" "RICHIESTE_RAPIDE" \
                    "MEDIA" 40 "$RICHIESTE_TOTALI richieste in ${FINESTRA_SECONDI}s, customer: $customer_id"
            fi
            
            ALERT_COUNT=$((ALERT_COUNT + 1))
        fi
        
        echo ""
    fi
    
done

echo ""
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Richieste catturate: $COUNTER"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_PATTERN"
echo "================================================================================"
