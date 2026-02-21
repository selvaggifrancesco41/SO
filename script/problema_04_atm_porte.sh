#!/bin/bash

# PROBLEMA 4: RILEVAMENTO PORTE NON AUTORIZZATE DA ATM - NETWORK SCAN
#
# SCOPO: Identificare ATM che si connettono al server usando porte sorgente
#        non autorizzate, possibile indicatore di malware o tunneling
#
# METODO: Usa ss/netstat per monitorare porte sorgente delle connessioni,
#         verifica con nmap-like approach (nc) se porte anomale sono aperte
#
# DATABASE: Usato SOLO per identificare ATM_ID associato a IP (opzionale)
# BLACKLIST: Registra IP ATM con porte sospette
#
# DIPENDENZE: ss, netstat, awk, nc (netcat)

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_ATM="/workspaces/SO/logs/atm_porte_alerts.log"
DB_PATH="/workspaces/SO/data/eventi_bancari.db"

# Parametri
SERVER_PORT=8000
# Porte autorizzate per ATM (ephemeral ports normalmente 32768-60999)
PORTA_MIN_AUTORIZZATA=32768
PORTA_MAX_AUTORIZZATA=60999
INTERVALLO_CHECK=8
DURATA_MONITORAGGIO=120

mkdir -p $(dirname "$LOG_ATM")

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
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,ATM_PORTE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,ATM_PORTE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: verifica_porta_aperta
# Usa netcat per verificare se una porta è aperta su host remoto
# ARG1: IP host
# ARG2: porta da testare
# RETURN: 0 se aperta, 1 se chiusa
verifica_porta_aperta() {
    local host="$1"
    local porta="$2"
    
    # nc: netcat
    # -z: zero-I/O mode (solo scan, non invia dati)
    # -w 2: timeout 2 secondi
    # -v: verbose (opzionale, ma qui soppresso con 2>/dev/null)
    nc -z -w 2 "$host" "$porta" 2>/dev/null
    return $?
}

# FUNZIONE: identifica_servizio_porta
# Tenta di identificare quale servizio gira su una porta
identifica_servizio_porta() {
    local porta="$1"
    
    # Porte comuni note (simplified port identification)
    case $porta in
        22) echo "SSH" ;;
        23) echo "TELNET" ;;
        80) echo "HTTP" ;;
        443) echo "HTTPS" ;;
        3306) echo "MySQL" ;;
        5432) echo "PostgreSQL" ;;
        6379) echo "Redis" ;;
        8080) echo "HTTP-Alt" ;;
        9050) echo "TOR-SOCKS" ;;
        1080) echo "SOCKS-Proxy" ;;
        3128) echo "Squid-Proxy" ;;
        *) echo "UNKNOWN" ;;
    esac
}

echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITORAGGIO PORTE ATM AVVIATO"
echo "================================================================================" | tee -a "$LOG_ATM"

echo "[*] Porta server: $SERVER_PORT"
echo "[*] Range porte autorizzate ATM: $PORTA_MIN_AUTORIZZATA-$PORTA_MAX_AUTORIZZATA"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ]; do
    
    echo "[Check #$ITERAZIONI] $(date '+%H:%M:%S')"
    
    # netstat: network statistics (alternativa a ss)
    # -t: TCP connections
    # -n: numeric (no hostname resolution)
    # grep :8000: filtra solo connessioni al server porta 8000
    # awk: estrae IP remoto e porta remota
    # Format output netstat: IP_locale:porta_locale IP_remoto:porta_remota
    
    CONNESSIONI=$(netstat -tn 2>/dev/null | grep ":$SERVER_PORT " | awk '{print $5}')
    
    # Conta connessioni
    NUM_CONN=$(echo "$CONNESSIONI" | grep -c '^' 2>/dev/null || echo 0)
    
    if [ $NUM_CONN -gt 0 ]; then
        echo "  → Connessioni rilevate: $NUM_CONN"
        
        # Analizza ogni connessione
        echo "$CONNESSIONI" | while read -r conn_full; do
            
            if [ -n "$conn_full" ]; then
                # Estrai IP e porta
                # cut -d':' -f1: primo campo delimitato da :  (IP)
                # cut -d':' -f2: secondo campo (porta)
                IP_REMOTO=$(echo "$conn_full" | cut -d':' -f1)
                PORTA_REMOTA=$(echo "$conn_full" | cut -d':' -f2)
                
                echo "    • $IP_REMOTO:$PORTA_REMOTA"
                
                # VERIFICA SE PORTA È FUORI RANGE AUTORIZZATO
                # -lt: less than (<)
                # -gt: greater than (>)
                if [ "$PORTA_REMOTA" -lt "$PORTA_MIN_AUTORIZZATA" ] || \
                   [ "$PORTA_REMOTA" -gt "$PORTA_MAX_AUTORIZZATA" ]; then
                    
                    echo ""
                    echo "  [!!!] PORTA SOSPETTA: $IP_REMOTO usa porta $PORTA_REMOTA"
                    echo "  [!!!] Fuori range autorizzato ($PORTA_MIN_AUTORIZZATA-$PORTA_MAX_AUTORIZZATA)"
                    
                    # Identifica servizio
                    SERVIZIO=$(identifica_servizio_porta "$PORTA_REMOTA")
                    echo "      → Possibile servizio: $SERVIZIO"
                    
                    # Tenta scan reverse: verifica se IP ha altre porte anomale aperte
                    echo "      → Scan reverse di porte comuni..."
                    PORTE_APERTE=""
                    # Scansiona alcune porte sospette comuni
                    for test_port in 22 23 1080 3128 9050; do
                        if verifica_porta_aperta "$IP_REMOTO" "$test_port"; then
                            PORTE_APERTE="$PORTE_APERTE $test_port"
                        fi
                    done
                    
                    # -n: controlla se stringa NON vuota
                    if [ -n "$PORTE_APERTE" ]; then
                        echo "      → Porte aperte trovate:$PORTE_APERTE"
                    else
                        echo "      → Nessuna porta sospetta comune aperta"
                    fi
                    
                    # Lookup ATM_ID/customer_id dal database
                    ATM_QUERY="SELECT customer_id FROM eventi 
                               WHERE ip_address='$IP_REMOTO' 
                               AND porta=$PORTA_REMOTA
                               ORDER BY timestamp DESC LIMIT 1"
                    atm_id=$(sqlite3 "$DB_PATH" "$ATM_QUERY" 2>/dev/null)
                    
                    if [ -z "$atm_id" ]; then
                        atm_id="UNKNOWN"
                    fi
                    echo "      → ATM/Customer ID: $atm_id"
                    
                    # Aggiungi a blacklist
                    if controlla_blacklist "IP" "$IP_REMOTO"; then
                        echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                        aggiungi_blacklist "IP" "$IP_REMOTO" "PORTA_NON_AUTORIZZATA" \
                            "CRITICA" 80 "Usa porta $PORTA_REMOTA (servizio: $SERVIZIO), porte aperte:$PORTE_APERTE, ATM: $atm_id"
                    else
                        echo "      → PRIMO RILEVAMENTO"
                        aggiungi_blacklist "IP" "$IP_REMOTO" "PORTA_NON_AUTORIZZATA" \
                            "ALTA" 60 "Usa porta $PORTA_REMOTA (servizio: $SERVIZIO), porte aperte:$PORTE_APERTE, ATM: $atm_id"
                    fi
                    
                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    
                    # Log
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT ATM PORTA - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "IP ATM:           $IP_REMOTO"
                        echo "Porta sorgente:   $PORTA_REMOTA"
                        echo "Servizio:         $SERVIZIO"
                        echo "Porte aperte:    $PORTE_APERTE"
                        echo "ATM ID:           $atm_id"
                        echo "Range valido:     $PORTA_MIN_AUTORIZZATA-$PORTA_MAX_AUTORIZZATA"
                        echo ""
                    } >> "$LOG_ATM"
                    
                    echo ""
                fi
            fi
        done
    else
        echo "  → Nessuna connessione attiva"
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
echo "[*] Log: $LOG_ATM"
echo "================================================================================"
