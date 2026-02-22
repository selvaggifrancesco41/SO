#!/bin/bash

# PROBLEMA 9: INCOERENZA RETE - GEOLOCATION & PATH ANALYSIS
#
# SCOPO: Identificare connessioni da location geografiche incoerenti o path
#        di rete sospetti (troppe hop, routing anomalo)
#
# METODO: Usa traceroute/mtr per analizzare path di rete, dig/host per DNS reverse,
#         verifica RTT e numero hop
#
# DATABASE: Usato SOLO per lookup puntuale customer_id
# BLACKLIST: Registra IP con path di rete anomali
#
# DIPENDENZE: traceroute o mtr, dig, host, ss

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_INCOERENZA="/workspaces/SO/logs/incoerenza_rete_alerts.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"

# Parametri
SERVER_PORT=8000
SOGLIA_HOP_MAX=15        # Max hop accettabili (tipico: 8-12 per rete normale)
SOGLIA_RTT_MAX=200       # Max RTT in ms (200ms = sospetto se "locale")
INTERVALLO_CHECK=20
DURATA_MONITORAGGIO=120

mkdir -p $(dirname "$LOG_INCOERENZA")

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
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,INCOERENZA_RETE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,INCOERENZA_RETE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: traceroute_analisi
# Esegue traceroute e conta numero di hop
# ARG1: IP destinazione
# RETURN: stampa numero hop (o 0 se fallisce)
traceroute_analisi() {
    local target_ip="$1"
    
    # traceroute:
    # -m 20: max-hops 20 (ferma dopo 20 hop)
    # -w 2: wait 2 secondi per risposta
    # -q 1: query 1 pacchetto per hop (più veloce)
    # grep -c "^ ": conta righe che iniziano con spazio (hop validi)
    
    local num_hop=$(traceroute -m 20 -w 2 -q 1 "$target_ip" 2>/dev/null | grep -c "^ " || echo 0)
    
    echo "$num_hop"
}

# FUNZIONE: ottieni_asn_info
# Tenta di ottenere ASN (Autonomous System Number) dall'IP
# Utile per identificare ISP/organizzazione
# ARG1: IP
ottieni_asn_info() {
    local ip="$1"
    
    # Reverse IP per query whois-like
    # dig può interrogare servizi come cymru.com per ASN
    # Esempio query: dig +short <reversed-ip>.origin.asn.cymru.com TXT
    
    # Per semplicità, usiamo solo reverse DNS
    # dig:
    # -x: reverse lookup (PTR record)
    # +short: output solo risposta
    local ptr=$(dig -x "$ip" +short 2>/dev/null | head -1)
    
    if [ -z "$ptr" ]; then
        echo "UNKNOWN"
    else
        echo "$ptr"
    fi
}

# FUNZIONE: analizza_hostname_geolocation
# Estrae info geografiche da hostname (es. "fra" = Frankfurt)
# ARG1: hostname
analizza_hostname_geolocation() {
    local hostname="$1"
    
    # Cerca pattern geografici comuni in hostname
    # fra/frank = Frankfurt, ams = Amsterdam, lon = London, etc
    
    # grep -oiE: output only, case-insensitive, extended regex
    local geo=$(echo "$hostname" | grep -oiE "fra|frank|ams|lon|nyc|sfo|lax|par|mil|rom" | head -1)
    
    if [ -n "$geo" ]; then
        echo "$geo (identificato da hostname)"
    else
        echo "UNKNOWN"
    fi
}

echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ANALISI INCOERENZA RETE AVVIATA"
echo "================================================================================" | tee -a "$LOG_INCOERENZA"

echo "[*] Porta: $SERVER_PORT"
echo "[*] Soglie: max $SOGLIA_HOP_MAX hop, max $SOGLIA_RTT_MAX ms RTT"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

# Verifica traceroute disponibile
if ! command -v traceroute &> /dev/null; then
    echo "[!] WARNING: traceroute non installato, alcune analisi saranno skippate"
    echo "[*] Installa con: sudo apt-get install traceroute"
fi

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ]; do
    
    echo "[Check #$ITERAZIONI] $(date '+%H:%M:%S')"
    
    # Estrai IP connessi
    IPS_CONNESSI=$(ss -tn state established sport = :$SERVER_PORT 2>/dev/null | \
        awk 'NR>1 {print $5}' | cut -d':' -f1 | sort -u)
    
    NUM_IPS=$(echo "$IPS_CONNESSI" | grep -c '^' 2>/dev/null || echo 0)
    
    if [ $NUM_IPS -gt 0 ]; then
        echo "  → IP da analizzare: $NUM_IPS"
        
        echo "$IPS_CONNESSI" | while read -r ip; do
            
            if [ -n "$ip" ]; then
                echo ""
                echo "  ┌─ Analisi: $ip"
                
                # PTR / ASN info
                PTR_INFO=$(ottieni_asn_info "$ip")
                echo "  │  PTR: $PTR_INFO"
                
                # Geolocation da hostname
                GEO=$(analizza_hostname_geolocation "$PTR_INFO")
                echo "  │  Geo: $GEO"
                
                # Traceroute (se disponibile)
                if command -v traceroute &> /dev/null; then
                    echo "  │  Traceroute in corso..."
                    
                    NUM_HOP=$(traceroute_analisi "$ip")
                    echo "  │  Hop: $NUM_HOP"
                    
                    # Verifica se hop eccessivi
                    # -gt: greater than
                    if [ "$NUM_HOP" -gt "$SOGLIA_HOP_MAX" ]; then
                        echo "  │"
                        echo "  └─ [!!!] TROPPI HOP: $NUM_HOP (soglia: $SOGLIA_HOP_MAX)"
                        
                        # Lookup customer
                        CUSTOMER_QUERY="SELECT customer_id FROM logs 
                                        WHERE ip_address='$ip' 
                                        ORDER BY timestamp DESC LIMIT 1"
                        customer_id=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null)
                        
                        if [ -z "$customer_id" ]; then
                            customer_id="UNKNOWN"
                        fi
                        
                        # Blacklist
                        if controlla_blacklist "IP" "$ip"; then
                            echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                            aggiungi_blacklist "IP" "$ip" "PATH_RETE_ANOMALO" \
                                "ALTA" 60 "$NUM_HOP hop (max: $SOGLIA_HOP_MAX), PTR: $PTR_INFO, geo: $GEO, customer: $customer_id"
                        else
                            echo "      → PRIMO RILEVAMENTO"
                            aggiungi_blacklist "IP" "$ip" "PATH_RETE_ANOMALO" \
                                "MEDIA" 40 "$NUM_HOP hop (max: $SOGLIA_HOP_MAX), PTR: $PTR_INFO, geo: $GEO, customer: $customer_id"
                        fi
                        
                        ALERT_COUNT=$((ALERT_COUNT + 1))
                        
                        # Log
                        {
                            echo "═══════════════════════════════════════════"
                            echo "ALERT INCOERENZA - $(date '+%Y-%m-%d %H:%M:%S')"
                            echo "═══════════════════════════════════════════"
                            echo "IP:          $ip"
                            echo "Hop:         $NUM_HOP (soglia: $SOGLIA_HOP_MAX)"
                            echo "PTR:         $PTR_INFO"
                            echo "Geo:         $GEO"
                            echo "Customer:    $customer_id"
                            echo ""
                        } >> "$LOG_INCOERENZA"
                        
                    else
                        echo "  └─ Path normale ($NUM_HOP hop)"
                    fi
                else
                    echo "  └─ Traceroute non disponibile"
                fi
                
            fi
        done
    else
        echo "  → Nessuna connessione"
    fi
    
    echo ""
    ITERAZIONI=$((ITERAZIONI + 1))
    
    if [ $ITERAZIONI -lt $MAX_ITERAZIONI ]; then
        sleep $INTERVALLO_CHECK
    fi
done

echo "================================================================================"
echo "[✓] Analisi completata"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_INCOERENZA"
echo "================================================================================"
