#!/bin/bash

# PROBLEMA 6: CORRELAZIONE EVENTI DI RETE - MULTI-HOST MONITORING
#
# SCOPO: Identificare IP che si connettono da subnet sospette o che appaiono
#        contemporaneamente su più servizi (server web + DB + cache)
#
# METODO: Usa ip, arp, ping per analizzare topologia rete e correlazioni,
#         identifica IP che saltano tra subnet diverse
#
# DATABASE: Usato SOLO per lookup puntuale customer_id
# BLACKLIST: Registra IP con pattern di connessione anomali
#
# DIPENDENZE: ip, arp, ping, ss, awk

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_CORRELAZIONE="/workspaces/SO/logs/correlazione_alerts.log"
DB_PATH="/workspaces/SO/data/eventi_bancari.db"

# Parametri
SERVER_PORT=8000
SUBNET_AUTORIZZATE=("192.168.0.0/16" "10.0.0.0/8" "172.16.0.0/12")
INTERVALLO_CHECK=12
DURATA_MONITORAGGIO=120

mkdir -p $(dirname "$LOG_CORRELAZIONE")

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
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,CORRELAZIONE_RETE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,CORRELAZIONE_RETE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: ottieni_info_rete
# Estrae informazioni sulla configurazione rete locale
ottieni_info_rete() {
    echo "[INFO RETE LOCALE]"
    
    # ip a: mostra indirizzi IP assegnati alle interfacce
    # ip r: mostra routing table
    echo "  Interfacce e IP:"
    # ip a: address show
    # grep "inet ": filtra solo righe con indirizzi IPv4
    # awk: estrae secondo campo (IP/CIDR)
    ip a | grep "inet " | awk '{print "    " $2 " (" $NF ")"}'
    
    echo "  Gateway predefinito:"
    # ip r: route show
    # grep "^default": filtra riga default gateway
    # awk: estrae IP gateway
    ip r | grep "^default" | awk '{print "    " $3 " via " $5}'
    
    echo ""
}

# FUNZIONE: verifica_ip_in_subnet
# Verifica se IP appartiene a subnet autorizzata (simplified check)
# ARG1: IP da verificare
# RETURN: 0 se autorizzato, 1 se sospetto
verifica_ip_in_subnet() {
    local ip="$1"
    
    # Estrai primi ottetti per confronto semplificato
    # cut -d'.' -f1: primo ottetto
    # cut -d'.' -f1-2: primi due ottetti
    PRIMO_OTTETTO=$(echo "$ip" | cut -d'.' -f1)
    PRIMI_DUE=$(echo "$ip" | cut -d'.' -f1-2)
    
    # Confronta con subnet comuni autorizzate
    # 192.168.x.x - rete privata classe C
    # 10.x.x.x - rete privata classe A
    # 172.16-31.x.x - rete privata classe B
    if [ "$PRIMO_OTTETTO" == "192" ] && [ "$PRIMI_DUE" == "192.168" ]; then
        return 0  # Autorizzato
    elif [ "$PRIMO_OTTETTO" == "10" ]; then
        return 0  # Autorizzato
    elif [ "$PRIMO_OTTETTO" == "172" ]; then
        SECONDO=$(echo "$ip" | cut -d'.' -f2)
        # -ge 16 -a -le 31: and logic (tra 16 e 31)
        if [ "$SECONDO" -ge 16 ] && [ "$SECONDO" -le 31 ]; then
            return 0  # Autorizzato
        fi
    fi
    
    return 1  # Sospetto (IP pubblico o subnet non autorizzata)
}

# FUNZIONE: ping_check
# Verifica raggiungibilità e RTT (Round Trip Time) di un host
# ARG1: IP da pingare
ping_check() {
    local target_ip="$1"
    
    # ping:
    # -c 3: count, invia 3 pacchetti ICMP Echo Request
    # -W 2: timeout 2 secondi per risposta
    # -q: quiet, output minimale
    # grep "avg": estrae riga con statistiche medie
    # cut: estrae valore RTT medio
    local ping_result=$(ping -c 3 -W 2 -q "$target_ip" 2>/dev/null | grep "rtt min/avg/max" | cut -d'/' -f5)
    
    if [ -n "$ping_result" ]; then
        echo "$ping_result ms"
    else
        echo "UNREACHABLE"
    fi
}

# FUNZIONE: ottieni_mac_da_arp
# Recupera MAC address di IP dalla ARP table
# ARG1: IP
ottieni_mac_da_arp() {
    local ip="$1"
    
    # arp -n: mostra ARP cache in formato numerico
    # grep: filtra riga con questo IP
    # awk: estrae campo MAC address
    # arp output format: IP HWtype HWaddress Flags Mask Iface
    local mac=$(arp -n 2>/dev/null | grep "^$ip " | awk '{print $3}')
    
    if [ -z "$mac" ]; then
        echo "UNKNOWN"
    else
        echo "$mac"
    fi
}

echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ANALISI CORRELAZIONE RETE AVVIATA"
echo "================================================================================" | tee -a "$LOG_CORRELAZIONE"

# Mostra info rete corrente
ottieni_info_rete

echo "[*] Porta server: $SERVER_PORT"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ]; do
    
    echo "[Check #$ITERAZIONI] $(date '+%H:%M:%S')"
    
    # Estrai IP connessi al server
    IPS_CONNESSI=$(ss -tn state established sport = :$SERVER_PORT 2>/dev/null | \
        awk 'NR>1 {print $5}' | cut -d':' -f1 | sort -u)
    
    NUM_IPS=$(echo "$IPS_CONNESSI" | grep -c '^' 2>/dev/null || echo 0)
    
    if [ $NUM_IPS -gt 0 ]; then
        echo "  → IP connessi: $NUM_IPS"
        
        echo "$IPS_CONNESSI" | while read -r ip; do
            
            if [ -n "$ip" ]; then
                echo "    • Analisi IP: $ip"
                
                # VERIFICA SUBNET
                if ! verifica_ip_in_subnet "$ip"; then
                    echo ""
                    echo "  [!!!] IP SOSPETTO: $ip NON in subnet autorizzata"
                    
                    # Ping check per RTT
                    RTT=$(ping_check "$ip")
                    echo "      → RTT: $RTT"
                    
                    # Controlla ARP table per MAC
                    MAC=$(ottieni_mac_da_arp "$ip")
                    echo "      → MAC: $MAC"
                    
                    # Lookup customer dal DB
                    CUSTOMER_QUERY="SELECT customer_id FROM eventi 
                                    WHERE ip_address='$ip' 
                                    ORDER BY timestamp DESC LIMIT 1"
                    customer_id=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null)
                    
                    if [ -z "$customer_id" ]; then
                        customer_id="UNKNOWN"
                    fi
                    echo "      → Customer: $customer_id"
                    
                    # Blacklist
                    if controlla_blacklist "IP" "$ip"; then
                        echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                        aggiungi_blacklist "IP" "$ip" "SUBNET_NON_AUTORIZZATA" \
                            "ALTA" 70 "IP fuori subnet autorizzate, RTT: $RTT, MAC: $MAC, customer: $customer_id"
                    else
                        echo "      → PRIMO RILEVAMENTO"
                        aggiungi_blacklist "IP" "$ip" "SUBNET_NON_AUTORIZZATA" \
                            "MEDIA" 50 "IP fuori subnet autorizzate, RTT: $RTT, MAC: $MAC, customer: $customer_id"
                    fi
                    
                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    
                    # Log
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT CORRELAZIONE - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "IP:          $ip"
                        echo "RTT:         $RTT"
                        echo "MAC:         $MAC"
                        echo "Customer:    $customer_id"
                        echo "Subnet:      NON AUTORIZZATA"
                        echo ""
                    } >> "$LOG_CORRELAZIONE"
                    
                    echo ""
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
echo "[*] Log: $LOG_CORRELAZIONE"
echo "================================================================================"
