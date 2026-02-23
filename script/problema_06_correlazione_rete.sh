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
LOG_CORRELAZIONE="/workspaces/SO/logs/correlazione_alerts.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"
LAST_CHECK_FILE="/tmp/problema06_last_check.txt"

# Parametri
SUBNET_AUTORIZZATE=("192.168.0.0/16" "10.0.0.0/8" "172.16.0.0/12")
INTERVALLO_CHECK=3
DURATA_MONITORAGGIO=60

# Soglia di blocco per risk_score (IP)
RISK_BLOCK_THRESHOLD=100

mkdir -p $(dirname "$LOG_CORRELAZIONE")

# Inizializza timestamp ultimo check (solo se non esiste)
if [ ! -f "$LAST_CHECK_FILE" ]; then
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
fi

# Array per tracciare IP già segnalati in questa sessione
declare -A SEGNALATI

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
        local recidivita=$(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH")
        recidivita=$((recidivita + 1))
        local new_risk=$((current_risk + risk_score))
        final_risk="$new_risk"
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_CORRELAZIONE"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},CORRELAZIONE_RETE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_CORRELAZIONE"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},CORRELAZIONE_RETE,${note}" >> "$BLACKLIST_PATH"
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

# Avvio monitoraggio con output minimo
log "P06 start"
# Log dettagliato su file
echo "================================================================================" >> "$LOG_CORRELAZIONE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ANALISI CORRELAZIONE RETE AVVIATA" >> "$LOG_CORRELAZIONE"
echo "================================================================================" >> "$LOG_CORRELAZIONE"

# Output verbose silenziato da exec 1>/dev/null
echo "[*] Subnet autorizzate: ${SUBNET_AUTORIZZATE[@]}"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
    echo "[Check #$ITERAZIONI] $(date '+%H:%M:%S')"
    
    # Leggi timestamp ultimo check
    LAST_CHECK=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo "1970-01-01T00:00:00")
    
    # Query: trova login recenti per analizzare IP
    QUERY="SELECT DISTINCT ip_address 
           FROM logs 
           WHERE azione = 'LOGIN' 
           AND timestamp > '$LAST_CHECK'"
    
    IPS_RECENTI=$(sqlite3 "$DB_PATH" "$QUERY" 2>/dev/null)
    
    # Conta IP solo se la stringa non è vuota
    if [ -n "$IPS_RECENTI" ]; then
        NUM_IPS=$(echo "$IPS_RECENTI" | wc -l)
    else
        NUM_IPS=0
    fi
    
    if [ $NUM_IPS -gt 0 ]; then
        echo "  → IP rilevati: $NUM_IPS"
        echo ""
        
        # Usa process substitution per evitare subshell
        while read -r ip; do
            
            if [ -n "$ip" ]; then
                
                # VERIFICA SUBNET
                if ! verifica_ip_in_subnet "$ip"; then
                    echo "  [!!!] IP SOSPETTO: $ip NON in subnet autorizzata"
                    # Messaggio minimo di alert
                    log "P06 alert $ip"
                    
                    # Lookup customer dal DB
                    CUSTOMER_QUERY="SELECT DISTINCT customer_id 
                                    FROM logs 
                                    WHERE ip_address='$ip' 
                                    AND timestamp > '$LAST_CHECK'
                                    LIMIT 5"
                    customer_ids=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null | paste -sd ',' -)
                    
                    if [ -z "$customer_ids" ]; then
                        customer_ids="UNKNOWN"
                    fi
                    echo "      → Customer: $customer_ids"
                    echo "      → Subnet: PUBBLICA/NON AUTORIZZATA"
                    
                    # Segnala solo se non già fatto in questa sessione
                    if [ -z "${SEGNALATI[$ip]}" ]; then
                        SEGNALATI[$ip]=1
                        
                        # Blacklist
                        if controlla_blacklist "IP" "$ip"; then
                            echo "      → GIÀ IN BLACKLIST (RECIDIVO)"
                            aggiungi_blacklist "IP" "$ip" "SUBNET_NON_AUTORIZZATA" \
                                "ALTA" 70 "IP fuori subnet autorizzate (pubblico); customer: $customer_ids"
                        else
                            echo "      → PRIMO RILEVAMENTO"
                            aggiungi_blacklist "IP" "$ip" "SUBNET_NON_AUTORIZZATA" \
                                "MEDIA" 50 "IP fuori subnet autorizzate (pubblico); customer: $customer_ids"
                        fi
                        
                        # Messaggio minimo di alert
                        log "P06 alert $ip"

                        ALERT_COUNT=$((ALERT_COUNT + 1))
                        
                        # Log
                        {
                            echo "═══════════════════════════════════════════"
                            echo "ALERT CORRELAZIONE - $(date '+%Y-%m-%d %H:%M:%S')"
                            echo "═══════════════════════════════════════════"
                            echo "IP:          $ip"
                            echo "Customer:    $customer_ids"
                            echo "Subnet:      PUBBLICA/NON AUTORIZZATA"
                            echo ""
                        } >> "$LOG_CORRELAZIONE"
                        
                        break
                    else
                        echo "      → Già segnalato in questa sessione (SKIP)"
                    fi
                    
                    echo ""
                fi
            fi
        done < <(echo "$IPS_RECENTI")
    else
        echo "  → Nessun IP rilevato"
    fi
    
    # Aggiorna timestamp ultimo check
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
    
    echo ""
    ITERAZIONI=$((ITERAZIONI + 1))
    
    if [ $ITERAZIONI -lt $MAX_ITERAZIONI ]; then
        sleep $INTERVALLO_CHECK
    fi
done

# Report finale (verbose, silenziato)
echo "================================================================================"
echo "[✓] Analisi completata"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_CORRELAZIONE"
echo "================================================================================"

# Messaggio minimo di fine
log "P06 done"
