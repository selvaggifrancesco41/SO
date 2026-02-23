#!/bin/bash

# PROBLEMA 9: INCOERENZA RETE - SUBNET AUTHORIZATION & CONTEXT VALIDATION
#
# SCOPO: Identificare operazioni da subnet inappropriate (es. bonifico da range ATM,
#        prelievo da range API, accessi da IP pubblici non autorizzati)
#
# METODO: Verifica che l'IP sorgente appartenga alla subnet corretta per il tipo
#         di operazione eseguita. Es: BONIFICO da subnet clienti (OK), 
#         BONIFICO da subnet ATM (ANOMALO)
#
# DATABASE: Legge log recenti per verificare IP vs azione
# BLACKLIST: Registra IP che eseguono operazioni da subnet inappropriate
#
# DIPENDENZE: sqlite3

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
LOG_INCOERENZA="/workspaces/SO/logs/incoerenza_rete_alerts.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"
LAST_CHECK_FILE="/tmp/problema09_last_check.txt"

# Parametri
SERVER_PORT=8000
INTERVALLO_CHECK=3       # Controlla ogni 3 secondi
DURATA_MONITORAGGIO=60   # Durata totale 60 secondi

# Soglia di blocco per risk_score (IP)
RISK_BLOCK_THRESHOLD=100

# DEFINIZIONE SUBNET AUTORIZZATE
# Ogni tipo di operazione ha subnet specifiche da cui può provenire
# Formato subnet: 192.168.X.0/24 → verifica 192.168.X.*

# Subnet clienti normali (possono fare: LOGIN, BONIFICO, CONSULTA_SALDO)
SUBNET_CLIENTI="192.168.10 192.168.20"

# Subnet ATM (possono fare: PRELIEVO, DEPOSITO, CONSULTA_SALDO)
SUBNET_ATM="192.168.30"

# Subnet API/servizi (possono fare: solo operazioni automatiche)
SUBNET_API="192.168.40"

# Subnet amministrazione (possono fare tutto)
SUBNET_ADMIN="192.168.1"

# Localhost (test - permesso)
SUBNET_TEST="127.0.0"

# Subnet pubbliche non autorizzate (tutti gli altri IP pubblici sono sospetti)
# 203.0.113.0/24 è range di test RFC5737
SUBNET_PUBBLICHE_TEST="203.0.113"

mkdir -p $(dirname "$LOG_INCOERENZA")

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
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_INCOERENZA"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},INCOERENZA_RETE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge "$RISK_BLOCK_THRESHOLD" ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            # Traccia blocco nel log problema
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_INCOERENZA"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},INCOERENZA_RETE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: verifica_subnet
# Controlla se un IP appartiene a una subnet
# ARG1: IP (es. 192.168.30.1)
# ARG2: Lista subnet (es. "192.168.30 192.168.40")
# RETURN: 0 se appartiene, 1 se non appartiene
verifica_subnet() {
    local ip="$1"
    local subnet_list="$2"
    
    # Estrai i primi 3 ottetti dell'IP (es. 192.168.30 da 192.168.30.1)
    local ip_prefix=$(echo "$ip" | cut -d'.' -f1-3)
    
    # Controlla se il prefisso è in una delle subnet
    for subnet in $subnet_list; do
        if [ "$ip_prefix" = "$subnet" ]; then
            return 0  # Trovato
        fi
    done
    
    return 1  # Non trovato
}

# FUNZIONE: verifica_azione_autorizzata
# Verifica se un'azione è autorizzata per una determinata subnet
# ARG1: IP
# ARG2: Azione (BONIFICO, PRELIEVO, LOGIN, ecc.)
# RETURN: 0 se autorizzata, 1 se NON autorizzata (+ echo messaggio)
verifica_azione_autorizzata() {
    local ip="$1"
    local azione="$2"
    
    # Localhost/test sempre autorizzato (per non bloccare i test)
    if verifica_subnet "$ip" "$SUBNET_TEST"; then
        return 0
    fi
    
    # Admin sempre autorizzato
    if verifica_subnet "$ip" "$SUBNET_ADMIN"; then
        return 0
    fi
    
    # Regole specifiche per azione
    case "$azione" in
        BONIFICO|CONSULTA_SALDO|LOGIN)
            # Queste azioni DEVONO venire da subnet clienti
            if verifica_subnet "$ip" "$SUBNET_CLIENTI"; then
                return 0
            else
                # ANOMALO: bonifico/login da subnet non-clienti
                if verifica_subnet "$ip" "$SUBNET_ATM"; then
                    echo "BONIFICO/LOGIN da subnet ATM (dovrebbe essere da clienti)"
                    return 1
                elif verifica_subnet "$ip" "$SUBNET_API"; then
                    echo "BONIFICO/LOGIN da subnet API (dovrebbe essere da clienti)"
                    return 1
                elif verifica_subnet "$ip" "$SUBNET_PUBBLICHE_TEST"; then
                    echo "BONIFICO/LOGIN da IP pubblico non autorizzato"
                    return 1
                else
                    echo "BONIFICO/LOGIN da subnet sconosciuta"
                    return 1
                fi
            fi
            ;;
        
        PRELIEVO|DEPOSITO)
            # Queste azioni DEVONO venire da ATM
            if verifica_subnet "$ip" "$SUBNET_ATM"; then
                return 0
            else
                # ANOMALO: prelievo da subnet non-ATM
                if verifica_subnet "$ip" "$SUBNET_CLIENTI"; then
                    echo "PRELIEVO/DEPOSITO da subnet clienti (dovrebbe essere da ATM)"
                    return 1
                elif verifica_subnet "$ip" "$SUBNET_API"; then
                    echo "PRELIEVO/DEPOSITO da subnet API (dovrebbe essere da ATM)"
                    return 1
                else
                    echo "PRELIEVO/DEPOSITO da subnet non-ATM"
                    return 1
                fi
            fi
            ;;
        
        *)
            # Azioni sconosciute: permetti ma logga
            return 0
            ;;
    esac
}


# Avvio monitoraggio con output minimo
log "P09 start"
# Log dettagliato su file
echo "================================================================================" >> "$LOG_INCOERENZA"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ANALISI INCOERENZA RETE (SUBNET) AVVIATA" >> "$LOG_INCOERENZA"
echo "================================================================================" >> "$LOG_INCOERENZA"

# Output verbose silenziato da exec 1>/dev/null
echo "[*] Porta: $SERVER_PORT"
echo "[*] Verifica subnet autorizzate per tipo operazione"
echo "[*] Intervallo: $INTERVALLO_CHECK secondi"
echo "[*] Durata: $DURATA_MONITORAGGIO secondi"
echo ""
echo "[*] Subnet clienti: $SUBNET_CLIENTI"
echo "[*] Subnet ATM: $SUBNET_ATM"
echo "[*] Subnet API: $SUBNET_API"
echo ""

# Inizializza timestamp da file (resettato da run_problem.sh)
if [ ! -f "$LAST_CHECK_FILE" ]; then
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
fi

ITERAZIONI=0
MAX_ITERAZIONI=$((DURATA_MONITORAGGIO / INTERVALLO_CHECK))
ALERT_COUNT=0

while [ $ITERAZIONI -le $MAX_ITERAZIONI ] && [ $ALERT_COUNT -eq 0 ]; do
    
    echo "[Check #$ITERAZIONI] $(date '+%H:%M:%S')"
    
    LAST_CHECK_TIMESTAMP=$(cat "$LAST_CHECK_FILE")
    
    # Leggi log recenti dal database
    QUERY="SELECT ip_address, azione, customer_id, timestamp 
           FROM logs 
           WHERE timestamp > '$LAST_CHECK_TIMESTAMP' 
           ORDER BY timestamp DESC"
    
    IPS_ANALIZZATI=0
    
    while IFS='|' read -r ip azione customer timestamp; do
        
        if [ -n "$ip" ] && [ -n "$azione" ]; then
            IPS_ANALIZZATI=$((IPS_ANALIZZATI + 1))
            
            # Verifica se azione è autorizzata per la subnet dell'IP
            MOTIVO=$(verifica_azione_autorizzata "$ip" "$azione")
            AUTORIZZATO=$?
            
            if [ $AUTORIZZATO -ne 0 ]; then
                # ANOMALIA RILEVATA
                echo ""
                echo "  [!!!] ANOMALIA RILEVATA"
                echo "  ├─ IP: $ip"
                echo "  ├─ Azione: $azione"
                echo "  ├─ Customer: $customer"
                echo "  ├─ Timestamp: $timestamp"
                echo "  └─ Motivo: $MOTIVO"
                
                # Segnala solo se non già fatto in questa sessione
                if [ -z "${SEGNALATI[$ip]}" ]; then
                    SEGNALATI[$ip]=1
                    
                    # Blacklist
                    if controlla_blacklist "IP" "$ip"; then
                        aggiungi_blacklist "IP" "$ip" "SUBNET_NON_AUTORIZZATA" \
                            "CRITICA" 90 "Azione $azione da subnet inappropriata: $MOTIVO; customer: $customer"
                        echo "  [!] AGGIUNTO A BLACKLIST (RECIDIVO)"
                    else
                        aggiungi_blacklist "IP" "$ip" "SUBNET_NON_AUTORIZZATA" \
                            "ALTA" 70 "Azione $azione da subnet inappropriata: $MOTIVO; customer: $customer"
                        echo "  [!] AGGIUNTO A BLACKLIST"
                    fi
                    
                    # Messaggio minimo di alert
                    log "P09 alert $ip"

                    ALERT_COUNT=$((ALERT_COUNT + 1))
                    
                    # Log
                    {
                        echo "═══════════════════════════════════════════"
                        echo "ALERT SUBNET NON AUTORIZZATA - $(date '+%Y-%m-%d %H:%M:%S')"
                        echo "═══════════════════════════════════════════"
                        echo "IP:              $ip"
                        echo "Azione:          $azione"
                        echo "Customer:        $customer"
                        echo "Timestamp:       $timestamp"
                        echo "Motivo:          $MOTIVO"
                        echo ""
                    } >> "$LOG_INCOERENZA"
                    
                    echo ""
                    
                    # ESCI IMMEDIATAMENTE dopo primo alert
                    break
                    
                else
                    echo "  [!] IP già segnalato in questa sessione (SKIP)"
                fi
                
                echo ""
            fi
        fi
        
    done < <(sqlite3 "$DB_PATH" "$QUERY" 2>/dev/null)
    
    echo "  → Log analizzati: $IPS_ANALIZZATI | Alert: $ALERT_COUNT"
    
    # Aggiorna timestamp per prossimo controllo
    date -u '+%Y-%m-%dT%H:%M:%S' > "$LAST_CHECK_FILE"
    
    ITERAZIONI=$((ITERAZIONI + 1))
    
    # Exit se alert trovato
    if [ $ALERT_COUNT -gt 0 ]; then
        break
    fi
    
    if [ $ITERAZIONI -le $MAX_ITERAZIONI ]; then
        sleep $INTERVALLO_CHECK
    fi
    
done

# Report finale (verbose, silenziato)
echo ""
echo "================================================================================"
echo "[✓] Analisi completata"
echo "[*] Check eseguiti: $ITERAZIONI"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_INCOERENZA"
echo "================================================================================"

# Messaggio minimo di fine
log "P09 done"
