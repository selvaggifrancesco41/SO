#!/bin/bash

# PROBLEMA 10: LOW & SLOW ATTACKS - NETWORK MONITORING  
#
# SCOPO: Rilevare attacchi a basso volume/bassa velocità
#        (connessioni prolungate, bandwidth insufficiente per operazione normale)
#
# METODO: Usa 'ss' per monitorare connessioni stabilizzate
#         Misura durata connessione e bytes trasmessi
#         Se connessione > tempo atteso con dati << attesi: attacco low&slow
#
# NETWORK TOOLS: ss

# Output minimale
exec 3>&1
exec 1>/dev/null

log() {
    printf "%s\n" "$1" >&3
}

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_SLOW="/workspaces/SO/logs/low_slow_alerts.log"

# Parametri
SERVER_PORT=8000
MONITORAGGIO_DURATA=30
INTERVALLO_CHECK=5
CONNESSIONE_TIMEOUT_THRESHOLD=20  # secondi - connessione < dati oppure > timeout
BYTES_THRESHOLD=1024             # Almeno 1KB atteso per transazione

mkdir -p $(dirname "$LOG_SLOW")

declare -A SEGNALATI
declare -A CONNESSIONE_START_TIME
declare -A CONNESSIONE_BYTES

# FUNZIONI COMUNI
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

blocca_ip_se_necessario() {
    local ip_to_block="$1"
    local risk_score="$2"
    if [ "$risk_score" -ge 100 ] && command -v iptables >/dev/null 2>&1; then
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
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge 100 ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_SLOW"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${final_risk},${stato},LOW_SLOW_ATTACK,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        if [ "$tipo_elemento" = "IP" ] && [ "$final_risk" -ge 100 ]; then
            stato="blocked"
            blocca_ip_se_necessario "$elemento" "$final_risk"
            echo "BLOCKED IP: $elemento | risk=$final_risk" >> "$LOG_SLOW"
        fi
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${final_risk},${stato},LOW_SLOW_ATTACK,${note}" >> "$BLACKLIST_PATH"
    fi
}

# INIZIO MONITORAGGIO
log "P10 start"

echo "================================================================================" >> "$LOG_SLOW"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ANALISI LOW & SLOW ATTACKS (NETWORK)" >> "$LOG_SLOW"
echo "================================================================================" >> "$LOG_SLOW"

echo "[*] Porta server: $SERVER_PORT"
echo "[*] Intervallo check: $INTERVALLO_CHECK secondi"
echo "[*] Durata monitoraggio: $MONITORAGGIO_DURATA secondi"
echo "[*] Soglia timeout: $CONNESSIONE_TIMEOUT_THRESHOLD secondi"
echo ""

ITERAZIONI=0
MAX_ITERAZIONI=$((MONITORAGGIO_DURATA / INTERVALLO_CHECK))
ALERT_COUNT=0
ORA_START=$(date +%s)

while [ $ITERAZIONI -le $MAX_ITERAZIONI ]; do
    
    ITERAZIONI=$((ITERAZIONI + 1))
    ORA_ATTUALE=$(date '+%H:%M:%S')
    ORA_UNIX=$(date +%s)
    TEMPO_TRASCORSO=$((ORA_UNIX - ORA_START))
    
    echo "[Check #$ITERAZIONI @ $ORA_ATTUALE] Tempo trascorso: ${TEMPO_TRASCORSO}s"
    
    # Ricava connessioni attive
    echo "  → ss -tno | grep :$SERVER_PORT"
    
    # ss -tno mostra: Protocol, Recv-Q, Send-Q, Local Address, Peer Address, State, PID/Program
    # Recv-Q e Send-Q indicano ristagno nei buffer
    SS_OUTPUT=$(ss -tno 2>/dev/null | grep ":$SERVER_PORT " | awk '{print $5, $6, $7}')
    
    if [ -n "$SS_OUTPUT" ]; then
        echo "  → Analizzando connessioni stagnanti..."
        
        while read -r source_addr recv_q send_q; do
            
            if [ -z "$source_addr" ]; then
                continue
            fi
            
            source_ip=$(echo "$source_addr" | cut -d: -f1)
            
            if [ -z "$source_ip" ] || [ "$source_ip" = "127.0.0.1" ]; then
                continue
            fi
            
            echo "  [*] IP Connesso: $source_ip"
            echo "      → Recv-Q: $recv_q bytes | Send-Q: $send_q bytes"
            
            # Verifica prima occurrence per questa connessione
            if [ -z "${CONNESSIONE_START_TIME[$source_ip]}" ]; then
                CONNESSIONE_START_TIME[$source_ip]=$TEMPO_TRASCORSO
                CONNESSIONE_BYTES[$source_ip]=$((recv_q + send_q))
                echo "      → [REGISTRAZIONE] Connessione inizio"
            else
                # Controlla durata e volume
                DURATA=$((TEMPO_TRASCORSO - CONNESSIONE_START_TIME[$source_ip]))
                BYTES_TOTALI=$((recv_q + send_q))
                BYTES_DELTA=$((BYTES_TOTALI - CONNESSIONE_BYTES[$source_ip]))
                
                echo "      → [CONNESSIONE ATTIVA] Durata: ${DURATA}s | Bytes: ${BYTES_TOTALI}B"
                
                # Rilevamento low&slow:
                # 1. Connessione prolungata MA pochi dati trasmessi
                # 2. Buffer stagnanti (dati non trasmessi)
                
                LOW_N_SLOW=0
                MOTIVO=""
                
                # Condizione 1: Connessione > soglia timeout ma dati < soglia
                if [ "$DURATA" -gt "$CONNESSIONE_TIMEOUT_THRESHOLD" ] && \
                   [ "$BYTES_TOTALI" -lt "$BYTES_THRESHOLD" ]; then
                    LOW_N_SLOW=1
                    MOTIVO="Connessione prolungata (${DURATA}s) con dati insufficienti (${BYTES_TOTALI}B < ${BYTES_THRESHOLD}B)"
                fi
                
                # Condizione 2: Buffer persistenti (Send-Q > 5KB per 2+ checK)
                if [ "$send_q" -gt 5120 ]; then
                    LOW_N_SLOW=1
                    MOTIVO="Buffer Send-Q stagnante (${send_q}B)"
                fi
                
                if [ "$LOW_N_SLOW" = "1" ]; then
                    echo "      → [!] ANOMALIA LOW&SLOW RILEVATA!"
                    echo "         Motivo: $MOTIVO"
                    
                    if [ -z "${SEGNALATI[$source_ip]}" ]; then
                        SEGNALATI[$source_ip]=1
                        
                        # Risk score basato su durata e stagnazione
                        risk_score=$((25 + (DURATA / 5) * 8))
                        [ "$risk_score" -gt 85 ] && risk_score=85
                        
                        aggiungi_blacklist "IP" "$source_ip" "LOW_SLOW_ATTACK" "MEDIA" "$risk_score" \
                            "Attacco low&slow: $MOTIVO"
                        
                        log "P10 alert $source_ip (${DURATA}s)"
                        ALERT_COUNT=$((ALERT_COUNT + 1))
                    fi
                fi
            fi
            
        done <<< "$SS_OUTPUT"
        
    else
        echo "  → Nessuna connessione attiva"
    fi
    
    echo ""
    
    # Se alert, posso stoppare anticipatamente
    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo "  [*] Alert rilevati, continuando monitoraggio..."
    fi
    
    sleep "$INTERVALLO_CHECK"
done

# REPORT FINALE
echo ""
echo "================================================================================"
echo "[✓] Monitoraggio low&slow completato"
echo "[*] Iterazioni: $ITERAZIONI"
echo "[*] IP monitorati: ${#CONNESSIONE_START_TIME[@]}"
echo "[*] Alert generati: $ALERT_COUNT"
if [ "$ALERT_COUNT" -eq 0 ]; then
    echo "[*] Nessun attacco low&slow rilevato"
fi
echo "[*] Log: $LOG_SLOW"
echo "================================================================================"

# Log finale
{
    echo "═══════════════════════════════════════════"
    echo "LOW & SLOW ATTACK - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "═══════════════════════════════════════════"
    echo "Connessioni monitorate: ${#CONNESSIONE_START_TIME[@]}"
    echo "Alert generati: $ALERT_COUNT"
} >> "$LOG_SLOW"

log "P10 done"

