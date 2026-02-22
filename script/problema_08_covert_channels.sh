#!/bin/bash

# PROBLEMA 8: RILEVAMENTO COVERT CHANNELS - DEEP PACKET INSPECTION
#
# SCOPO: Identificare tunnel, encoding nascosti, pacchetti con dimensioni anomale
#        che potrebbero nascondere data exfiltration
#
# METODO: Usa tcpdump per cattura raw packets, analizza dimensioni, flags TCP,
#         payload patterns inusuali
#
# DATABASE: Usato SOLO per lookup puntuale
# BLACKLIST: Registra IP con traffico anomalo
#
# DIPENDENZE: tcpdump, tshark, xxd (hex dump)

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_COVERT="/workspaces/SO/logs/covert_channels_alerts.log"
DB_PATH="/workspaces/SO/data/bank_logs.db"

# Parametri
SERVER_PORT=8000
SOGLIA_PACKET_SIZE_MIN=1400   # Pacchetti sospetti se > 1400 bytes (MTU ~ 1500)
SOGLIA_PACKET_SIZE_ANOMALO=100  # O troppo piccoli < 100
DURATA_CATTURA=90

mkdir -p $(dirname "$LOG_COVERT")

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
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,COVERT_CHANNELS,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,COVERT_CHANNELS,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: analizza_tcp_flags
# Interpreta TCP flags per identificare pattern anomali
# ARG1: flags in formato hex o stringa
analizza_tcp_flags() {
    local flags="$1"
    
    # TCP Flags comuni:
    # S = SYN (inizio connessione)
    # A = ACK (acknowledgment)
    # P = PSH (push, dati da consegnare subito)
    # F = FIN (chiusura connessione)
    # R = RST (reset, chiusura abrupt)
    # U = URG (urgent pointer)
    
    # Pattern sospetti:
    # - Nessun flag (NULL scan)
    # - Solo FIN (FIN scan)
    # - Combinazioni strane (XMAS scan: FPU)
    
    if [ -z "$flags" ] || [ "$flags" == "none" ]; then
        echo "NULL_SCAN"
    elif echo "$flags" | grep -q "FPU"; then
        echo "XMAS_SCAN"
    elif echo "$flags" | grep -q "F" && ! echo "$flags" | grep -q "A"; then
        echo "FIN_SCAN"
    else
        echo "NORMAL"
    fi
}

echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] RILEVAMENTO COVERT CHANNELS AVVIATO"
echo "================================================================================" | tee -a "$LOG_COVERT"

echo "[*] Porta: $SERVER_PORT"
echo "[*] Soglie dimensioni: <$SOGLIA_PACKET_SIZE_ANOMALO bytes o >$SOGLIA_PACKET_SIZE_MIN bytes"
echo "[*] Durata: $DURATA_CATTURA secondi"
echo "[*] Premi Ctrl+C per terminare"
echo ""

# Verifica tcpdump disponibile
if ! command -v tcpdump &> /dev/null; then
    echo "[!] ERRORE: tcpdump non installato"
    echo "[*] Installa con: sudo apt-get install tcpdump"
    exit 1
fi

COUNTER=0
ALERT_COUNT=0

# CATTURA CON TCPDUMP
# tcpdump:
# -i any: tutte le interfacce
# -n: no DNS resolution
# -tttt: timestamp human-readable
# -v: verbose (mostra più dettagli)
# -s 0: snapshot-length 0 = cattura pacchetto intero (no truncate)
# tcp port 8000: filtra TCP porta 8000
# ${var##* }: rimuove tutto fino all'ultimo spazio (bash parameter expansion)

timeout $DURATA_CATTURA sudo tcpdump -i lo -n -tttt -v -s 0 "tcp port $SERVER_PORT" 2>/dev/null | \
while read -r line; do
    
    # tcpdump output format (simplified):
    # timestamp IP src.port > dst.port: Flags [...], length XXX
    
    # Cerca righe con "length" per estrarre dimensioni pacchetto
    if echo "$line" | grep -q "length"; then
        
        COUNTER=$((COUNTER + 1))
        
        # Estrai lunghezza pacchetto
        # grep -oP: output only match, Perl regex
        # 'length \K\d+': \K scarta tutto prima, \d+ cattura cifre
        PACKET_LENGTH=$(echo "$line" | grep -oP 'length \K\d+' 2>/dev/null)
        
        # Estrai IP sorgente
        # awk: secondo campo contiene IP.porta
        # cut -d'.' -f1-4: primi 4 campi delimitati da . (IP senza porta)
        SRC_IP=$(echo "$line" | awk '{print $3}' | cut -d'.' -f1-4)
        
        # -n: verifica NON vuoto
        if [ -n "$PACKET_LENGTH" ] && [ -n "$SRC_IP" ]; then
            
            # Controlla se dimensione anomala
            # -lt: less than
            # -gt: greater than
            if [ "$PACKET_LENGTH" -lt "$SOGLIA_PACKET_SIZE_ANOMALO" ] || \
               [ "$PACKET_LENGTH" -gt "$SOGLIA_PACKET_SIZE_MIN" ]; then
                
                echo "[+] Pacchetto #$COUNTER ANOMALO:"
                echo "    IP: $SRC_IP | Dimensione: $PACKET_LENGTH bytes"
                
                # Estrai TCP flags se presenti
                FLAGS=$(echo "$line" | grep -oP 'Flags \[\K[^\]]+' 2>/dev/null)
                if [ -n "$FLAGS" ]; then
                    FLAG_ANALYSIS=$(analizza_tcp_flags "$FLAGS")
                    echo "    Flags: $FLAGS → $FLAG_ANALYSIS"
                else
                    FLAG_ANALYSIS="UNKNOWN"
                fi
                
                # Determina tipo anomalia
                ANOMALY_TYPE="UNKNOWN"
                if [ "$PACKET_LENGTH" -gt "$SOGLIA_PACKET_SIZE_MIN" ]; then
                    ANOMALY_TYPE="PACKET_TROPPO_GRANDE"
                elif [ "$PACKET_LENGTH" -lt "$SOGLIA_PACKET_SIZE_ANOMALO" ]; then
                    ANOMALY_TYPE="PACKET_TROPPO_PICCOLO"
                fi
                
                echo "    Tipo: $ANOMALY_TYPE"
                echo ""
                
                # Lookup customer
                CUSTOMER_QUERY="SELECT customer_id FROM logs 
                                WHERE ip_address='$SRC_IP' 
                                ORDER BY timestamp DESC LIMIT 1"
                customer_id=$(sqlite3 "$DB_PATH" "$CUSTOMER_QUERY" 2>/dev/null)
                
                if [ -z "$customer_id" ]; then
                    customer_id="UNKNOWN"
                fi
                
                # Blacklist
                if controlla_blacklist "IP" "$SRC_IP"; then
                    echo "  [!] GIÀ IN BLACKLIST (RECIDIVO)"
                    aggiungi_blacklist "IP" "$SRC_IP" "COVERT_CHANNEL_SOSPETTO" \
                        "CRITICA" 90 "$ANOMALY_TYPE, size: $PACKET_LENGTH bytes, flags: $FLAGS ($FLAG_ANALYSIS), customer: $customer_id"
                else
                    echo "  [!] PRIMO RILEVAMENTO"
                    aggiungi_blacklist "IP" "$SRC_IP" "COVERT_CHANNEL_SOSPETTO" \
                        "ALTA" 70 "$ANOMALY_TYPE, size: $PACKET_LENGTH bytes, flags: $FLAGS ($FLAG_ANALYSIS), customer: $customer_id"
                fi
                
                ALERT_COUNT=$((ALERT_COUNT + 1))
                
                # Log
                {
                    echo "═══════════════════════════════════════════"
                    echo "ALERT COVERT CHANNEL - $(date '+%Y-%m-%d %H:%M:%S')"
                    echo "═══════════════════════════════════════════"
                    echo "IP:              $SRC_IP"
                    echo "Dimensione:      $PACKET_LENGTH bytes"
                    echo "Tipo anomalia:   $ANOMALY_TYPE"
                    echo "TCP Flags:       $FLAGS ($FLAG_ANALYSIS)"
                    echo "Customer:        $customer_id"
                    echo ""
                    echo "Dettagli pacchetto:"
                    echo "$line"
                    echo ""
                } >> "$LOG_COVERT"
                
                echo ""
            fi
        fi
    fi
    
    # Ogni 10 pacchetti stampa progresso
    # %: modulo (resto divisione)
    # -eq: equal
    if [ $((COUNTER % 10)) -eq 0 ] && [ $COUNTER -gt 0 ]; then
        echo "[*] Pacchetti analizzati: $COUNTER | Alert: $ALERT_COUNT"
    fi
    
done

echo ""
echo "================================================================================"
echo "[✓] Analisi completata"
echo "[*] Pacchetti analizzati: $COUNTER"
echo "[*] Alert generati: $ALERT_COUNT"
echo "[*] Log: $LOG_COVERT"
echo "================================================================================"
