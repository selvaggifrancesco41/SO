#!/bin/bash

# PROBLEMA 5: RILEVAMENTO BRUTE-FORCE LOGIN - PACKET CAPTURE
#
# SCOPO: Rilevare tentativi di brute-force sulle API /login del server
#        monitorando frequenza richieste HTTP da stessi IP sorgente
#
# METODO: Cattura traffico HTTP con tcpdump/tshark, conta richieste /login
#         per IP in finestra temporale, rileva pattern di attacco
#
# DATABASE: Usato SOLO per lookup puntuale customer_id (opzionale)
# BLACKLIST: Controlla e registra IP che eseguono brute-force
#
# DIPENDENZE: tcpdump o tshark, awk, grep

BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_BRUTEFORCE="/workspaces/SO/logs/bruteforce_alerts.log"
STATE_FILE="/workspaces/SO/logs/bruteforce_state.tmp"
DB_PATH="/workspaces/SO/data/eventi_bancari.db"

# Parametri rilevamento
SERVER_PORT=8000                   # Porta server Flask
SOGLIA_TENTATIVI=10                # Max tentativi login da stessIP in finestra
FINESTRA_SECONDI=60                # Finestra temporale di analisi
DURATA_CATTURA=300                 # Durata totale cattura (5 minuti)

mkdir -p $(dirname "$LOG_BRUTEFORCE")
mkdir -p $(dirname "$STATE_FILE")

# FUNZIONE: controlla_blacklist
# ARG1: tipo (IP, USER_ID, IBAN, PORTA, ATM_ID)
# ARG2: valore elemento
# RETURN: 0 se presente in blacklist, 1 se assente
# NOTE: grep -q silent mode, 2>/dev/null scarta errori
controlla_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    grep -q "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH" 2>/dev/null
    return $?
}

# FUNZIONE: get_risk_score
# ARG1: tipo_elemento
# ARG2: elemento
# OUTPUT: risk_score (numero) oppure 0 se non trovato
# NOTE: awk separa CSV con -F',', $7 è colonna risk_score
get_risk_score() {
    local tipo_elemento="$1"
    local elemento="$2"
    
    local score=$(awk -F',' -v tipo="$tipo_elemento" -v elem="$elemento" \
        '$3==tipo && $4==elem {print $7}' "$BLACKLIST_PATH" | tail -1)
    
    # -z: controllo se stringa vuota (zero length)
    if [ -z "$score" ]; then
        echo 0
    else
        echo "$score"
    fi
}

# FUNZIONE: aggiungi_blacklist
# ARGS: tipo, elemento, azione, gravita, risk_score, note
# COMPORTAMENTO: Aggiunge a blacklist, se recidivo incrementa risk e recidivita
aggiungi_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    local azione="$3"
    local gravita="$4"
    local risk_score="$5"
    local note="$6"
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if controlla_blacklist "$tipo_elemento" "$elemento"; then
        # RECIDIVO
        local current_risk=$(get_risk_score "$tipo_elemento" "$elemento")
        # grep -c conta numero di match
        local recidivita=$(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH")
        recidivita=$((recidivita + 1))
        # $(( )) arithmetic expansion per somma
        local new_risk=$((current_risk + risk_score))
        
        # >> append al file senza sovrascrivere
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${recidivita},${new_risk},blacklisted,BRUTEFORCE,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        # NUOVO
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,BRUTEFORCE,${note}" >> "$BLACKLIST_PATH"
    fi
}

# FUNZIONE: blocca_ip_con_iptables
# ARG1: IP da bloccare
# AZIONE: Aggiunge regola iptables DROP per quell'IP
# NOTE: Richiede sudo, verifica prima se iptables disponibile
blocca_ip_con_iptables() {
    local ip_to_block="$1"
    
    # command -v verifica se comando esiste nel PATH
    if command -v iptables &> /dev/null; then
        echo "[*] Tentativo blocco IP $ip_to_block con iptables..."
        
        # iptables -A INPUT: append regola alla chain INPUT
        # -s: source IP
        # -j DROP: jump to DROP target (scarta pacchetto)
        # 2>&1: redirige stderr su stdout per catturare errori
        sudo iptables -A INPUT -s "$ip_to_block" -j DROP 2>&1
        
        # $?: exit code del comando precedente (0 = success, != 0 = error)
        if [ $? -eq 0 ]; then
            echo "[✓] IP $ip_to_block bloccato con iptables"
        else
            echo "[!] Errore blocco (potrebbe servire sudo o permessi)"
        fi
    else
        echo "[!] iptables non disponibile, skip blocco"
    fi
}

# AVVIO MONITORAGGIO
echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] RILEVAMENTO BRUTE-FORCE AVVIATO"
echo "================================================================================" | tee -a "$LOG_BRUTEFORCE"

echo "[*] Porta monitorata: $SERVER_PORT"
echo "[*] Soglia tentativi: $SOGLIA_TENTATIVI in $FINESTRA_SECONDI secondi"
echo "[*] Durata cattura: $DURATA_CATTURA secondi"
echo "[*] Premi Ctrl+C per terminare"
echo ""

# Verifica tshark disponibile
if ! command -v tshark &> /dev/null; then
    echo "[!] ERRORE: tshark non installato"
    echo "[*] Installa con: sudo apt-get install tshark"
    exit 1
fi

# Inizializza file di stato
# Format: timestamp_unix|ip_sorgente|uri
echo "# Brute-force state - $(date)" > "$STATE_FILE"

COUNTER_PACKETS=0
ALERT_COUNT=0

# CATTURA CON TSHARK
# timeout: termina comando dopo N secondi
# tshark:
#   -i any: cattura su tutte le interfacce
#   -f "tcp port 8000": BPF filter, solo TCP porta 8000
#   -Y: display filter Wireshark
#   -T fields: output formattato a campi
#   -e: estrai questi campi
#   -l: line buffered (output immediato)
timeout $DURATA_CATTURA tshark -i any -f "tcp port $SERVER_PORT" \
    -Y 'http.request.method and http.request.uri contains "login"' \
    -T fields -e frame.time_epoch -e ip.src -e http.request.uri -l 2>/dev/null | \
while IFS=$'\t' read -r timestamp_epoch ip_src uri; do
    
    COUNTER_PACKETS=$((COUNTER_PACKETS + 1))
    
    echo "[+] Pacchetto #$COUNTER_PACKETS: $ip_src → $uri"
    
    # Salva nel file di stato
    # date +%s: timestamp Unix corrente
    echo "$(date +%s)|$ip_src|$uri" >> "$STATE_FILE"
    
    # ANALISI: conta tentativi da questo IP nell'ultima finestra temporale
    # date +%s: timestamp Unix (secondi da epoch)
    CURRENT_TIME=$(date +%s)
    # $(( )) calcolo: tempo corrente - finestra = tempo minimo
    WINDOW_START=$((CURRENT_TIME - FINESTRA_SECONDI))
    
    # Conta tentativi login da questo IP nella finestra
    # awk:
    #   -F'|': separator pipe
    #   -v: passa variabili shell a awk
    #   $1>=window: timestamp maggiore o uguale a inizio finestra (-ge in bash)
    #   $2==ip: IP sorgente uguale a quello corrente
    #   END{print NR}: stampa numero di record processati
    TENTATIVI=$(awk -F'|' -v window="$WINDOW_START" -v ip="$ip_src" \
        '$1>=window && $2==ip {count++} END{print count+0}' "$STATE_FILE")
    
    echo "  → Tentativi da $ip_src negli ultimi $FINESTRA_SECONDI sec: $TENTATIVI"
    
    # CONTROLLO SOGLIA
    # -ge: greater or equal (>=)
    if [ $TENTATIVI -ge $SOGLIA_TENTATIVI ]; then
        echo ""
        echo "  [!!!] BRUTE-FORCE RILEVATO DA $ip_src!"
        echo "  [!!!] $TENTATIVI tentativi in $FINESTRA_SECONDI secondi"
        echo ""
        
        ALERT_COUNT=$((ALERT_COUNT + 1))
        
        # Controlla blacklist
        if controlla_blacklist "IP" "$ip_src"; then
            echo "  [!] IP già in blacklist (RECIDIVO, gravità CRITICA)"
            aggiungi_blacklist "IP" "$ip_src" "BRUTE_FORCE_LOGIN" \
                "CRITICA" 100 "Attacco brute-force: $TENTATIVI tentativi in ${FINESTRA_SECONDI}s"
        else
            echo "  [!] Primo rilevamento"
            aggiungi_blacklist "IP" "$ip_src" "BRUTE_FORCE_LOGIN" \
                "ALTA" 70 "Attacco brute-force: $TENTATIVI tentativi in ${FINESTRA_SECONDI}s"
        fi
        
        # AZIONE: Blocca IP con iptables (opzionale, richiede sudo)
        # Decommenta la riga seguente per abilitare blocco automatico
        # blocca_ip_con_iptables "$ip_src"
        
        # Log dettagliato
        {
            echo "═══════════════════════════════════════════"
            echo "ALERT BRUTE-FORCE - $(date '+%Y-%m-%d %H:%M:%S')"
            echo "═══════════════════════════════════════════"
            echo "IP attaccante:      $ip_src"
            echo "Tentativi:          $TENTATIVI"
            echo "Finestra:           $FINESTRA_SECONDI secondi"
            echo "Soglia:             $SOGLIA_TENTATIVI"
            echo "Ultimo URI:         $uri"
            echo ""
        } >> "$LOG_BRUTEFORCE"
        
    fi
    
    echo ""
done

# Report finale
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Pacchetti catturati: $COUNTER_PACKETS"
echo "[*] Alert brute-force: $ALERT_COUNT"
echo "[*] Log: $LOG_BRUTEFORCE"
echo "[*] State file: $STATE_FILE"
echo "================================================================================"
