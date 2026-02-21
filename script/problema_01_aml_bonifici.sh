#!/bin/bash

# PROBLEMA 1: RILEVAMENTO FLUSSI ANOMALI BONIFICI (AML) - NETWORK MONITORING
#
# SCOPO: Intercettare traffico HTTP verso /bonifico in tempo reale e rilevare
#        pattern sospetti di money laundering (molti mittenti verso stesso IBAN)
#
# METODO: Cattura pacchetti di rete con tcpdump/tshark, estrae payload HTTP,
#         analizza pattern dei bonifici mentre avvengono
#
# DATABASE: Usato SOLO per lookup dati cliente specifico (se serve verificare se esiste)
# BLACKLIST: Controlla se IBAN destinatario già segnalato in precedenza
#
# DIPENDENZE: tcpdump o tshark, grep, awk, sqlite3 (per lookup puntuali)

# Percorsi file di configurazione e log
BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_AML="/workspaces/SO/logs/aml_alerts.log"
STATE_FILE="/workspaces/SO/logs/aml_state.tmp"  # File temporaneo per tracciare bonifici
DB_PATH="/workspaces/SO/data/eventi_bancari.db"  # Solo per lookup puntuali

# Parametri soglia rilevamento
SOGLIA_MITTENTI_UNICI=5     # Max mittenti distinti verso stesso IBAN
FINESTRA_SECONDI=300        # Finestra temporale di analisi (5 minuti)
SERVER_PORT=8000            # Porta del server Flask da monitorare

# Crea directory per log se non esistono
# mkdir -p: crea directory inclusi path intermedi, non fallisce se già esiste
mkdir -p $(dirname "$LOG_AML")
mkdir -p $(dirname "$STATE_FILE")

# FUNZIONE: controlla_blacklist - Verifica se elemento già segnalato
# ARG1: tipo_elemento (es. "IBAN", "IP", "PORTA")
# ARG2: elemento (valore da cercare, es. "IT60X0542811101000000123456")
# RETURN: exit code 0 se trovato, 1 se non trovato
# TECNICA: grep -q esegue ricerca silenziosa (quiet), ritorna solo exit code
#          ^.* = qualsiasi carattere all'inizio riga (regex anchor)
#          2>/dev/null = redirige stderr a /dev/null per sopprimere errori
controlla_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    
    grep -q "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH" 2>/dev/null
    return $?
}

# FUNZIONE: get_risk_score - Recupera punteggio rischio corrente da blacklist
# ARG1: tipo_elemento
# ARG2: elemento
# OUTPUT: Stampa risk_score (colonna 7 CSV) oppure 0 se non trovato
# TECNICA: awk -F',' imposta delimitatore di campo a virgola
#          -v tipo="..." assegna variabile awk da shell
#          $3==tipo confronta terza colonna con variabile tipo
#          {print $7} stampa settima colonna (risk_score)
#          tail -1 prende solo ultima occorrenza (la più recente)
get_risk_score() {
    local tipo_elemento="$1"
    local elemento="$2"
    
    local score=$(awk -F',' -v tipo="$tipo_elemento" -v elem="$elemento" \
        '$3==tipo && $4==elem {print $7}' "$BLACKLIST_PATH" | tail -1)
    
    # Test -z: verifica se stringa è zero-length (vuota)
    # Se vuota significa che elemento non trovato, ritorna 0
    if [ -z "$score" ]; then
        echo 0
    else
        echo "$score"
    fi
}

# FUNZIONE: aggiungi_blacklist - Inserisce/aggiorna elemento in blacklist
# ARG1: tipo_elemento (IBAN, IP, PORTA, USER_ID, ATM_ID)
# ARG2: elemento (valore specifico)
# ARG3: azione (tipo di azione rilevata, es. "BONIFICO_ANOMALO")
# ARG4: gravita (BASSA, MEDIA, ALTA, CRITICA)
# ARG5: risk_score (punteggio da aggiungere, es. 50)
# ARG6: note (descrizione dettagliata dell'anomalia)
# COMPORTAMENTO: Se elemento già presente (recidivo), incrementa risk_score e recidivita
#                Se nuovo, lo aggiunge con recidivita=1
aggiungi_blacklist() {
    local tipo_elemento="$1"
    local elemento="$2"
    local azione="$3"
    local gravita="$4"
    local risk_score="$5"
    local note="$6"
    
    # date '+FORMAT': genera timestamp formattato
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Controlla se elemento già presente in blacklist
    if controlla_blacklist "$tipo_elemento" "$elemento"; then
        # RECIDIVO: lo stesso elemento è stato già segnalato in passato
        local current_risk=$(get_risk_score "$tipo_elemento" "$elemento")
        local new_risk=$((current_risk + risk_score))
        local new_recidivita=$(($(grep -c "^.*,${tipo_elemento},${elemento}," "$BLACKLIST_PATH") + 1))
        
        # >>: append to file (non sovrascrive, aggiunge alla fine)
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},${new_recidivita},${new_risk},blacklisted,AML_BONIFICI,${note} [RECIDIVO]" >> "$BLACKLIST_PATH"
    else
        # NUOVO ELEMENTO: prima segnalazione, recidivita=1
        echo "${timestamp},${tipo_elemento},${elemento},${azione},${gravita},1,${risk_score},blacklisted,AML_BONIFICI,${note}" >> "$BLACKLIST_PATH"
    fi
}

# ANALISI TRAFFICO DI RETE IN TEMPO REALE
echo "================================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] AVVIO MONITORAGGIO RETE - AML Bonifici"
echo "================================================================================" | tee -a "$LOG_AML"

# Verifica se tshark è installato (Wireshark command-line)
# command -v: restituisce path del comando se esiste, altrimenti vuoto
# /dev/null: discard output, vogliamo solo exit code
if ! command -v tshark &> /dev/null; then
    echo "[!] ERRORE: tshark non installato"
    echo "[*] Installalo con: sudo apt-get install tshark"
    echo "[*] Alternativa: tcpdump (richiede parsing manuale)"
    exit 1
fi

# Inizializza file di stato per tracciare bonifici in memoria
# > (redirect): crea/sovrascrive file vuoto
# Format: timestamp|customer_id_mittente|iban_destinatario|importo
echo "# AML State File - $(date)" > "$STATE_FILE"

echo "[*] Cattura traffico su porta $SERVER_PORT..."
echo "[*] Filtro: richieste HTTP POST /bonifico"
echo "[*] Premi Ctrl+C per terminare"
echo ""

# CATTURA PACCHETTI CON TSHARK
# -i any: cattura su tutte le interfacce di rete (-i = interface)
# -f "tcp port 8000": BPF filter, solo pacchetti TCP su porta 8000
# -Y "http.request.method == POST": display filter Wireshark, solo POST
# -T fields: output come campi separati
# -e frame.time: timestamp del frame
# -e ip.src: IP sorgente del pacchetto
# -e http.request.uri: URI della richiesta HTTP (es. /bonifico?customer_id=...)
# -e http.file_data: payload body della richiesta POST
# -l: line-buffered output (stampa riga per riga senza buffer)

COUNTER=0
TIMESTAMP_START=$(date +%s)

# Timeout dopo FINESTRA_SECONDI per analizzare i dati raccolti
timeout $FINESTRA_SECONDI tshark -i any -f "tcp port $SERVER_PORT" \
    -Y 'http.request.method == "POST" and http.request.uri contains "bonifico"' \
    -T fields -e frame.time -e ip.src -e http.request.uri -e http.file_data -l 2>/dev/null | \
while IFS=$'\t' read -r timestamp ip_src uri payload; do
    
    # Incrementa contatore pacchetti catturati
    COUNTER=$((COUNTER + 1))
    
    echo "[+] Pacchetto #$COUNTER intercettato da $ip_src"
    
    # ESTRAZIONE PARAMETRI dalla URI
    # URI esempio: /bonifico?customer_id=1001&iban_dest=IT60X...&importo=1500
    
    # grep -oP: -o stampa solo match, -P usa Perl regex
    # [?&]: carattere ? oppure &
    # customer_id=\K: \K scarta tutto prima di questo punto
    # [^&]*: qualsiasi carattere tranne &, ripetuto (* = 0 o più volte)
    customer_id=$(echo "$uri" | grep -oP 'customer_id=\K[^&]*')
    iban_dest=$(echo "$uri" | grep -oP 'iban_dest=\K[^&]*')
    importo=$(echo "$uri" | grep -oP 'importo=\K[^&]*')
    
    # Test -n: controlla se stringa NON vuota (opposto di -z)
    if [ -n "$customer_id" ] && [ -n "$iban_dest" ] && [ -n "$importo" ]; then
        echo "  Customer: $customer_id → IBAN: $iban_dest, €$importo"
        
        # Salva nel file di stato
        echo "$(date +%s)|$customer_id|$iban_dest|$importo" >> "$STATE_FILE"
        
        # VERIFICA PATTERN ANOMALO: conta quanti mittenti unici verso questo IBAN
        # awk -F'|': usa pipe come field separator
        # $3==iban_dest: filtra righe dove campo 3 (IBAN destinatario) corrisponde
        # {print $2}: stampa campo 2 (customer_id mittente)
        # sort -u: ordina e elimina duplicati (-u = unique)
        # wc -l: conta numero di righe risultanti
        mittenti_unici=$(awk -F'|' -v iban="$iban_dest" '$3==iban {print $2}' "$STATE_FILE" | sort -u | wc -l)
        
        echo "  → Mittenti unici verso $iban_dest: $mittenti_unici"
        
        # CONTROLLO SOGLIA
        # -ge: greater than or equal (>=)
        if [ "$mittenti_unici" -ge "$SOGLIA_MITTENTI_UNICI" ]; then
            echo ""
            echo "  [!!!] ALERT AML: IBAN $iban_dest riceve da $mittenti_unici mittenti!"
            echo ""
            
            # Verifica se IBAN già in blacklist
            if controlla_blacklist "IBAN" "$iban_dest"; then
                echo "  [!] IBAN già in blacklist - RECIDIVO"
                aggiungi_blacklist "IBAN" "$iban_dest" "FLUSSO_AML_REAL_TIME" \
                    "CRITICA" 80 "Rilevato in tempo reale: $mittenti_unici mittenti in $FINESTRA_SECONDI secondi"
            else
                echo "  [!] Primo rilevamento - NUOVO"
                aggiungi_blacklist "IBAN" "$iban_dest" "FLUSSO_AML_REAL_TIME" \
                    "ALTA" 50 "Rilevato in tempo reale: $mittenti_unici mittenti in $FINESTRA_SECONDI secondi"
            fi
            
            # Log dettagliato dell'alert
            {
                echo "═══════════════════════════════════════════"
                echo "ALERT AML - $(date '+%Y-%m-%d %H:%M:%S')"
                echo "═══════════════════════════════════════════"
                echo "IBAN Beneficiario: $iban_dest"
                echo "Mittenti unici:    $mittenti_unici"
                echo "Soglia:            $SOGLIA_MITTENTI_UNICI"
                echo "Ultimo importo:    €$importo"
                echo "Ultimo mittente:   $customer_id"
                echo "IP origine:        $ip_src"
                echo ""
            } >> "$LOG_AML"
        fi
    fi
    
    echo ""
done

# Al termine della cattura (timeout o Ctrl+C)
echo ""
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Pacchetti analizzati: $COUNTER"
echo "[*] Log: $LOG_AML"
echo "[*] State file: $STATE_FILE"
echo "================================================================================"
