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

# Percorsi file di configurazione e log
BLACKLIST_PATH="/workspaces/SO/blacklist.csv"
LOG_AML="/workspaces/SO/logs/aml_alerts.log"
STATE_FILE="/workspaces/SO/logs/aml_state.tmp"  # File temporaneo per tracciare bonifici
DB_PATH="/workspaces/SO/data/bank_logs.db"  # Solo per lookup puntuali

# Parametri soglia rilevamento
SOGLIA_MITTENTI_UNICI=5     # Max mittenti distinti verso stesso IBAN
FINESTRA_SECONDI=60         # Finestra temporale di analisi (1 minuto)
SERVER_PORT=8000            # Porta del server Flask da monitorare

# Crea directory per log se non esistono
# mkdir -p: crea directory inclusi path intermedi, non fallisce se già esiste
mkdir -p $(dirname "$LOG_AML")
mkdir -p $(dirname "$STATE_FILE")

# Array per tracciare IBAN già segnalati in questa sessione
declare -A SEGNALATI

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
# Messaggio minimo di avvio
log "P01 start"
# Log dettagliato su file
echo "================================================================================" >> "$LOG_AML"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] AVVIO MONITORAGGIO RETE - AML Bonifici" >> "$LOG_AML"
echo "================================================================================" >> "$LOG_AML"

# Inizializza file di stato per tracciare bonifici in memoria
# > (redirect): crea/sovrascrive file vuoto
# Format: customer_id_mittente|iban_destinatario|importo|timestamp
> "$STATE_FILE"

REALTIME_LOG="/workspaces/SO/logs/realtime_access.log"

# Output verbose silenziato da exec 1>/dev/null
echo "[*] Monitoraggio del log in tempo reale: $REALTIME_LOG"
echo "[*] Filtro: azione BONIFICO"
echo "[*] Finestra temporale: $FINESTRA_SECONDI secondi"
echo "[*] Soglia mittenti unici per IBAN: $SOGLIA_MITTENTI_UNICI"
echo "[*] Premi Ctrl+C per terminare"
echo ""

COUNTER=0
TIMESTAMP_START=$(date +%s)
LAST_POSITION=0
ALERT_COUNT=0

# Monitora il file di log per FINESTRA_SECONDI
while [ $ALERT_COUNT -eq 0 ]; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - TIMESTAMP_START))
    
    # Esci se superata la finestra temporale
    if [ $ELAPSED -ge $FINESTRA_SECONDI ]; then
        break
    fi
    
    # Leggi nuove righe dal log (solo BONIFICO)
    # Format log: timestamp|customer_id|ip|azione|importo|iban|session_duration
    # Usa process substitution < <(...) per evitare subshell con pipe
    if [ -f "$REALTIME_LOG" ]; then
        while IFS='|' read -r timestamp customer_id ip_src azione importo iban_dest session_duration; do
            
            COUNTER=$((COUNTER + 1))
            LAST_POSITION=$((LAST_POSITION + 1))
            
            echo "[+] Bonifico #$COUNTER da customer $customer_id"
            
            # Verifica parametri validi
            if [ -n "$customer_id" ] && [ -n "$iban_dest" ] && [ -n "$importo" ]; then
                echo "  IP: $ip_src → IBAN: $iban_dest, €$importo"
                
                # Salva nel file di stato
                echo "$customer_id|$iban_dest|$importo|$(date +%s)" >> "$STATE_FILE"
                
                # VERIFICA PATTERN ANOMALO: conta quanti mittenti unici verso questo IBAN
                mittenti_unici=$(awk -F'|' -v iban="$iban_dest" '$2==iban {print $1}' "$STATE_FILE" | sort -u | wc -l)
                
                echo "  → Mittenti unici verso $iban_dest: $mittenti_unici"
                
                # CONTROLLO SOGLIA
                if [ "$mittenti_unici" -ge "$SOGLIA_MITTENTI_UNICI" ]; then
                    
                    # Segnala solo se non già fatto in questa sessione
                    if [ -z "${SEGNALATI[$iban_dest]}" ]; then
                        SEGNALATI[$iban_dest]=1
                        
                        # Messaggio minimo di alert
                        log "P01 alert $iban_dest"

                        echo ""
                        echo "  [!!!] ALERT AML: IBAN $iban_dest riceve da $mittenti_unici mittenti!"
                        echo ""
                        
                        # Estrai primo mittente coinvolto (rappresentante del pattern)
                        primo_mittente=$(awk -F'|' -v iban="$iban_dest" '$2==iban {print $1}' "$STATE_FILE" | sort -u | head -1)
                        
                        # Aggiungi solo UN mittente rappresentativo alla blacklist
                        if [ -n "$primo_mittente" ]; then
                            if controlla_blacklist "ACCOUNT" "$primo_mittente"; then
                                echo "  [!] Customer $primo_mittente già in blacklist - RECIDIVO"
                                aggiungi_blacklist "ACCOUNT" "$primo_mittente" "FLUSSO_AML_REAL_TIME" \
                                    "CRITICA" 80 "Partecipa a schema AML verso IBAN $iban_dest; totale mittenti: $mittenti_unici"
                            else
                                echo "  [!] Customer $primo_mittente aggiunto a blacklist - NUOVO"
                                aggiungi_blacklist "ACCOUNT" "$primo_mittente" "FLUSSO_AML_REAL_TIME" \
                                    "ALTA" 50 "Partecipa a schema AML verso IBAN $iban_dest; totale mittenti: $mittenti_unici"
                            fi
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
                        
                        ALERT_COUNT=$((ALERT_COUNT + 1))
                        break  # Exit immediatamente dopo primo alert
                    else
                        echo "  → IBAN già segnalato in questo ciclo (SKIP)"
                    fi
                fi
            fi
            
            echo ""
        done < <(tail -n +$((LAST_POSITION + 1)) "$REALTIME_LOG" 2>/dev/null | grep "|BONIFICO|")
    fi
    
    # Attendi prima del prossimo check
    sleep 2
done

# Al termine della cattura
# Report finale (verbose, silenziato)
echo ""
echo "================================================================================"
echo "[✓] Monitoraggio completato"
echo "[*] Transazioni analizzate: $COUNTER"
echo "[*] Alert generati: $ALERT_COUNT"
if [ $ALERT_COUNT -eq 0 ]; then
    echo "[*] Nessun pattern AML rilevato in ${FINESTRA_SECONDI}s"
fi
echo "[*] Log: $LOG_AML"
echo "[*] State file: $STATE_FILE"
echo "================================================================================"

# Messaggio minimo di fine
log "P01 done"
