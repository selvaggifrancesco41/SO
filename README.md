# PROGETTO_SERVER_BANCA

## Introduzione

Questo progetto simula un **server bancario GNU/Linux** con monitoraggio avanzato di 10 anomalie di sicurezza critiche rilevabili attraverso **flusso eventi in tempo reale**.

Tutti gli script leggono **solo** il file `logs/realtime_access.log` (scritto dal server) usando `tail -f`. **Nessun log storico o database** viene usato come input di analisi. Ogni script mantiene un **output minimalista** sul terminale e scrive alert in `blacklist.csv`. L'alert viene segnalato **al primo rilevamento** per focalizzare l'attenzione.

## Perché questo approccio?

Nel settore bancario e nelle infrastrutture critiche, la sicurezza non si basa solo su database storici. I problemi più subdoli sono quelli che **non violano formalmente alcuna regola** ma mostrano un comportamento **incoerente con i pattern attesi**.

Monitorando **un flusso eventi in tempo reale** (timestamp, account, IP, azione, importo, IBAN, durata sessione) e mantenendo una finestra temporale breve, è possibile rilevare:
- Anomalie **temporali** (accessi notturni)
- Anomalie **comportamentali** (pattern ripetitivi o simultanei)
- Anomalie **di coerenza** (operazioni da subnet non compatibili)
- Anomalie **lente** (molte operazioni piccole distribuite nel tempo)

**Database e log storici sono usati SOLO per scrivere alert, MAI per input.**

---

## Architettura

```
/workspaces/SO/
├── script/                           # 10 script di monitoraggio + orchestrator
│   ├── problema_01_aml_bonifici.sh          # Stream log: rilevamento riciclaggio
│   ├── problema_02_accessi_simultanei.sh    # Stream log: session hijacking
│   ├── problema_03_accessi_notturni.sh      # Stream log: anomalie temporali
│   ├── problema_04_atm_porte.sh             # Stream log: subnet ATM inattesa
│   ├── problema_05_bruteforce.sh            # Stream log: brute-force login
│   ├── problema_06_correlazione_rete.sh     # Stream log: IP pubblico inatteso
│   ├── problema_07_pattern_api.sh           # Stream log: automazione API
│   ├── problema_08_covert_channels.sh       # Stream log: importo=0
│   ├── problema_09_incoerenza_rete.sh       # Stream log: ATM esegue BONIFICO
│   ├── problema_10_low_slow.sh              # Stream log: operazioni piccole ripetute
│   └── run_problem.sh                       # Orchestrator (avvia monitor + test)
├── server/
│   └── server.py                    # Server Flask per test
├── data/
│   └── bank_logs.db                 # Database SQLite (storico, non usato per input)
├── logs/
│   ├── realtime_access.log          # Log centrale in tempo reale (input)
│   └── notifiche_email.txt          # Notifiche ai clienti (output)
├── blacklist.csv                    # Blacklist incrementale con risk_score
├── clienti_banca.csv                # Dati clienti (email, 2FA, etc)
└── README.md
```

## Esecuzione

**Esegui un singolo problema:**
```bash
cd /workspaces/SO/script
./run_problem.sh 1
```

Ogni esecuzione avvia il monitor e poi il relativo generatore di test.

## Comportamento comune

- Ogni alert aggiorna [blacklist.csv](blacklist.csv) con `risk_score` e `recidivita`.
- Quando il `risk_score` cumulato arriva a 100, lo `stato` diventa `BLOCKED`.
- Output a terminale **ridotto al minimo**.
- Gli script terminano al **primo alert** per focalizzare l'attenzione.
- P02 e P03 scrivono notifiche in [logs/notifiche_email.txt](logs/notifiche_email.txt).

---

## I 10 Problemi di Sicurezza (sintesi aggiornata)

Formato del flusso `logs/realtime_access.log`:
```
timestamp|customer_id|ip|azione|importo|iban|session_duration
```

Ogni monitor legge il flusso con `tail -f`, mantiene una finestra di 60s e scrive su [blacklist.csv](blacklist.csv) con rischio cumulativo.

### Sintesi per problema

1. **P01 AML bonifici**: se 5+ mittenti unici verso lo stesso IBAN in 60s → alert su account.
2. **P02 accessi simultanei**: se 3+ IP diversi per lo stesso account → alert + notifica 2FA.
3. **P03 accessi notturni**: se login in fascia 22-06 (o TEST_MODE) → alert + notifica.
4. **P04 ATM subnet**: IP in 192.168.30.x → alert.
5. **P05 bruteforce**: 5+ LOGIN dallo stesso IP → alert.
6. **P06 IP pubblico**: IP non RFC1918 → alert.
7. **P07 pattern API**: 10+ richieste dallo stesso IP → alert.
8. **P08 covert channels**: BONIFICO con importo=0 → alert.
9. **P09 incoerenza rete**: IP ATM (192.168.30.x) che fa BONIFICO → alert con risk 100.
10. **P10 low & slow**: 8+ operazioni con importo < 100 per lo stesso account → alert.

### Snippet tipico di monitor

```bash
tail -f "$REALTIME" 2>/dev/null | while IFS='|' read ts cid ip az imp iban sd; do
    [ $(($(date +%s) - START)) -ge 60 ] && break
    # ... condizioni specifiche ...
    add_blacklist_entry "ACCOUNT" "$cid" "AZIONE" "GRAVITA" "RISK" "ORIGINE" "NOTE"
    kill %1 2>/dev/null; exit 0
done &
wait $!
```
            # ISOLA IMMEDIATAMENTE con risk_score=100
            aggiungi_blacklist "IP" "$atm_ip" "ATM_ANOMALO" "CRITICA" 100 \
                "$conn_count connessioni simultanee - ISOLAMENTO IMMEDIATO"
            
            # Applica DROP con iptables
            iptables -A INPUT -s "$atm_ip" -j DROP 2>/dev/null
        fi
    fi
done <<< "$ATM_CONNECTIONS"
```

#### Comportamento dell'alert

1. Registra su `logs/atm_porte_alerts.log` con gravità **CRITICA**
2. Aggiunge l'IP in blacklist con `risk_score=100` e stato **"blocked"**
3. **L'ATM viene isolato immediatamente** (iptables DROP)
4. L'anomalia non richiede verifica ulteriore: il compromesso è attestato

---

### PROBLEMA 5: Brute-force sulle API di login

#### Contesto

Attacchi di **forza bruta** anche con rate limiting distribuito sono possibili. Un IP che effettua **10+ tentativi di login in soli 10 secondi** è un pattern di automazione.

#### Metodo di rilevamento

Lo script **cattura e analizza il traffico HTTP in tempo reale**:
- Usa `tshark` per catturare pacchetti HTTP verso la porta server
- Filtra solo i metodi HTTP POST verso `/login`
- Conta i tentativi di login per IP sorgente
- Se un IP effettua 10+ tentativi in ~10 secondi, segnala brute-force

```bash
# File: problema_05_bruteforce.sh
# Cattura traffico HTTP per 10 secondi
CADURE=10
CADURE_FILE="/tmp/bruteforce_$$.pcap"
timeout "$DURATA" tshark -i lo -f "tcp port $SERVER_PORT" -w "$CAPTURE_FILE" -q 2>/dev/null

# Analizza il pcap per richieste HTTP POST /login
LOGIN_ATTEMPTS=$(tshark -r "$CAPTURE_FILE" \
    -Y 'http.request.method == "POST" && http.request.uri contains "/login"' \
    -T fields -e ip.src 2>/dev/null)

# Conta tentativi per IP
while read -r src_ip; do
    if [ -n "$src_ip" ]; then
        count=$(echo "$LOGIN_ATTEMPTS" | grep -c "^$src_ip$")
        
        # Se 10+ tentativi
        if [ "$count" -ge 10 ]; then
            # Brute-force rilevato
            aggiungi_blacklist "IP" "$src_ip" "BRUTEFORCE_LOGIN" "ALTA" 70 \
                "$count tentativi in ${DURATA}s - BRUTE-FORCE RILEVATO"
            blocca_ip_se_necessario "$src_ip" 70
        fi
    fi
done <<< "$(echo "$LOGIN_ATTEMPTS" | sort -u)"

rm -f "$CAPTURE_FILE"
```

#### Comportamento dell'alert

1. Registra su `logs/bruteforce_alerts.log` il numero di tentativi
2. Aggiunge l'IP in blacklist con `risk_score=70`
3. Effetto deterrente: attacchi successivi dall'IP vengono rifiutati
4. Se risk_score >= 100, blocca

---

### PROBLEMA 6: Correlazione rete e subnet anomale

#### Contesto

Un'infrastruttura bancaria ha **subnet separate**: clienti pubblici su range privati, staff interno su segment specifico. Un login da subnet "inattesa" (es. da range pubblico) è anomalo.

#### Metodo di rilevamento

Lo script **monitora la topologia di rete locale e IP pubblici**:
- Usa `ss -tn state established` per ottenere connessioni attive
- Usa `ip addr show` per raccogliere le interfacce e subnet locali
- Usa `arp -a` per visualizzare i dispositivi sulla rete locale
- Usa `ping` per verificare latenza e raggiungibilità di IP anomali
- Se un IP è pubblico o estraneo alle subnet attese, segnala

```bash
# File: problema_06_correlazione_rete.sh
# Raccolta topologia di rete: interfacce locali
INTERFACCE=$(ip addr show | grep "inet " | awk '{print $2}' | grep -v "127.0.0.1")

# Raccolta ARP cache
ARP_CACHE=$(arp -a | grep -E "192.168|10\.")

# Connessioni al server
CONNESSIONI=$(ss -tn state established | grep ":$SERVER_PORT " | awk '{print $4}' | cut -d: -f1 | sort -u)

while read -r suspicious_ip; do
    if is_private_ip "$suspicious_ip"; then
        # IP privato (atteso)
        continue
    else
        # IP PUBBLICO O INATTESO -> anomalia
        LATENCY=$(ping -c 1 -W 1 "$suspicious_ip" 2>/dev/null | grep "time=" | awk -F'time=' '{print $2}' | cut -d' ' -f1)
        
        aggiungi_blacklist "IP" "$suspicious_ip" "SUBNET_ANOMALA" "MEDIA" 50 \
            "Login da IP pubblico inatteso: $suspicious_ip; latenza: ${LATENCY}ms"
    fi
done <<< "$CONNESSIONI"
```

#### Comportamento dell'alert

1. Registra su `logs/correlazione_alerts.log`
2. Aggiunge l'IP in blacklist con `risk_score=50`
3. Se risk_score >= 100, blocca

---

### PROBLEMA 7: Pattern anomali nell'uso API

#### Contesto

Ogni tipo di client (app mobile, ATM, web portal) ha un **pattern di utilizzo caratteristico**. Un bot esegue richieste regolari e meccaniche; un utente umano esegue operazioni sparse nel tempo. **Troppe operazioni in troppo poco tempo** indica automazione.

#### Metodo di rilevamento

Lo script **cattura e analizza il traffico HTTP in tempo reale**:
- Usa `tshark` per catturare pacchetti HTTP verso la porta server
- Analizza le richieste HTTP per endpoint univoci
- Conta il numero di richieste per IP sorgente in una finestra temporale
- Se un IP effettua troppe richieste HTTP in poco tempo, segnala pattern anomalo (automazione)

```bash
# File: problema_07_pattern_api.sh
# Cattura traffico HTTP per 20 secondi
DURATION_CAPTURE=20
CADURE_FILE="/tmp/api_capture_$$.pcap"
timeout "$DURATION_CAPTURE" tshark -i lo -f "tcp port $SERVER_PORT" -w "$CAPTURE_FILE" -q 2>/dev/null

# Analizza le richieste HTTP
tshark -r "$CAPTURE_FILE" \
    -Y "http.request.method" \
    -T fields -e frame.time -e ip.src -e http.request.method -e http.request.uri > "$TSHARK_OUTPUT"

# Conta richieste per IP
while IFS=$'\t' read -r timestamp src_ip method uri; do
    if [ -n "$src_ip" ]; then
        count=$((${REQUEST_COUNTS[$src_ip]:-0} + 1))
        REQUEST_COUNTS[$src_ip]=$count
    fi
done < "$TSHARK_OUTPUT"

# Se troppe richieste -> automazione sospetta
for ip in "${!REQUEST_COUNTS[@]}"; do
    count=${REQUEST_COUNTS[$ip]}
    if [ "$count" -ge 15 ]; then
        aggiungi_blacklist "IP" "$ip" "PATTERN_API_ABUSE" "MEDIA" 40 \
            "$count richieste HTTP in poco tempo - AUTOMAZIONE SOSPETTA"
    fi
done

rm -f "$CAPTURE_FILE" "$TSHARK_OUTPUT"
```

#### Comportamento dell'alert

1. Registra su `logs/pattern_api_alerts.log`
2. Aggiunge l'IP in blacklist con `risk_score=40`
3. Se risk_score >= 100, blocca

---

### PROBLEMA 8: Covert channels tramite operazioni fake

#### Contesto

Un **canale covert** è comunicazione nascosta dentro traffico legittimo. Nel banking, **operazioni a importo=0** sono sospette: non sono vere transazioni, but possono essere "impulsi" per beacon C2. Un pattern di operazioni fake regolari (1 ogni 10 secondi) è un segnale di automazione.

#### Metodo di rilevamento

Lo script **cattura pacchetti anomali che indicano covert channels**:
- Usa `tcpdump` per catturare pacchetti sulla localhost
- Usa `tshark` per analizzare il pcap e cercare pattern anomali:
  - Pacchetti ACK-only senza payload (flag 0x10)
  - Pacchetti con zero-length payload suggestivi di comunicazione nascosta
- Conta pattern anomali per IP sorgente
- Inoltre, analizza il log realtime per operazioni a `importo=0` (fake operations)
- Se pattern anomali o troppe operazioni fake, segnala covert channel

```bash
# File: problema_08_covert_channels.sh
# Cattura pacchetti con tcpdump
timeout "$DURATION_CAPTURE" tcpdump -i lo "tcp port $SERVER_PORT" -w "$CAPTURE_FILE" -q

# Analizza con tshark per pattern anomali
tshark -r "$CAPTURE_FILE" -T fields -e ip.src -e tcp.flags -e tcp.len > "$TSHARK_ANALYSIS"

# Conta ACK-only packets (flags=0x10) e zero-payload
while IFS=$'\t' read -r src_ip flags payload_len; do
    if [ "$flags" = "0x10" ]; then
        ACK_ONLY_PACKETS[$src_ip]=$((${ACK_ONLY_PACKETS[$src_ip]:-0} + 1))
    fi
    if [ "$payload_len" = "0" ] && [ "$flags" != "0x02" ]; then
        ZERO_PAYLOAD[$src_ip]=$((${ZERO_PAYLOAD[$src_ip]:-0} + 1))
    fi
done < "$TSHARK_ANALYSIS"

# Se pattern anomali rilevati
for ip in "${!ACK_ONLY_PACKETS[@]}"; do
    count=${ACK_ONLY_PACKETS[$ip]}
    if [ "$count" -ge 20 ]; then
        # CONSEGUENZE CRITICHE
        aggiungi_blacklist "IP" "$ip" "COVERT_ACK_FLOOD" "CRITICA" 100 \
            "Flood ACK patterns rilevati - Canale covert - API SOSPESE"
        sospendi_api "$ip"
    fi
done
```

#### Comportamento dell'alert

1. Registra operazioni bloccate in `logs/operazioni_bloccate_zero.log`
2. **Sospende tutte le API** per l'IP e scrive su `logs/api_sospese.log`
3. Aggiunge l'IP in blacklist con `risk_score=100` e azione **"API_SOSPESA"**
4. Stato diventa **"blocked"** e viene applicato iptables
5. L'IP è isolato dalla rete

---

### PROBLEMA 9: Incoerenza rete e tipo operazione

#### Contesto

Nel mondo reale, non tutte le operazioni sono lecite solo perché formalmente valide. Un **bonifico da un ATM** è strano (ATM fanno prelievi, non bonifici). Un **accesso amministrativo da IP pubblico** è sospetto (admin dovrebbero usare VPN). Una **operazione incoerente con il tipo di client** è anomalia critica.

#### Metodo di rilevamento

Lo script **classifica i client in base al tipo di rete e verifica coerenza operazioni**:
- Usa `dig +short -x <IP>` per reverse DNS lookup e classificare il client type (ATM, PC_CLIENT, MOBILE, etc.)
- Usa `traceroute` per analizzare il percorso di rete fino al client
- Legge il log realtime per estrarre le operazioni eseguite
- Verifica se l'operazione è coerente con il tipo di client rilevato
- Se mismatch (es. BONIFICO da ATM, o PRELIEVO da ADMIN), segnala incoerenza

```bash
# File: problema_09_incoerenza_rete.sh
# Classificazione client type da IP
classifica_client() {
    local ip="$1"
    
    # Reverse lookup con dig
    hostname=$(dig +short -x "$ip" | head -1)
    
    if [[ "$hostname" =~ [Aa][Tt][Mm]|bancomat ]]; then
        echo "ATM"
    elif [[ "$hostname" =~ [Cc]lient|[Pp]c|[Ww]eb ]]; then
        echo "PC_CLIENT"
    elif [[ "$hostname" =~ [Mm]obile|[Aa]pp ]]; then
        echo "MOBILE"
    else
        echo "UNKNOWN"
    fi
}

# Leggi operazioni dal log e verifica coerenza
while IFS='|' read -r timestamp customer_id operation ip_source; do
    client_type=$(classifica_client "$ip_source")
    
    case "$client_type|$operation" in
        "ATM|BONIFICO")
            # ATM non dovrebbe fare bonifici
            aggiungi_blacklist "IP" "$ip_source" "INCOERENZA_RETE" "ALTA" 70 \
                "ATM tentò BONIFICO - INCOERENTE"
            ;;
        "ADMIN|PRELIEVO")
            # Admin non dovrebbe fare prelievi
            aggiungi_blacklist "IP" "$ip_source" "INCOERENZA_RETE" "ALTA" 70 \
                "ADMIN tentò PRELIEVO - INCOERENTE"
            ;;
    esac
done < <(tail -50 "$LOG_REALTIME" | grep -E "BONIFICO|ATM|PRELIEVO|ONLINE" | 
         awk -F',' '{print $1 "|" $3 "|" $4 "|" $5}')
```

#### Comportamento dell'alert

1. Registra su `logs/incoerenza_rete_alerts.log`
2. Aggiunge l'IP in blacklist con `risk_score=70`
3. La transazione è **sospesa temporaneamente**
4. Se risk_score >= 100, blocca

---

### PROBLEMA 10: Low & Slow ad alto impatto

#### Contesto

Non tutti gli attacchi sono rumorosi. Gli attacchi **lenti e distribuiti** (low & slow) non superano mai soglie istantanee, ma **degradano il servizio progressivamente nel tempo**. Un IP con 1 richiesta ogni 20 secondi per 1 ora = 180 richieste complessivamente, che non attira suspicio istantanea but causa degrado.

#### Metodo di rilevamento

Lo script **monitora le connessioni TCP stagnanti in tempo reale**:
- Usa `ss -tno` per ottenere connessioni TCP con statistiche dettagliate (Recv-Q, Send-Q)
- Traccia connessioni che rimangono stabilizzate per più di 20 secondi
- Monitora il volume di dati trasmessi (Recv-Q + Send-Q)
- Se una connessione è prolungata MA ha pochi dati trasmessi, indica attacco low&slow
- Se Send-Q mostra ristagno (> 5KB per più check), indica possibile stall

```bash
# File: problema_10_low_slow.sh
# Monitora connessioni TCP con estadísticas
while true; do
    SS_OUTPUT=$(ss -tno 2>/dev/null | grep ":$SERVER_PORT " | awk '{print $5, $6, $7}')
    
    while read -r source_addr recv_q send_q; do
        source_ip=$(echo "$source_addr" | cut -d: -f1)
        
        if [ -z "${CONNESSIONE_START_TIME[$source_ip]}" ]; then
            # Prima occorrenza: registra
            CONNESSIONE_START_TIME[$source_ip]=$TEMPO_ATTUALE
            CONNESSIONE_BYTES[$source_ip]=$((recv_q + send_q))
        else
            # Connessione attiva: verifica durata e volume
            DURATA=$((TEMPO_ATTUALE - CONNESSIONE_START_TIME[$source_ip]))
            BYTES_TOTALI=$((recv_q + send_q))
            
            # Rilevamento low&slow:
            if [ "$DURATA" -gt 20 ] && [ "$BYTES_TOTALI" -lt 1024 ]; then
                # Connessione prolungata con pochi dati
                aggiungi_blacklist "IP" "$source_ip" "LOW_SLOW_ATTACK" "MEDIA" 60 \
                    "Connessione prolungata (${DURATA}s) con dati insufficienti (${BYTES_TOTALI}B)"
            fi
            
            # Se Send-Q stagnante
            if [ "$send_q" -gt 5120 ]; then
                aggiungi_blacklist "IP" "$source_ip" "LOW_SLOW_SEND_STALL" "MEDIA" 50 \
                    "Buffer Send-Q stagnante (${send_q}B)"
            fi
        fi
    done <<< "$SS_OUTPUT"
    
    sleep 5
done
```

#### Comportamento dell'alert

1. Registra su `logs/low_slow_attacks.log` il rate per tracciamento
2. Aggiunge l'IP in blacklist con `risk_score=60`
3. **Risk_score accumula nel tempo** per elementi recidivi
4. Quando il rischio supera 100, **blocca proattivamente** prima che il degrado sia severo

---

## Note operative

- **Metodo P01-P02**: Real-time log analysis (tail + grep/awk) per rilevamento veloce
- **Metodo P03-P10**: Network monitoring commands per osservazione diretta del traffico:
  - P03: `ss -tn state established` per connessioni TCP, `host` per reverse DNS
  - P04: `netstat -tn` per monitoraggio subnet ATM
  - P05: `tshark` per cattura HTTP e conteggio tentativi /login
  - P06: `ip addr`, `arp -a`, `ping` per topologia rete
  - P07: `tshark` per analisi richieste HTTP e pattern API
  - P08: `tcpdump` + `tshark` per pacchetti anomali (ACK-only, zero-payload)
  - P09: `dig` per reverse lookup client classification, `traceroute` per path analysis
  - P10: `ss -tno` per monitoraggio buffer Send-Q e connessioni stagnanti
- **Output**: Redirect stdout a /dev/null, usa FD3 per output critico
- **Logging**: Dettagli completi in file specializzati per ogni problema
- **Escalation**: Risk_score accumula per elementi recidivi
- **Blocco automatico**: A risk_score >= 100 viene applicato `iptables DROP`
- **Priorità**: Terminazione al primo alert per focalizzare l'attenzione

