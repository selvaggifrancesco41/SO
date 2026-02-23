# PROGETTO_SERVER_BANCA

## Introduzione

Questo progetto simula un **server bancario GNU/Linux** con monitoraggio avanzato di 10 anomalie di sicurezza critiche rilevabili attraverso:
- **Analisi real-time di log** per rilevamenti veloci (P01, P02)
- **Comandi di rete in tempo reale** per monitoraggio diretto di connessioni, pacchetti e topologia (P03-P10)

Tutti i script utilizzano **comandi GNU/Linux standard** (`ss`, `netstat`, `tshark`, `tcpdump`, `dig`, `traceroute`, `arp`, `ping`, `ip`) come sorgente primaria di analisi, non interrogare il database. Ogni script mantiene un **output minimalista** sul terminale e registra dettagli completi in log specializzati. L'alert viene segnalato **al primo rilevamento** per focalizzare l'attenzione.

## Perché questo approccio?

Nel settore bancario e nelle infrastrutture critiche, la sicurezza non si basa più solo su database storici. I problemi più subdoli sono quelli che **non violano formalmente alcuna regola** ma mostrano un comportamento **incoerente con i pattern di rete attesi**.

Monitorando **log in tempo reale** e **osservando direttamente il traffico e le connessioni di rete**, è possibile rilevare:
- Anomalie **temporali** (accessi anomali in orari inaspettati, rilevabili da ss/netstat)
- Anomalie **comportamentali** (pattern di utilizzo insoliti, visibili via tshark/tcpdump)
- Anomalie **di schema** (operazioni incoerenti con il tipo di client, verificabili con dig/traceroute)
- Anomalie **lente** (attacchi low-and-slow, tracciabili monitorando socket con ss -tno)
- Anomalie **di rete** (subnet inattese, IP pubblici inaspettati, visibili da ss/arp/ip)

---

## Architettura

```
/workspaces/SO/
├── script/                           # 10 script di monitoraggio + orchestrator
│   ├── problema_01_aml_bonifici.sh          # Real-time log: rilevamento riciclaggio
│   ├── problema_02_accessi_simultanei.sh    # Real-time log: session hijacking
│   ├── problema_03_accessi_notturni.sh      # Network: ss + host - anomalie temporali
│   ├── problema_04_atm_porte.sh             # Network: netstat - isolamento ATM
│   ├── problema_05_bruteforce.sh            # Network: tshark - brute-force login
│   ├── problema_06_correlazione_rete.sh     # Network: ip,arp,ping - anomalie subnet
│   ├── problema_07_pattern_api.sh           # Network: tshark - automazione API
│   ├── problema_08_covert_channels.sh       # Network: tcpdump - canali covert
│   ├── problema_09_incoerenza_rete.sh       # Network: dig,traceroute - incoerenza
│   ├── problema_10_low_slow.sh              # Network: ss -tno - attacchi lenti
│   └── run_problem.sh                       # Orchestrator
├── server/
│   └── server.py                    # Server Flask per test
├── data/
│   └── bank_logs.db                 # Database SQLite (storico, non usato per rilevamento)
├── logs/
│   ├── realtime_access.log          # Log centrale in tempo reale
│   ├── aml_alerts.log
│   ├── simultanei_alerts.log
│   ├── notturni_alerts.log          # P03: anomalie notturne
│   ├── atm_porte_alerts.log         # P04: ATM anomali
│   ├── bruteforce_alerts.log        # P05: brute-force
│   ├── correlazione_alerts.log      # P06: subnet anomale
│   ├── pattern_api_alerts.log       # P07: pattern API
│   ├── covert_channels_alerts.log   # P08: covert channels
│   ├── incoerenza_alerts.log        # P09: incoerenza rete
│   ├── low_slow_alerts.log          # P10: low&slow
│   ├── notifiche_email.txt          # Notifiche ai clienti
│   ├── operazioni_bloccate_zero.log # Blocchi importo=0
│   └── api_sospese.log              # API sospese
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

**Esegui tutti i 10 problemi in sequenza:**
```bash
./run_problem.sh
```

## Comportamento comune

- Ogni alert aggiorna [blacklist.csv](blacklist.csv) con `risk_score` e `recidivita`.
- Per IP con `risk_score >= 100` lo stato diventa `blocked` e viene applicato `iptables` DROP.
- Output a terminale **ridotto al minimo**; dettagli completi nei file di log.
- Gli script terminano al **primo alert** per focalizzare l'attenzione.

---

## I 10 Problemi di Sicurezza

### PROBLEMA 1: Flussi anomali bonifici (AML)

#### Contesto

Nel settore bancario, il **riciclaggio di denaro** (money laundering) è uno dei crimini più sofisticati. Uno schema tipico: **molti bonifici da account diversi verso uno stesso IBAN in breve tempo**. Ogni transazione è formalmente valida, ma il **pattern complessivo è anomalo**.

#### Metodo di rilevamento

Lo script **monitora il file di log in tempo reale** `logs/realtime_access.log`:
- Legge le nuove righe man mano che vengono scritte
- Filtra solo gli eventi di azione "BONIFICO"
- Traccia i bonifici in un file temporaneo (formato: `customer_id|iban_dest|importo|timestamp`)
- Conta i **mittenti unici per IBAN negozio** negli ultimi 60 secondi
- Se il count supera 5, segnala l'anomalia

```bash
# File: problema_01_aml_bonifici.sh
# Legge nuove righe dal log (solo BONIFICO)
tail -n +$((LAST_POSITION + 1)) "$REALTIME_LOG" | grep "|BONIFICO|" | \
while IFS='|' read -r timestamp customer_id ip_src azione importo iban_dest ...
    # Salva nel file di stato
    echo "$customer_id|$iban_dest|$importo|$(date +%s)" >> "$STATE_FILE"
    
    # Conta mittenti unici per this IBAN
    mittenti_unici=$(awk -F'|' -v iban="$iban_dest" '$2==iban {print $1}' "$STATE_FILE" | sort -u | wc -l)
    
    # Se supera soglia
    if [ "$mittenti_unici" -ge 5 ]; then
        # Segnala alert
```

#### Comportamento dell'alert

1. Registra su `logs/aml_alerts.log` l'IBAN sospetto e il numero di mittenti
2. Aggiunge il primo mittente rappresentativo in blacklist con `risk_score=50`
3. Se recidivo, incrementa il risk_score
4. Se risk_score >= 100, blocca l'IP

---

### PROBLEMA 2: Accessi simultanei sullo stesso account

#### Contesto

Uno dei segnali più affidabili di **compromissione delle credenziali**: lo stesso account è contemporaneamente attivo da **3+ indirizzi IP diversi**. Un utente legittimo accede da **un'unica locazione alla volta**.

#### Metodo di rilevamento

Lo script **monitora il file di log in tempo reale** `logs/realtime_access.log`:
- Legge le ultime 50 righe del log
- Filtra solo eventi di azione "LOGIN"
- Raggruppa per `customer_id`
- Conta quanti **IP diversi** sono attivi contemporaneamente per lo stesso customer
- Se il count supera 3, segnala

```bash
# File: problema_02_accessi_simultanei.sh
tail -50 /workspaces/SO/logs/realtime_access.log | \
    grep "|LOGIN|" | \
    awk -F'|' '{print $2"|"$3}' | \  # estrai customer_id|ip
    awk '
        {
            customer=$1; ip=$2
            if (customer != "" && ip != "" && ip != "127.0.0.1") {
                key = customer SUBSEP ip
                seen[key] = 1
            }
        }
        END {
            for (k in seen) {
                split(k, a, SUBSEP)
                customer = a[1]
                ip = a[2]
                # Conta IP diversi per customer
                if (++ ip_count[customer] >= 3) {
                    # SEGNALA
```

**Inoltre**, notifica il cliente via email se 2FA non è attivo:

```bash
# Se 2FA disattivo: richiedi attivazione urgente
if [ "$twofa" = "false" ]; then
    echo "[$timestamp] TO:$email SUBJECT:Attiva 2FA - URGENTE" >> "$NOTIFY_LOG"
else
    echo "[$timestamp] TO:$email SUBJECT:Accessi simultanei rilevati" >> "$NOTIFY_LOG"
fi
```

#### Comportamento dell'alert

1. Registra su `logs/simultanei_alerts.log` gli IP coinvolti
2. Aggiunge il customer in blacklist con `risk_score=40`
3. Scrive notifica cliente in `logs/notifiche_email.txt`
4. Se risk_score >= 100, blocca gli IP

---

### PROBLEMA 3: Accessi notturni fuori profilo

#### Contesto

Il **fattore temporale** è un indicatore di anomalia comportamentale cruciale. Un accesso legittimo alle 3 del mattino da un account che non ha mai avuto attività notturne è sospetto.

#### Metodo di rilevamento

Lo script **monitora le connessioni TCP attive in tempo reale**:
- Usa `ss -tn state established` per ottenere le connessioni stabilizzate
- Filtra solo le connessioni verso `SERVER_PORT` (porta server)
- Per ogni IP connesso, estrae il peer address (sorgente)
- Usa `host <IP>` per ottenere il reverse DNS
- Verifica se l'ora attuale ricade nella fascia notturna (22:00-06:00)
- Se nuovo IP notturno, segnala

```bash
# File: problema_03_accessi_notturni.sh
# Monitora connessioni TCP attive verso la porta server
CONNESSIONI=$(ss -tn state established | grep ":$SERVER_PORT " | awk '{print $4}' | cut -d: -f1 | sort -u)

while read -r suspicious_ip; do
    if [ -z "$suspicious_ip" ] || [ "$suspicious_ip" = "127.0.0.1" ]; then
        continue
    fi
    
    # Verifica ora attuale
    CURRENT_HOUR=$(date '+%H')
    if [ "$CURRENT_HOUR" -ge 22 ] || [ "$CURRENT_HOUR" -lt 6 ]; then
        
        # Ricava hostname per validazione
        HOSTNAME=$(host "$suspicious_ip" | grep "domain name pointer" | awk '{print $NF}')
        
        # Se non già segnalato
        if ! controlla_blacklist "IP" "$suspicious_ip"; then
            # Segnala accesso notturno anomalo
            aggiungi_blacklist "IP" "$suspicious_ip" "LOGIN_NOTTURNO" "MEDIA" 30 \
                "Accesso notturno da $suspicious_ip ($HOSTNAME)"
        fi
    fi
done <<< "$CONNESSIONI"
```

#### Comportamento dell'alert

1. Registra su `logs/notturni_alerts.log` l'IP e il timestamp
2. Aggiunge l'IP in blacklist con `risk_score=30`
3. Notifica il cliente
4. Se risk_score >= 100, blocca

---

### PROBLEMA 4: ATM con pattern anomali

#### Contesto

Gli **ATM sono nodi critici** con comportamento altamente standardizzato. ATM da range specifico (192.168.30.x) che effettuano **molti login in breve tempo** indicano possibile compromissione o malware.

#### Metodo di rilevamento

Lo script **monitora le connessioni TCP della subnet ATM in tempo reale**:
- Usa `netstat -tn` per ottenere tutte le connessioni TCP
- Filtra solo le connessioni dalla subnet ATM (192.168.30.x)
- Per ogni ATM (IP univoco), conta il numero di connessioni contemporanee
- Se il count per un singolo ATM supera 5 connessioni, segnala **ISOLAMENTO IMMEDIATO**

```bash
# File: problema_04_atm_porte.sh
# Monitora connessioni TCP dalla subnet ATM
ATM_CONNECTIONS=$(netstat -tn | grep " $ATM_SUBNET\." | grep ":$SERVER_PORT ")

while read -r line; do
    # Estrai IP sorgente ATM
    atm_ip=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
    
    if [ -n "$atm_ip" ]; then
        # Conta connessioni contemporanee per questo ATM
        conn_count=$(echo "$ATM_CONNECTIONS" | grep "$atm_ip" | wc -l)
        
        # Se troppi login simultanei dal singolo ATM
        if [ "$conn_count" -ge 5 ]; then
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

