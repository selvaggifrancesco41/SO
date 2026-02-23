# PROGETTO_SERVER_BANCA

## Introduzione

Questo progetto simula un **server bancario GNU/Linux** con monitoraggio avanzato di 10 anomalie di sicurezza critiche rilevabili attraverso:
- **Analisi real-time di log** per rilevamenti veloci (P01, P02)
- **Query periodiche database SQLite** per pattern complessi e storici (P03-P10)

Ogni script mantiene un **output minimalista** sul terminale e registra dettagli completi in log specializzati. L'alert viene segnalato **al primo rilevamento** per focalizzare l'attenzione.

## Perché questo approccio?

Nel settore bancario e nelle infrastrutture critiche, la sicurezza non si basa solo su autenticazione e autorizzazione. I problemi più subdoli sono quelli che **non violano formalmente alcuna regola** ma mostrano un comportamento **incoerente con i pattern attesi**.

Monitorando **log in tempo reale** e **interrogando il database periodicamente**, è possibile rilevare:
- Anomalie **temporali** (accessi anomali in orari inaspettati)
- Anomalie **comportamentali** (pattern di utilizzo insoliti)
- Anomalie **di schema** (operazioni incoerenti con il tipo di client)
- Anomalie **lente** (attacchi low-and-slow che non superano soglie istantanee)

---

## Architettura

```
/workspaces/SO/
├── script/                           # 10 script di monitoraggio + orchestrator
│   ├── problema_01_aml_bonifici.sh          # Real-time: rilevamento riciclaggio
│   ├── problema_02_accessi_simultanei.sh    # Real-time: session hijacking
│   ├── problema_03_accessi_notturni.sh      # DB: anomalie temporali
│   ├── problema_04_atm_porte.sh             # DB: isolamento ATM
│   ├── problema_05_bruteforce.sh            # DB: brute-force login
│   ├── problema_06_correlazione_rete.sh     # DB: anomalie subnet
│   ├── problema_07_pattern_api.sh           # DB: automazione sospetta
│   ├── problema_08_covert_channels.sh       # DB: canali covert
│   ├── problema_09_incoerenza_rete.sh       # DB: incoerenza operazione-client
│   ├── problema_10_low_slow.sh              # DB: attacchi lenti
│   └── run_problem.sh                       # Orchestrator
├── server/
│   └── server.py                    # Server Flask per test
├── data/
│   └── bank_logs.db                 # Database SQLite con eventi
├── logs/
│   ├── realtime_access.log          # Log centrale in tempo reale
│   ├── aml_alerts.log
│   ├── simultanei_alerts.log
│   ├── notturni_alerts.log
│   ├── atm_porte_alerts.log
│   ├── bruteforce_alerts.log
│   ├── correlazione_alerts.log
│   ├── pattern_api_alerts.log
│   ├── covert_channels_alerts.log
│   ├── incoerenza_rete_alerts.log
│   ├── low_slow_attacks.log
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

Lo script **interroga periodicamente il database SQLite**:
- Query per LOGIN nella fascia sensibile (22:00-06:00)
- Filtra solo **timestamp recenti** (ultimi 60 secondi)
- Per ogni IP notturno, verifica se già noto o nuovo
- Se nuovo, segnala

```bash
# File: problema_03_accessi_notturni.sh
# Query SQLite: cerca LOGIN in fascia notturna
QUERY="SELECT timestamp, customer_id, ip_address, azione 
       FROM logs 
       WHERE azione = 'LOGIN' 
       AND datetime > datetime('now', '-60 seconds') 
       AND (strftime('%H', datetime) >= '22' OR strftime('%H', datetime) < '06')"

LOGIN_NOTTURNI=$(sqlite3 "$DB_PATH" "$QUERY")

# Per ogni match, controlla se IP è già noto
if ! controlla_blacklist "IP" "$ip_address"; then
    # IP nuovo in fascia notturna -> segnala
    aggiungi_blacklist "IP" "$ip_address" "LOGIN_NOTTURNO" "MEDIA" 30 \
        "Accesso notturno anomalo da $ip_address"
fi
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

Lo script **interroga periodicamente il database SQLite**:
- Query per LOGIN da IP ATM (range 192.168.30.%)
- Conta i login dello stesso ATM negli ultimi 60 secondi
- Se il count supera 10, segnala **ISOLAMENTO IMMEDIATO**

```bash
# File: problema_04_atm_porte.sh
# Query: conta LOGIN da IP ATM negli ultimi 60s
QUERY="SELECT ip, COUNT(*) as login_count 
       FROM logs 
       WHERE action='LOGIN' 
       AND ip LIKE '192.168.30.%' 
       AND datetime > datetime('now', '-60 seconds')
       GROUP BY ip HAVING COUNT(*) > 10"

ATM_LOGINS=$(sqlite3 "$DB_PATH" "$QUERY")

# Se trovato pattern anomalo
if [ -n "$ATM_LOGINS" ]; then
    # ISOLA IMMEDIATAMENTE con risk_score=100
    aggiungi_blacklist "IP" "$atm_ip" "ATM_ANOMALO" "CRITICA" 100 \
        "$login_count login in 60s - ISOLAMENTO IMMEDIATO"
    
    # Applica DROP con iptables
    iptables -A INPUT -s "$atm_ip" -j DROP
fi
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

Lo script **interroga periodicamente il database SQLite**:
- Query per LOGIN dagli ultimi 10 secondi
- Per ogni IP univoco, conta i tentativi nella finestra
- Se il count supera 10, segnala

```bash
# File: problema_05_bruteforce.sh
# Calcola finestra temporale: ultimi 10 secondi
WINDOW_START=$(date -u -d "10 seconds ago" '+%Y-%m-%dT%H:%M:%S')

# Query: conta LOGIN per IP nella finestra
COUNT_QUERY="SELECT COUNT(*) 
             FROM logs 
             WHERE azione = 'LOGIN' 
             AND ip_address = '$suspicious_ip'
             AND timestamp >= '$WINDOW_START'"

TENTATIVI=$(sqlite3 "$DB_PATH" "$COUNT_QUERY")

# Controllo soglia
if [ "$TENTATIVI" -ge 10 ]; then
    # Brute-force rilevato
    aggiungi_blacklist "IP" "$suspicious_ip" "BRUTEFORCE_LOGIN" "ALTA" 70 \
        "$TENTATIVI tentativi in 10s - BRUTE-FORCE RILEVATO"
    blocca_ip_se_necessario "$suspicious_ip" 70
fi
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

Lo script **interroga periodicamente il database SQLite**:
- Query per LOGIN recenti
- Per ogni IP, verifica se appartiene alle subnet attese (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Se IP è pubblico o inatteso, segnala

```bash
# File: problema_06_correlazione_rete.sh
IPS_RECENTI=$(sqlite3 "$DB_PATH" "$QUERY")  # Query LOGIN recenti

while read -r ip; do
    # Controlla se IP è in range privato atteso
    if ! echo "$ip" | grep -qE "^192.168|^10\.|^172.1[6-9]\.|^172.2[0-9]\.|^172.3[01]"; then
        # IP pubblico/inatteso -> anomalia
        aggiungi_blacklist "IP" "$ip" "SUBNET_ANOMALA" "MEDIA" 50 \
            "Login da IP pubblico inatteso: $ip"
    fi
done <<< "$IPS_RECENTI"
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

Lo script **interroga periodicamente il database SQLite**:
- Query per operazioni (PRELIEVO/DEPOSITO/BONIFICO) negli ultimi 15 secondi
- Raggruppa per IP
- Se un IP ha >15 operazioni in 15s, segnala

```bash
# File: problema_07_pattern_api.sh
# Query: conta operazioni API per IP in 15 secondi
QUERY="SELECT ip_address, COUNT(*) as op_count 
       FROM logs 
       WHERE azione IN ('PRELIEVO', 'DEPOSITO', 'BONIFICO') 
       AND datetime > datetime('now', '-15 seconds')
       GROUP BY ip_address HAVING COUNT(*) > 15"

RICHIESTE_RECENTI=$(sqlite3 "$DB_PATH" "$QUERY")

# Per ogni match
RICHIESTE_IP=$(sqlite3 "$DB_PATH" "$COUNT_QUERY")
if [ "$RICHIESTE_IP" -gt 15 ]; then
    aggiungi_blacklist "IP" "$ip" "PATTERN_ANOMALO_API" "MEDIA" 40 \
        "$RICHIESTE_IP operazioni in 15s - AUTOMAZIONE SOSPETTA"
fi
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

Lo script **interroga periodicamente il database SQLite**:
- Query per operazioni a importo=0 o NULL negli ultimi 60 secondi
- Se un IP ha >5 operazioni fake, segnala con **conseguenze critiche**

```bash
# File: problema_08_covert_channels.sh
# Query: estrai operazioni fake (importo=0 o NULL) in 60s
QUERY="SELECT ip_address, customer_id, COUNT(*) as fake_count 
       FROM logs 
       WHERE (importo = 0 OR importo IS NULL) 
       AND datetime > datetime('now', '-60 seconds')
       GROUP BY ip_address, customer_id HAVING COUNT(*) >= 5"

FAKE_OPS=$(sqlite3 "$DB_PATH" "$QUERY")

# Se trovato canale covert
if [ "$fake_count" -ge 5 ]; then
    # CONSEGUENZE CRITICHE:
    registra_blocco_importo_zero "$ip" "$customer_id" "$fake_count"  # Log blocco
    sospendi_api "$ip" "$customer_id"  # Sospendi le API
    
    # Registra entry CRITICA in blacklist
    aggiungi_blacklist "IP" "$ip" "API_SOSPESA" "CRITICA" 100 \
        "Canale covert rilevato - API sospese"
fi

# FUNZIONE: registra_blocco_importo_zero
# Scrive su log dedicato
registra_blocco_importo_zero() {
    local ip="$1"
    local customer_id="$2"
    local count="$3"
    echo "[$timestamp] BLOCCO IP:$ip CUSTOMER:$customer_id FAKE_OPS:$count" >> "$LOG_BLOCCO_ZERO"
}

# FUNZIONE: sospendi_api
# Sospende tutte le API per l'IP
sospendi_api() {
    local ip="$1"
    local customer_id="$2"
    echo "[$timestamp] API_SOSPESA IP:$ip CUSTOMER:$customer_id" >> "$LOG_API_SOSPESA"
    aggiungi_blacklist "IP" "$ip" "API_SOSPESA" "CRITICA" 100 \
        "Tutte le API sospese - canale covert"
}
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

Lo script **interroga periodicamente il database SQLite**:
- Determina il "tipo di client" dall'IP sorgente (ATM vs web client vs admin)
- Verifica se l'operazione è coerente con il tipo
- Se c'è mismatch, segnala

```bash
# File: problema_09_incoerenza_rete.sh
# Controlla coerenza operazione vs tipo di client
case "$client_type|$operation" in
    "ATM|BONIFICO")
        # ATM non dovrebbe fare bonifici
        aggiungi_blacklist "IP" "$ip" "INCOERENZA_RETE" "ALTA" 70 \
            "ATM tentò BONIFICO - INCOERENTE"
        ;;
    "ADMIN|PRELIEVO")
        # Admin non dovrebbe fare prelievi
        aggiungi_blacklist "IP" "$ip" "INCOERENZA_RETE" "ALTA" 70 \
            "ADMIN tentò PRELIEVO - INCOERENTE"
        ;;
    *)
        # Coerente
        ;;
esac
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

Lo script **interroga periodicamente il database SQLite**:
- Conta le richieste per IP negli ultimi 60 secondi
- Se il count è tra 3 e 8 (rate basso ma sostenuto), segnala come Low & Slow
- Continua il monitoraggio per correlare il pattern nel tempo

```bash
# File: problema_10_low_slow.sh
# Query: estrai richieste per IP negli ultimi 60s
QUERY="SELECT ip_address, COUNT(*) as req_count 
       FROM logs 
       WHERE datetime > datetime('now', '-60 seconds')
       GROUP BY ip_address HAVING COUNT(*) BETWEEN 3 AND 8"

# Se trovato pattern Low & Slow
if [ "$count" -ge 3 ] && [ "$count" -le 8 ]; then
    # Rate basso ma sostenuto -> Low & Slow
    aggiungi_blacklist "IP" "$ip" "LOW_SLOW_ATTACK" "MEDIA" 60 \
        "$count richieste in 60s - ATTACCO LENTO"
fi
```

#### Comportamento dell'alert

1. Registra su `logs/low_slow_attacks.log` il rate per tracciamento
2. Aggiunge l'IP in blacklist con `risk_score=60`
3. **Risk_score accumula nel tempo** per elementi recidivi
4. Quando il rischio supera 100, **blocca proattivamente** prima che il degrado sia severo

---

## Note operative

- **Metodo P01-P02**: Real-time log analysis (tail + grep/awk)
- **Metodo P03-P10**: Periodic SQLite queries (sqlite3 command)
- **Output**: Redirect stdout a /dev/null, usa FD3 per output critico
- **Logging**: Dettagli completi in file specializzati per ogni problema
- **Escalation**: Risk_score accumula per elementi recidivi
- **Blocco automatico**: A risk_score >= 100 viene applicato `iptables DROP`
- **Priorità**: Terminazione al primo alert per focalizzare l'attenzione

