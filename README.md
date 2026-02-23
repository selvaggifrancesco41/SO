# PROGETTO_SERVER_BANCA

## Introduzione

Questo progetto simula un **server bancario GNU/Linux** con monitoraggio avanzato di 10 anomalie di sicurezza critiche rilevabili esclusivamente tramite **network monitoring** e **comportamento in tempo reale**, senza fare affidamento su dati storici o precompilati.

Ogni script analizza il traffico di rete, le connessioni TCP attive, i pattern di accesso e il comportamento dei client in **tempo reale**, mantenendo un **output minimalista** sul terminale e registrando dettagli completi in log specializzati.

### Perché questo progetto?

Nel settore bancario e nelle infrastrutture critiche, la sicurezza non si basa solo su autenticazione e autorizzazione. I problemi più subdoli sono quelli che **non violano formalmente alcuna regola** ma mostrano un comportamento **incoerente con i pattern attesi**.

Questo progetto dimostra come rilevare anomalie attraverso:
- **Analisi di rete real-time** con tcpdump/tshark/ss
- **Monitoraggio delle connessioni TCP** (netstat)
- **Correlazione temporale** tra eventi
- **Escalation di rischio** con scoring incrementale
- **Blocchi automatici** quando il rischio supera soglie critiche

---

## Architettura

```
/workspaces/SO/
├── script/                           # 10 script di monitoraggio + orchestratore
│   ├── problema_01_aml_bonifici.sh   # Rilevamento riciclaggio (AML)
│   ├── problema_02_accessi_simultanei.sh  # Session hijacking
│   ├── problema_03_accessi_notturni.sh    # Comportamento anomalo temporale
│   ├── problema_04_atm_porte.sh           # Isolamento ATM compromessi
│   ├── problema_05_bruteforce.sh          # Força bruta sulle API
│   ├── problema_06_correlazione_rete.sh   # Anomalie subnet
│   ├── problema_07_pattern_api.sh         # Automazione sospetta
│   ├── problema_08_covert_channels.sh     # Canali covert (importo 0)
│   ├── problema_09_incoerenza_rete.sh     # Operazioni contestualmente incoerenti
│   ├── problema_10_low_slow.sh            # Attacchi lenti e persistenti
│   └── run_problem.sh                 # Orchestratore (avvia 1-10 in sequenza)
├── server/
│   └── server.py                      # Server Flask per test
├── data/
│   └── bank_logs.db                   # Database SQLite con eventi
├── logs/                              # Log specializzati per ogni problema
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
│   ├── notifiche_email.txt            # Notifiche ai clienti
│   ├── operazioni_bloccate_zero.log   # Blocchi importo=0
│   ├── api_sospese.log                # API sospese
│   └── realtime_access.log            # Log accessi in tempo reale
├── blacklist.csv                      # Blacklist incrementale di entry rischio
├── clienti_banca.csv                  # Dati clienti (email, 2FA, etc)
└── README.md                          # Questo file

## Struttura rapida

```bash
cd /workspaces/SO/script
./run_problem.sh 1                     # Esegui problema 1 isolatamente
./run_problem.sh                       # Esegui tutti 1-10 in sequenza
```

## Esecuzione

**Esegui un singolo problema:**
```bash
cd /workspaces/SO/script
./run_problem.sh 1
```

**Esegui tutti i 10 problemi:**
```bash
./run_problem.sh
```

## Comportamento comune

- Ogni alert aggiorna [blacklist.csv](blacklist.csv) con `risk_score` e `recidivita`.
- Per IP con `risk_score >= 100` lo stato diventa `blocked` e viene applicato `iptables` (se disponibile).
- Output a terminale **ridotto al minimo** per ridurre il rumore; dettagli completi nei file di log.
- Gli script terminano al **primo alert** per focalizzare l'attenzione sull'anomalia più critica.

---

## Problemi monitorati

### PROBLEMA 1: Flussi anomali bonifici in ingresso (AML)

#### Contesto di sicurezza

Nel settore bancario, il **riciclaggio di denaro (money laundering)** è uno dei crimini più sofisticati. Uno schema tipico è il **structuring** o **smurfing**: piccoli bonifici da molti mittenti diversi verso uno stesso conto beneficiario, in modo che ogni singola transazione non superi la soglia di alert, ma il totale complessivo soddisfi l'obbiettivo criminale.

#### Perché è un problema difficile da rilevare

Dal punto di vista applicativo, ogni bonifico è **formalmente valido**: credenziali corrette, importo lecito, mittente noto. Il server non genera errori. Ma **correlando i bonifici nel tempo**, emerge un pattern innaturale: 5+ mittenti diversi verso lo stesso IBAN in soli 60 secondi. Un utente legittimo non riceve mai bonifici così frequentemente da più sorgenti.

#### Come viene rilevato

Lo script analizza il **traffico HTTP in tempo reale** verso l'endpoint `/bonifico` utilizzando **tcpdump** o **tshark**:

```bash
# Cattura pacchetti POST verso /bonifico e estrae gli IBAN beneficiari
tshark -i lo -f "tcp port 8000" -Y "http.request.method == POST and http.request.uri contains \"/bonifico\"" \
  -T fields -e ip.src -e http.file_data
```

Conta i mittenti unici per ciascun IBAN nella finestra di 60 secondi. Se il count supera 5, segnala:

```bash
# Conteggio mittenti unici per IBAN
mittenti_unici=$(grep "iban_dest=$iban_target" $STATE_FILE | cut -d'|' -f1 | sort -u | wc -l)

if [ "$mittenti_unici" -gt "$SOGLIA_MITTENTI_UNICI" ]; then
    aggiungi_blacklist "IBAN" "$iban_target" "BONIFICI_ANOMALI" "ALTA" 50 \
        "$mittenti_unici mittenti in 60s verso $iban_target"
fi
```

#### Comportamento dell'alert

1. Inserisce l'**IBAN beneficiario** in blacklist con `risk_score=50`
2. Registra su `logs/aml_alerts.log` con timestamp, numero mittenti, e iban sospetto
3. Se l'IBAN è recidivo (già segnalato), incrementa `risk_score` e `recidivita`
4. **Non blocca immediatamente** perché un singolo AML potrebbe essere veramente sospetto ma isolato

---

### PROBLEMA 2: Accessi simultanei sullo stesso account

#### Contesto di sicurezza

Uno dei segnali più affidabili di **compromissione delle credenziali** è quando lo stesso account bancario è contemporaneamente attivo da **indirizzi IP diversi**. Un utente legittimo esegue il login da **un'unica locazione alla volta**.

Se un account è attivo da 3 IP differenti nello stesso momento, significa che:
- Le credenziali sono state rubate
- C'è un session hijacking in corso
- Un malware ha accesso alle credenziali

#### Perché è un problema difficile da rilevare

Ogni **singola sessione** è formalmente valida: credenziali corrette, nessun errore di autenticazione. Ma l'**overlap temporale** di più sessioni da IP diversi è l'anomalia critica.

#### Come viene rilevato

Lo script monitora le **connessioni TCP attive** verso il server bancario (porta 8000):

```bash
# Estrae connessioni TCP stabilite verso la porta 8000
ss -tn state established | grep ":8000 " | awk '{print $4, $5}'
```

Per ogni connessione, risolve il `customer_id` associato all'IP sorgente (lookup puntuale nel database) e conta quanti IP diversi sono attivi contemporaneamente per lo stesso customer:

```bash
# Conta IP diversi attivi per customer
ip_count=$(echo "$results" | awk -F'|' -v cid="$customer_id" '$2==cid {print $1}' | sort -u | wc -l)

if [ "$ip_count" -ge "$SOGLIA_IP_SIMULTANEI" ]; then
    # Account con troppi IP simultanei -> possibile compromissione
```

**Inoltre, se 2FA è disattivo**, notifica il cliente per attivarlo:

```bash
notifica_cliente() {
    local customer_id="$1"
    info=$(get_cliente_info "$customer_id")  # Estrae email e stato 2FA
    email=$(echo "$info" | cut -d'|' -f1)
    twofa=$(echo "$info" | cut -d'|' -f2)
    
    if [ "$twofa" = "false" ]; then
        # 2FA non attivo -> richiedi urgentemente
        echo "[$timestamp] TO:$email SUBJECT:Attiva 2FA" >> "$NOTIFY_LOG"
    else
        # 2FA attivo -> notifica comunque
        echo "[$timestamp] TO:$email SUBJECT:Accessi sospetti rilevati" >> "$NOTIFY_LOG"
    fi
}
```

#### Comportamento dell'alert

1. Inserisce **l'ACCOUNT** (customer_id) in blacklist con `risk_score=40`
2. Registra su `logs/simultanei_alerts.log` gli IP coinvolti
3. Scrive una **notifica email simulata** in `logs/notifiche_email.txt`
4. Se 2FA è disattivo, il soggetto della mail è **"Attiva 2FA - Urgente"**
5. Se il rischio supera 100, blocca l'IP con `iptables`

---

### PROBLEMA 3: Accessi notturni fuori profilo

#### Contesto di sicurezza

Il **fattore temporale** è uno dei migliori indicatori di anomalia comportamentale. Un utente legittimo ha pattern di accesso prevedibili: se avesse sempre acceduto tra le 8 e le 20, un accesso alle 3 del mattino è sospetto, anche se la sessione è formalmente valida.

Questo è il principio della **anomaly detection basata su profilo**: ogni account ha un "profilo orario" implicito. Un accesso fuori profilo non significa frode certa, ma aumenta il sospetto.

#### Perché è un problema difficile da rilevare

Richiede di **correlare il tempo dell'accesso con il comportamento storico dell'utente**. Ma in questo progetto, usiamo un **euristica semplice**: se è nella fascia notturna (22:00-06:00) e il cliente non ha mai avuto accessi notturni in passato, è sospetto.

#### Come viene rilevato

Lo script legge i login dal database in fascia notturna:

```bash
# Query SQLite: estrai LOGIN tra le 22:00 e le 06:00
sqlite3 "$DB_PATH" \
    "SELECT ip, customer_id FROM events WHERE action='LOGIN' 
     AND datetime > datetime('now', '-60 seconds') 
     AND (strftime('%H', datetime) >= '22' OR strftime('%H', datetime) < '06')"
```

Per ogni IP notturno, controlla se è mai stato visto prima in fascia notturna. Se è nuovo, lo segnala:

```bash
if controlla_blacklist "IP" "$ip"; then
    # IP già noto -> potrebbe essere legittimo
    continue
else
    # IP nuovo in fascia notturna -> anomalía
    aggiungi_blacklist "IP" "$ip" "LOGIN_NOTTURNO" "MEDIA" 30 \
        "Accesso notturno anomalo da $ip"
fi
```

Inoltre, tenta una risoluzione DNS inversa per capire da dove stia arrivando l'accesso:

```bash
hostname=$(host "$ip" | awk '{print $NF}')  # Risoluzione PTR record
```

#### Comportamento dell'alert

1. Inserisce l'**IP** in blacklist con `risk_score=30`
2. Registra su `logs/notturni_alerts.log` il timestamp e l'IP
3. Notifica il cliente come per P02
4. Se il rischio supera 100, blocca l'IP

---

### PROBLEMA 4: ATM con pattern anomali

#### Contesto di sicurezza

Gli **ATM sono nodi critici** molto controllati in un'infrastruttura bancaria reale. Hanno IP fissi (es. range 192.168.30.x), comunicano solo con specifiche porte sul server, e il loro comportamento è **altamente standardizzato**.

Se un ATM inizia a comportarsi in modo anomalo (accessi molto frequenti, pattern inusuali), potrebbe essere stato **compromesso da malware** o sottoposto a **test di intrusione**.

#### Perché è un problema difficile da rilevare

Dal punto di vista della sicurezza, gli ATM ricevono poco scrutinio dinamico. Si presume che se un ATM è "in rete", sia sicuro. Ma il monitoraggio del **comportamento dell'ATM nel tempo** rivela compromissioni silenziose.

#### Come viene rilevato

Lo script identifica login da IP nel range ATM (192.168.30.x) e ne analizza il pattern:

```bash
# Estrai login da IP ATM negli ultimi 60 secondi
sqlite3 "$DB_PATH" \
    "SELECT ip, customer_id, COUNT(*) FROM events 
     WHERE action='LOGIN' 
     AND ip LIKE '192.168.30.%' 
     AND datetime > datetime('now', '-60 seconds')
     GROUP BY ip, customer_id"
```

Se un singolo ATM effettua **troppi login in breve tempo** (es. >10 in 60 secondi), indica possibile malware:

```bash
if [ "$login_count" -gt 10 ]; then
    # ATM anomalo -> isola immediatamente
    aggiungi_blacklist "IP" "$atm_ip" "ATM_ANOMALO" "CRITICA" 100 \
        "$login_count login in 60s da ATM $atm_ip - ISOLAMENTO IMMEDIATO"
fi
```

#### Comportamento dell'alert

1. Inserisce l'**IP ATM** in blacklist con `risk_score=100` (soglia di blocco immediato)
2. Cambia stato a **"blocked"** e applica `iptables` DROP
3. Registra su `logs/atm_porte_alerts.log` con gravità **CRITICA**
4. **L'ATM viene isolato immediatamente** dalla rete
5. Nessun tentativo di monitoraggio ulteriore: il compromesso è attestato

```bash
# Isolamento immediato con iptables
if [ "$risk_score" -ge 100 ]; then
    iptables -A INPUT -s "$atm_ip" -j DROP
    stato="blocked"  # Stato nel CSV blacklist
fi
```

---

### PROBLEMA 5: Brute-force sulle API di login

#### Contesto di sicurezza

Le **API di login** sono target privilegiati per attacchi di forza bruta. Anche con rate limiting, un attaccante può distribuire i tentativi su più connessioni parallele, ciascuna formalmente lecita ma che insieme costituisce un attacco.

#### Perché è un problema difficile da rilevare

Un singolo tentativo di login fallito è normale (utente sbaglia password). Ma **5+ tentativi contemporanei da uno stesso IP in 10 secondi** è un pattern automatizzato. Senza correlazione temporale, sembra solo "traffico regolare".

#### Come viene rilevato

Lo script conta i tentativi di login per IP in finestre temporali ristrette:

```bash
# SQLite: conta LOGIN per IP negli ultimi 10 secondi
sqlite3 "$DB_PATH" \
    "SELECT ip, COUNT(*) FROM events 
     WHERE action='LOGIN' 
     AND datetime > datetime('now', '-10 seconds')
     GROUP BY ip HAVING COUNT(*) > 10"
```

Se un IP supera la soglia, viene registrato come brute-force:

```bash
login_count=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM events WHERE action='LOGIN' 
     AND ip='$ip' AND datetime > datetime('now', '-10 seconds')")

if [ "$login_count" -gt 10 ]; then
    aggiungi_blacklist "IP" "$ip" "BRUTEFORCE_LOGIN" "ALTA" 70 \
        "$login_count tentativi login in 10s - BRUTE-FORCE RILEVATO"
    blocca_ip_se_necessario "$ip" 70
fi
```

#### Comportamento dell'alert

1. Inserisce l'**IP** in blacklist con `risk_score=70`
2. Registra su `logs/bruteforce_alerts.log` con numero di tentativi
3. Se il rischio supera 100, blocca l'IP
4. Effetto deterrente: gli attacchi successivi da quello stesso IP vengono automaticamente rifiutati

---

### PROBLEMA 6: Correlazione rete e subnet non autorizzate

#### Contesto di sicurezza

Un'infrastruttura bancaria ha una **topologia di rete ben definita**: subnet separate per clienti pubblici, ATM, staff interno, API partners esterne. Un login proveniente da subnet "inattesa" (es. da un range pubblico invece che da una VPN aziendale) è sospetto.

#### Perché è un problema difficile da rilevare

Richiede di **mappare la topologia di rete** e di capire "dove dovrebbe provenire il traffico legittimo". Senza questo contesto, è difficile individuare anomalie topologiche.

#### Come viene rilevato

Lo script raccoglie informazioni di rete locali e analizza le comunicazioni:

```bash
# Estrae subnet locali con 'ip' command
ip addr show | grep "inet " | awk '{print $2}'

# Verifica ARP neighbors per capire cosa è sulla LAN
arp -a | grep -E "192.168|10\."

# Ping test per misurare latenza
ping -c 3 "$source_ip" | grep "rtt min/avg/max"
```

Se un IP supera la soglia di "estraneo" (non è nella subnet privata attesa), viene segnalato:

```bash
if ! echo "$ip" | grep -q "^192.168\|^10\.\|^172.1[6-9]\|^172.2[0-9]\|^172.3[01]"; then
    # IP pubblico -> anomalía
    aggiungi_blacklist "IP" "$ip" "SUBNET_ANOMALA" "MEDIA" 50 \
        "Login da IP pubblico inatteso: $ip"
fi
```

#### Comportamento dell'alert

1. Inserisce l'**IP** in blacklist con `risk_score=50`
2. Registra su `logs/correlazione_alerts.log` la subnet di provenienza
3. Traccia le route di rete per capire il percorso
4. Se il rischio supera 100, blocca

---

### PROBLEMA 7: Pattern anomali nell'uso API

#### Contesto di sicurezza

Ogni tipo di client (app mobile, ATM, portale web, integrazioni) ha un **pattern di utilizzo API caratteristico**: frequenza, endpoint utilizzati, tipo di operazioni. Un automazione non autorizzata (bot, script) genera pattern diversi.

#### Perché è un problema difficile da rilevare

Richiede di **correlare sequenze di richieste** e capire se sono "umane" o "automatiche". Un utente umano esegue operazioni sparse nel tempo; un bot esegue richieste regolari e meccaniche.

#### Come viene rilevato

Lo script conta le operazioni per IP in finestre di 15 secondi:

```bash
# SQLite: conta operazioni PRELIEVO/DEPOSITO/BONIFICO per IP in 15s
sqlite3 "$DB_PATH" \
    "SELECT ip, COUNT(*) FROM events 
     WHERE action IN ('PRELIEVO', 'DEPOSITO', 'BONIFICO')
     AND datetime > datetime('now', '-15 seconds')
     GROUP BY ip HAVING COUNT(*) > 15"
```

Se un IP esegue troppo operazioni in troppo poco tempo, è indicativo di automazione:

```bash
op_count=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM events WHERE ip='$ip' 
     AND action IN ('PRELIEVO', 'DEPOSITO', 'BONIFICO')
     AND datetime > datetime('now', '-15 seconds')")

if [ "$op_count" -gt 15 ]; then
    aggiungi_blacklist "IP" "$ip" "PATTERN_ANOMALO_API" "MEDIA" 40 \
        "$op_count operazioni in 15s - AUTOMAZIONE SOSPETTA"
fi
```

Inoltre, testa gli endpoint API con `curl` per verificare che respondano normalmente:

```bash
response=$(curl -s -w "%{http_code}" http://localhost:8000/api/balance)
if [ "${response: -3}" = "200" ]; then
    # API rispondono -> pattern è rilevante
fi
```

#### Comportamento dell'alert

1. Inserisce l'**IP** in blacklist con `risk_score=40`
2. Registra su `logs/pattern_api_alerts.log` il numero di operazioni
3. Se il rischio supera 100, blocca

---

### PROBLEMA 8: Covert channels tramite operazioni fake

#### Contesto di sicurezza

Un **canale covert** è una comunicazione nascosta dentro traffico apparentemente legittimo. Nel contesto bancario, un attaccante potrebbe usare **operazioni fake** (es. con importo 0 o NULL) come "beacon" per comunicare con un server C2 (Command & Control).

Ogni operazione fake non rappresenta una vera transazione, ma è un "impulso" nel traffico di rete. Un pattern di impulsi regolari (es. una fake op ogni 10 secondi) è un beacon tipico.

#### Perché è un problema difficile da rilevare

Le operazioni fake sono formalmente valide dal punto di vista applicativo. Il server accetta importo=0 e le elabora senza errori. Ma il **pattern temporale** di queste operazioni fake rivela l'automazione.

#### Come viene rilevato

Lo script cerca operazioni con importo zero:

```bash
# SQLite: estrai operazioni con importo=0 o NULL negli ultimi 60s
sqlite3 "$DB_PATH" \
    "SELECT ip, customer_id, COUNT(*) FROM events 
     WHERE (importo=0 OR importo IS NULL)
     AND datetime > datetime('now', '-60 seconds')
     GROUP BY ip, customer_id HAVING COUNT(*) >= 5"
```

Se un IP effettua **5+ operazioni fake in 60 secondi**, è quasi certamente un canale covert:

```bash
if [ "$fake_count" -ge "$SOGLIA_FAKE_OPS" ]; then
    # Canale covert rilevato
    registra_blocco_importo_zero "$ip" "$customer_id" "$fake_count"
    sospendi_api "$ip" "$customer_id"
fi
```

**Conseguenze specifiche di P08:**

```bash
# FUNZIONE: registra_blocco_importo_zero
# Scrive su log dedicato e BLOCCA tutte le operazioni future a importo=0
registra_blocco_importo_zero() {
    local ip="$1"
    local customer_id="$2"
    local count="$3"
    echo "[$timestamp] BLOCCO IP:$ip CUSTOMER:$customer_id FAKE_OPS:$count" >> "$LOG_BLOCCO_ZERO"
}

# FUNZIONE: sospendi_api
# Sospende tutte le API per l'IP compromesso
sospendi_api() {
    local ip="$1"
    local customer_id="$2"
    echo "[$timestamp] API_SOSPESA IP:$ip" >> "$LOG_API_SOSPESA"
    
    # Registra entry CRITICA in blacklist
    aggiungi_blacklist "IP" "$ip" "API_SOSPESA" "CRITICA" 100 \
        "Canale covert - tutte le API sospese"
}
```

#### Comportamento dell'alert

1. Registra su `logs/operazioni_bloccate_zero.log` tutte le operazioni fake bloccate
2. Sospende le API per l'IP compromesso e scrive su `logs/api_sospese.log`
3. Inserisce l'**IP** in blacklist con `risk_score=100` e azione **"API_SOSPESA"**
4. Lo stato diventa **"blocked"** e viene applicato `iptables`
5. Ogni tentativo di operazione successiva da quello stesso IP fallisce

---

### PROBLEMA 9: Incoerenza rete e tipo operazione

#### Contesto di sicurezza

Nel mondo reale, non tutte le operazioni sono lecite solo perché formalmente valide. Una **bonifico da un ATM** è strana (gli ATM fanno prelievi, non bonifici). Un **accesso amministrativo da IP pubblico** è sospetto (gli admin dovrebbero usare VPN).

Questo problema rileva **operazioni formalmente corrette ma contestualmente incoerenti**.

#### Perché è un problema difficile da rilevare

Richiede di mappare il **contesto atteso per ogni tipo di operazione**: 
- Prelievi -> provengono da ATM
- Bonifici -> provengono da portal web o app
- Accessi admin -> provengono da subnet internal
- Download report -> provengono da web portal

Un mismatch tra contesto e operazione è l'anomalia.

#### Come viene rilevato

Lo script determina il "tipo di client" associato all'IP sorgente (ATM, client web, API):

```bash
# Determina tipo di client dall'IP
if [[ "$ip" =~ 192.168.30.* ]]; then
    client_type="ATM"
elif [[ "$ip" =~ 192.168.20.* ]]; then
    client_type="CLIENT_WEB"
elif [[ "$ip" =~ 192.168.10.* ]]; then
    client_type="ADMIN"
else
    client_type="EXTERNAL"
fi
```

Poi verifica se l'operazione è coerente con il client type:

```bash
# Verifica coerenza
case "$client_type|$operation" in
    "ATM|BONIFICO")
        # ATM non dovrebbe fare bonifici -> anomalía
        aggiungi_blacklist "IP" "$ip" "INCOERENZA_RETE" "ALTA" 70 \
            "ATM tentò operazione BONIFICO - INCOERENTE"
        ;;
    "ADMIN|PRELIEVO")
        # Admin non dovrebbe fare prelievi -> anomalia
        aggiungi_blacklist "IP" "$ip" "INCOERENZA_RETE" "ALTA" 70 \
            "ADMIN tentò operazione PRELIEVO - INCOERENTE"
        ;;
    *)
        # Coerente
        ;;
esac
```

#### Comportamento dell'alert

1. Inserisce l'**IP** in blacklist con `risk_score=70`
2. Registra su `logs/incoerenza_rete_alerts.log` l'operazione incoerente
3. La transazione viene **temporaneamente sospesa** in attesa di verifica manuale
4. Se il rischio supera 100, blocca

---

### PROBLEMA 10: Low & Slow ad alto impatto

#### Contesto di sicurezza

Non tutti gli attacchi sono **rumorosi**. Gli attacchi **lenti e distribuiti** (low & slow) sono difficili da rilevare perché non superano mai soglie istantanee. Ma nel tempo, producono **degradazione significativa del servizio**.

Un esempio: 1 richiesta ogni 10 secondi da 1000 IP diversi = 100 req/sec complessivamente, che non supera soglia istantanea di 10 req/sec singola IP, ma **degrada il servizio progressivamente**.

#### Perché è un problema difficile da rilevare

Richiede di **correlare metriche nel tempo** e di capire se un IP, preso singolarmente, ha un rate basso ma sostenutonel tempo.

#### Come viene rilevato

Lo script misura il rate di richieste per IP su 60 secondi:

```bash
# SQLite: estrai richieste per IP negli ultimi 60s
sqlite3 "$DB_PATH" \
    "SELECT ip, COUNT(*) FROM events 
     WHERE datetime > datetime('now', '-60 seconds')
     GROUP BY ip HAVING COUNT(*) BETWEEN 3 AND 8"
```

Se un IP ha un rate basso ma costante (3-8 richieste/60s = 0.05-0.13 req/sec), è Low & Slow:

```bash
for ip in $(sqlite3 ...); do
    count=$(get_request_count "$ip" 60)
    
    if [ "$count" -ge 3 ] && [ "$count" -le 8 ]; then
        # Rate basso pero' sostenuto -> Low & Slow
        aggiungi_blacklist "IP" "$ip" "LOW_SLOW_ATTACK" "MEDIA" 60 \
            "$count richieste in 60s - ATTACK LENTO"
    fi
done
```

Lo script continua il monitoraggio per correlate i pattern nel tempo:

#### Comportamento dell'alert

1. Inserisce l'**IP** in blacklist con `risk_score=60`
2. Registra su `logs/low_slow_attacks.log` il rate per tracciamento
3. Se le richieste continuano, il risk_score accumula nel tempo
4. Quando il rischio supera 100, blocca proattivamente prima che il degradamento sia severo

---

## Note operative

- **Output minimalista**: Ogni script reindirizza stdout a /dev/null e usa FD3 per output critico
- **Logging dettagliato**: Tutti i dettagli sono in file speciali in `/logs/`
- **Escalation progressiva**: Il risk_score accumula per elementi recidivi
- **Blocco automatico**: A risk_score >= 100, viene applicato `iptables` con DROP
- **Priorità**: Gli script terminano al primo alert per focalizzare l'attenzione

gli script terminano al primo alert per ridurre il rumore.
- I log principali sono in `logs/` e possono essere ruotati o puliti a piacere.
