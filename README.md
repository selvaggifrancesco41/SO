# PROGETTO_SERVER_BANCA

Simulazione di un server bancario GNU/Linux con traffico applicativo e di rete generato da client e ATM. Gli script rilevano 10 anomalie realistiche con output minimale e logging dettagliato.

## Struttura rapida

- [script/](script/): monitoraggi problemi 01-10 e runner
- [server/](server/): server di test
- [data/](data/): database SQLite degli eventi
- [logs/](logs/): log di alert e notifiche
- [blacklist.csv](blacklist.csv): eventi di rischio e blocchi
- [COMANDI_RETE_UTILIZZATI.md](COMANDI_RETE_UTILIZZATI.md): comandi di rete effettivi

## Esecuzione

```bash
cd /workspaces/SO/script
./run_problem.sh 1
```

Per eseguire tutti i controlli:

```bash
./esegui_tutti_controlli.sh
```

## Comportamento comune

- Ogni alert aggiorna [blacklist.csv](blacklist.csv) con `risk_score` e `recidivita`.
- Per IP con `risk_score >= 100` lo stato diventa `blocked` e, se disponibile, viene applicato `iptables`.
- Output a terminale ridotto al minimo; dettagli nei file di log.

## Problemi monitorati

### 1 - Flussi anomali bonifici in ingresso (AML)

- **Spiegazione semplificata:** troppi mittenti diversi verso lo stesso IBAN in poco tempo possono indicare riciclaggio.
- **Come rileva:** analizza `logs/realtime_access.log`, conta mittenti unici per IBAN in 60s (soglia 5).
- **Dopo la rilevazione:** inserisce l'`ACCOUNT` in blacklist (risk 50/80) e logga in `logs/aml_alerts.log`.

### 2 - Accessi simultanei sullo stesso account

- **Spiegazione semplificata:** lo stesso account non dovrebbe essere attivo da molti IP insieme.
- **Come rileva:** legge gli ultimi `LOGIN` da `logs/realtime_access.log` e conta IP distinti per `customer_id` (soglia 3).
- **Dopo la rilevazione:** aggiunge l'`ACCOUNT` in blacklist (risk 40/60), scrive `logs/simultanei_alerts.log` e notifica il cliente in `logs/notifiche_email.txt`.

### 3 - Accessi notturni fuori profilo

- **Spiegazione semplificata:** login in orari notturni sono sospetti se non abituali.
- **Come rileva:** query SQLite sui `LOGIN` in fascia 22:00-06:00, risolve hostname con `host`.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 30/50), notifica il cliente e blocca l'IP se `risk_score >= 100`. Log: `logs/notturni_alerts.log`.

### 4 - ATM con pattern anomali

- **Spiegazione semplificata:** un ATM che si comporta in modo anomalo va isolato subito.
- **Come rileva:** login da IP ATM in contesto non previsto (range `192.168.30.x`).
- **Dopo la rilevazione:** isolamento immediato con `risk_score=100`, stato `blocked`, iptables se disponibile, log in `logs/atm_porte_alerts.log`.

### 5 - Brute-force sulle API di login

- **Spiegazione semplificata:** molti login in pochi secondi indicano tentativi automatici.
- **Come rileva:** conta `LOGIN` per IP in 10s (soglia 10) nel database.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 70/100), blocca se `risk_score >= 100`, log in `logs/bruteforce_alerts.log`.

### 6 - Correlazione rete e subnet non autorizzate

- **Spiegazione semplificata:** IP fuori dalle subnet private attese sono sospetti.
- **Come rileva:** verifica gli IP recenti rispetto a subnet private e raccoglie info di rete (`ip`, `arp`, `ping`).
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 50/70), blocca se `risk_score >= 100`, log in `logs/correlazione_alerts.log`.

### 7 - Pattern anomali nell'uso API

- **Spiegazione semplificata:** troppe richieste ravvicinate alle API indicano automazione.
- **Come rileva:** conta operazioni (PRELIEVO/DEPOSITO/BONIFICO) per IP in 15s (soglia 15) e verifica endpoint con `curl`.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 40/60), blocca se `risk_score >= 100`, log in `logs/pattern_api_alerts.log`.

### 8 - Covert channels tramite operazioni fake

- **Spiegazione semplificata:** operazioni con importo 0/NULL possono nascondere un canale covert.
- **Come rileva:** cerca 5+ operazioni fake per IP nel database.
- **Dopo la rilevazione:**
  - blacklist IP (risk 70/90) e log in `logs/covert_channels_alerts.log`.
  - blocco operazioni a importo 0 in `logs/operazioni_bloccate_zero.log`.
  - sospensione API (log in `logs/api_sospese.log`) con entry blacklist aggiuntiva `API_SOSPESA` e `risk_score=100`.

### 9 - Incoerenza rete e tipo operazione

- **Spiegazione semplificata:** un'operazione lecita da una subnet sbagliata e' sospetta.
- **Come rileva:** mappa subnet (clienti/ATM/API/admin) e verifica coerenza azione vs IP.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 70/90), blocca se `risk_score >= 100`, log in `logs/incoerenza_rete_alerts.log`.

### 10 - Low & Slow ad alto impatto

- **Spiegazione semplificata:** poche richieste ma persistenti nel tempo possono degradare il servizio.
- **Come rileva:** individua IP con 3-8 richieste in 60s e rate basso.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 60), blocca se `risk_score >= 100`, log in `logs/low_slow_attacks.log`.

## Note

- Gli script terminano al primo alert per ridurre il rumore.
- I log principali sono in `logs/` e possono essere ruotati o puliti a piacere.
# PROGETTO_SERVER_BANCA

Simulazione di un server bancario GNU/Linux con traffico applicativo e di rete generato da client e ATM. Gli script rilevano 10 anomalie realistiche con output minimale e logging dettagliato.

## Struttura rapida

- [script/](script/): monitoraggi problemi 01-10 e runner
- [server/](server/): server di test
- [data/](data/): database SQLite degli eventi
- [logs/](logs/): log di alert e notifiche
- [blacklist.csv](blacklist.csv): eventi di rischio e blocchi
- [COMANDI_RETE_UTILIZZATI.md](COMANDI_RETE_UTILIZZATI.md): comandi di rete effettivi

## Esecuzione

```bash
cd /workspaces/SO/script
./run_problem.sh 1
```

Per eseguire tutti i controlli:

```bash
./esegui_tutti_controlli.sh
```

## Comportamento comune

- Ogni alert aggiorna [blacklist.csv](blacklist.csv) con `risk_score` e `recidivita`.
- Per IP con `risk_score >= 100` lo stato diventa `blocked` e, se disponibile, viene applicato `iptables`.
- Output a terminale ridotto al minimo; dettagli nei file di log.

## Problemi monitorati

### 1 - Flussi anomali bonifici in ingresso (AML)

- **Spiegazione semplificata:** troppi mittenti diversi verso lo stesso IBAN in poco tempo possono indicare riciclaggio.
- **Come rileva:** analizza `logs/realtime_access.log`, conta mittenti unici per IBAN in 60s (soglia 5).
- **Dopo la rilevazione:** inserisce l'`ACCOUNT` in blacklist (risk 50/80) e logga in `logs/aml_alerts.log`.

### 2 - Accessi simultanei sullo stesso account

- **Spiegazione semplificata:** lo stesso account non dovrebbe essere attivo da molti IP insieme.
- **Come rileva:** legge gli ultimi `LOGIN` da `logs/realtime_access.log` e conta IP distinti per `customer_id` (soglia 3).
- **Dopo la rilevazione:** aggiunge l'`ACCOUNT` in blacklist (risk 40/60), scrive `logs/simultanei_alerts.log` e notifica il cliente in `logs/notifiche_email.txt`.

### 3 - Accessi notturni fuori profilo

- **Spiegazione semplificata:** login in orari notturni sono sospetti se non abituali.
- **Come rileva:** query SQLite sui `LOGIN` in fascia 22:00-06:00, risolve hostname con `host`.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 30/50), notifica il cliente e blocca l'IP se `risk_score >= 100`. Log: `logs/notturni_alerts.log`.

### 4 - ATM con pattern anomali

- **Spiegazione semplificata:** un ATM che si comporta in modo anomalo va isolato subito.
- **Come rileva:** login da IP ATM in contesto non previsto (range `192.168.30.x`).
- **Dopo la rilevazione:** isolamento immediato con `risk_score=100`, stato `blocked`, iptables se disponibile, log in `logs/atm_porte_alerts.log`.

### 5 - Brute-force sulle API di login

- **Spiegazione semplificata:** molti login in pochi secondi indicano tentativi automatici.
- **Come rileva:** conta `LOGIN` per IP in 10s (soglia 10) nel database.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 70/100), blocca se `risk_score >= 100`, log in `logs/bruteforce_alerts.log`.

### 6 - Correlazione rete e subnet non autorizzate

- **Spiegazione semplificata:** IP fuori dalle subnet private attese sono sospetti.
- **Come rileva:** verifica gli IP recenti rispetto a subnet private e raccoglie info di rete (`ip`, `arp`, `ping`).
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 50/70), blocca se `risk_score >= 100`, log in `logs/correlazione_alerts.log`.

### 7 - Pattern anomali nell’uso API

- **Spiegazione semplificata:** troppe richieste ravvicinate alle API indicano automazione.
- **Come rileva:** conta operazioni (PRELIEVO/DEPOSITO/BONIFICO) per IP in 15s (soglia 15) e verifica endpoint con `curl`.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 40/60), blocca se `risk_score >= 100`, log in `logs/pattern_api_alerts.log`.

### 8 - Covert channels tramite operazioni fake

- **Spiegazione semplificata:** operazioni con importo 0/NULL possono nascondere un canale covert.
- **Come rileva:** cerca 5+ operazioni fake per IP nel database.
- **Dopo la rilevazione:**
  - blacklist IP (risk 70/90) e log in `logs/covert_channels_alerts.log`.
  - blocco operazioni a importo 0 in `logs/operazioni_bloccate_zero.log`.
  - sospensione API (log in `logs/api_sospese.log`) con entry blacklist aggiuntiva `API_SOSPESA` e `risk_score=100`.

### 9 - Incoerenza rete e tipo operazione

- **Spiegazione semplificata:** un'operazione lecita da una subnet sbagliata e' sospetta.
- **Come rileva:** mappa subnet (clienti/ATM/API/admin) e verifica coerenza azione vs IP.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 70/90), blocca se `risk_score >= 100`, log in `logs/incoerenza_rete_alerts.log`.

### 10 - Low & Slow ad alto impatto

- **Spiegazione semplificata:** poche richieste ma persistenti nel tempo possono degradare il servizio.
- **Come rileva:** individua IP con 3-8 richieste in 60s e rate basso.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 60), blocca se `risk_score >= 100`, log in `logs/low_slow_attacks.log`.

## Note

- Gli script terminano al primo alert per ridurre il rumore.

- I log principali sono in `logs/` e possono essere ruotati o puliti a piacere.
- importi sotto le soglie di alert tradizionali
- operazioni distribuite su finestre temporali brevi
- assenza di una causale coerente o ricorrente

Questo tipo di attività è progettato per **non generare allarmi immediati**, ma risulta anomala se osservata in modo correlato.

### Risultati dell’analisi

L’analisi consente di individuare:
- conti con elevata entropia dei mittenti
- picchi improvvisi nel numero di bonifici in ingresso
- deviazioni significative rispetto al comportamento storico
- potenziali nodi di smistamento finanziario

### Focus tecnico

L'implementazione del problema si basa esclusivamente su **cattura e analisi del traffico di rete in tempo reale**, senza interrogare il database per aggregazioni o conteggi.

Attività principali:
- cattura pacchetti HTTP verso l'endpoint `/bonifico` tramite **`tshark`**
- estrazione di IP sorgente e payload delle richieste POST
- parsing del corpo della richiesta per identificare IBAN beneficiario
- conteggio in memoria dei mittenti unici per ciascun IBAN
- confronto con soglia AML (es. 3+ mittenti distinti)
- segnalazione automatica in blacklist

Strumenti e comandi chiave:
- **`tshark -i lo -f "tcp port 8000" -Y "http.request.method == POST"`**
- **`tshark -T fields -e ip.src -e http.file_data`**
- parsing JSON del payload per estrarre `iban_beneficiario`
- file temporanei (`/logs/*.tmp`) per tracciamento in-memory
- **aggregazione bash** con array associativi

### Risposta operativa:
Quando un conto riceve numerosi bonifici da IBAN differenti in un intervallo temporale ristretto, il sistema attiva automaticamente una procedura di verifica antifrode.

L’operatività del conto viene temporaneamente limitata e al cliente viene richiesto di riconfermare la propria identità.
Se l’autenticazione a due fattori non risulta attiva, viene richiesta l’attivazione immediata; in caso contrario viene avviata una procedura di verifica dell’identità tramite conferma sicura.

L’evento viene inoltre registrato come segnalazione di rischio per eventuali controlli successivi.

### [Elenco dei problemi](#elenco-dei-problemi)
--- 

## 2-Individuazione di accessi simultanei sospetti dallo stesso account
In un sistema bancario distribuito, l’accesso contemporaneo allo stesso account da più punti della rete rappresenta uno dei segnali più affidabili di **compromissione delle credenziali**. A differenza degli attacchi rumorosi, questo tipo di scenario può passare inosservato se non viene analizzato a livello di **correlazione temporale e di contesto di rete**.

Un singolo login valido non è mai di per sé sospetto. Il problema emerge quando lo **stesso account risulta attivo in più sessioni sovrapposte**, provenienti da indirizzi IP o segmenti di rete differenti.

### Scenario operativo

Il problema si verifica quando:
- un utente effettua un accesso legittimo
- senza disconnettersi, viene aperta un’altra sessione
- le sessioni risultano attive nello stesso intervallo temporale
- le connessioni provengono da IP diversi o da subnet non correlate

Dal punto di vista applicativo, tutte le richieste risultano corrette: credenziali valide, token corretti, nessun errore di autenticazione. Tuttavia, il comportamento globale **non è coerente con un utilizzo umano normale**.

### Obiettivo dell’analisi

Individuare situazioni in cui un account bancario risulta utilizzato simultaneamente da più origini, suggerendo:
- furto di credenziali
- condivisione non autorizzata dell’account
- accesso da malware o script automatizzati

L’obiettivo è identificare **overlap temporali tra sessioni attive**, prima che l’account venga utilizzato per operazioni fraudolente.

### Caratteristiche del comportamento sospetto

Gli account sospetti presentano tipicamente:
- più sessioni attive contemporaneamente
- IP di origine differenti
- sessioni che non seguono un pattern di logout/login
- operazioni bancarie eseguite in parallelo

In particolare, il rischio aumenta quando:
- le sessioni insistono su reti diverse
- le azioni vengono eseguite quasi in simultanea
- l’utente non ha mai mostrato questo comportamento in passato

### Risultati dell’analisi

L’analisi consente di individuare:
- account con sessioni sovrapposte
- anomalie nella gestione delle sessioni
- potenziali compromissioni silenziose
- utilizzo fraudolento in tempo reale

I conti identificati possono essere soggetti a:
- invalidazione forzata delle sessioni
- richiesta di verifica aggiuntiva
- blocco temporaneo dell’account

### Focus tecnico

L'implementazione del problema si basa esclusivamente su **monitoraggio delle connessioni TCP attive in tempo reale**, senza analizzare log applicativi o database.

Attività principali:
- monitoraggio delle socket TCP verso il server bancario (porta 8000)
- utilizzo di **`ss`** per ispezionare connessioni nello stato `ESTABLISHED`
- estrazione degli indirizzi IP sorgente
- conteggio delle connessioni simultanee per ciascun IP
- confronto con soglia di sicurezza (es. ≥ 2 connessioni contemporanee)
- identificazione account tramite lookup puntuale nel database (`LIMIT 1`)

Strumenti e comandi chiave:
- **`ss -tn state established`** → visualizza socket TCP attive
- **`grep ":8000 "`** → filtra solo il server bancario
- **`awk '{print $4}'`** → estrae IP:porta remota
- **`cut -d: -f1`** → isola l'indirizzo IP
- **`sort | uniq -c`** → conta connessioni per IP
- query puntuale SQLite solo per recuperare `customer_id` da IP

### Risposta operativa:
Quando vengono rilevate sessioni attive contemporaneamente da indirizzi IP differenti per lo stesso account, il sistema interpreta l’evento come possibile compromissione delle credenziali.

Tutte le sessioni attive vengono terminate automaticamente e l’utente deve effettuare nuovamente l’accesso.
Viene generata una notifica di sicurezza che informa il cliente dell’attività anomala e viene richiesto il rinnovo delle credenziali di accesso.

L’evento viene registrato come possibile incidente di sicurezza.

### [Elenco dei problemi](#elenco-dei-problemi)
---

## 3-Analisi degli accessi notturni fuori dal profilo abituale
In ambito bancario, il **fattore temporale** è uno degli indicatori più sottovalutati ma allo stesso tempo più potenti per l’individuazione di comportamenti anomali. Un accesso tecnicamente corretto può diventare sospetto se avviene **in una fascia oraria incompatibile con il profilo storico dell’utente**.
Questo problema non riguarda l’accesso simultaneo né la validità delle credenziali, ma la **coerenza temporale** dell’attività rispetto alle abitudini consolidate del cliente.

### Scenario operativo

Il problema emerge quando:
- un account effettua accessi in orari notturni o atipici
- tali accessi non risultano coerenti con il comportamento passato
- le operazioni eseguite sono formalmente legittime
- non vengono generati errori o alert automatici

Ad esempio, un cliente che opera abitualmente tra le 8:00 e le 20:00, con attività sporadica e prevedibile, improvvisamente accede ripetutamente tra le 2:00 e le 4:00 del mattino.

Dal punto di vista del server, **non c’è alcuna violazione** evidente: autenticazione valida, richieste corrette, traffico regolare.

### Obiettivo dell’analisi

Individuare accessi che risultano **statisticamente anomali** rispetto al profilo temporale dell’utente, al fine di:
- rilevare account compromessi
- identificare utilizzo da script automatizzati
- intercettare accessi fraudolenti a basso rumore

L’obiettivo non è bloccare tutti gli accessi notturni, ma **separare quelli plausibili da quelli incoerenti**.

### Caratteristiche del comportamento sospetto

Gli account sospetti mostrano tipicamente:
- accessi concentrati in fasce orarie insolite
- assenza di attività simile nei periodi precedenti
- operazioni bancarie effettuate subito dopo il login
- ripetizione del pattern su più notti

Ulteriori segnali di rischio includono:
- accessi notturni seguiti da bonifici o modifiche sensibili
- variazioni improvvise del ritmo di utilizzo
- combinazione con IP o reti mai usate prima

### Risultati dell’analisi

L’analisi consente di:
- costruire un profilo temporale per ogni utente
- individuare deviazioni significative
- classificare accessi come “atipici”
- attivare controlli aggiuntivi solo dove necessario

I risultati possono portare a:
- segnalazioni di rischio
- richiesta di verifica dell’identità
- monitoraggio rafforzato dell’account

### Focus tecnico

La risoluzione del problema si basa su **monitoraggio real-time delle connessioni durante fasce orarie specifiche**, senza analisi storica dei log.

Attività principali:
- verifica dell'ora corrente del sistema tramite **`date +%H`**
- identificazione della fascia notturna (22:00–06:00)
- monitoraggio delle connessioni TCP attive solo durante orario notturno
- estrazione degli IP sorgente connessi al server bancario
- risoluzione DNS inversa tramite **`host`** per identificare il tipo di client
- lookup puntuale nel database per identificare l'account associato

Strumenti e comandi chiave:
- **`date +%H`** → recupera l'ora corrente (formato 24h)
- **`ss -tn state established | grep ":8000 "`** → connessioni attive al server
- **`awk '{print $4}' | cut -d: -f1`** → estrae IP remoto
- **`host <ip_address>`** → risoluzione DNS inversa (PTR record)
- **Condizioni bash**: `[[ ora -ge 22 || ora -lt 06 ]]`
- query puntuale SQLite per mapping IP → customer_id

### [Elenco dei problemi](#elenco-dei-problemi)
---

## 4-Rilevamento ATM che comunicano su porte non autorizzate
In un’infrastruttura bancaria reale, gli **ATM rappresentano nodi critici e altamente controllati**. Il loro comportamento di rete è fortemente standardizzato: comunicano con servizi ben definiti, su porte specifiche, con pattern di traffico prevedibili.
Qualsiasi deviazione da questo modello è un **segnale di rischio elevato**, anche in assenza di errori o malfunzionamenti apparenti.
Questo problema si concentra sull’analisi del **comportamento di rete degli ATM**, non sul contenuto delle transazioni.

### Scenario operativo

Il problema si manifesta quando:
- un ATM risulta attivo e operativo
- le operazioni effettuate sono formalmente valide
- il traffico di rete avviene su porte non previste
- non vengono generati errori applicativi

Ad esempio, un ATM che dovrebbe comunicare esclusivamente con il server bancario su una porta dedicata inizia ad aprire connessioni su porte alte o non documentate.

Dal punto di vista funzionale, **il servizio continua a operare**, rendendo il problema difficile da individuare senza un’analisi di rete mirata.

### Obiettivo dell’analisi

Individuare ATM che:
- utilizzano porte di comunicazione non autorizzate
- instaurano socket inattesi
- presentano pattern di rete incompatibili con il profilo assegnato

L’obiettivo è rilevare:
- compromissioni dell’ATM
- malware o software non autorizzato
- tunneling o canali di comunicazione non previsti
- errori di configurazione critici

### Caratteristiche del comportamento sospetto

Gli ATM anomali mostrano tipicamente:
- porte di destinazione diverse da quelle standard
- connessioni persistenti non documentate
- tentativi di connessione ripetuti su porte non consentite
- differenze di comportamento rispetto ad altri ATM

Ulteriori segnali includono:
- attività di rete in orari insoliti
- traffico verso servizi non bancari
- variazioni improvvise nel numero di socket aperti

### Risultati dell’analisi

L’analisi consente di:
- identificare ATM fuori policy
- mappare porte e servizi effettivamente utilizzati
- confrontare il comportamento tra più ATM
- isolare dispositivi potenzialmente compromessi

I risultati possono portare a:
- disabilitazione preventiva dell’ATM
- alert di sicurezza ad alta priorità
- revisione delle regole di firewalling
- audit della configurazione di rete

### Focus tecnico

La risoluzione del problema si basa esclusivamente su **strumenti di monitoraggio di rete e port scanning**, senza interrogazioni al database.

Attività principali:
- monitoraggio delle connessioni TCP attive tramite **`netstat`**
- identificazione degli IP associati agli ATM (range specifico)
- estrazione delle porte remote utilizzate dalle connessioni ATM
- verifica del range di porte autorizzato (efimere: 32768–60999)
- port scanning con **`nc`** per verificare porte aperte sospette
- segnalazione automatica di ATM che usano porte fuori policy

Strumenti e comandi chiave:
- **`netstat -tn | grep ESTABLISHED`** → connessioni TCP attive
- **`awk '{print $4, $5}'`** → estrae local:porta e remote:porta
- **`cut -d: -f2`** → isola il numero di porta
- **Condizioni bash**: `[[ porta -lt 32768 || porta -gt 60999 ]]`
- **`nc -zv <ip> <porta>`** → verifica porta aperta (port scanning)
- **`timeout 2 nc -zv`** → evita blocchi su porte non responsive

### Risposta operativa:
Quando vengono rilevate sessioni attive contemporaneamente da indirizzi IP differenti per lo stesso account, il sistema interpreta l’evento come possibile compromissione delle credenziali.

Tutte le sessioni attive vengono terminate automaticamente e l’utente deve effettuare nuovamente l’accesso.
Viene generata una notifica di sicurezza che informa il cliente dell’attività anomala e viene richiesto il rinnovo delle credenziali di accesso.

L’evento viene registrato come possibile incidente di sicurezza.

### [Elenco dei problemi](#elenco-dei-problemi)
---

## 5-Rilevamento tentativi di brute-force sulle API del server
In un’architettura bancaria moderna, le **API rappresentano uno dei punti di esposizione più critici**. Anche quando correttamente protette da autenticazione e rate limiting, restano un bersaglio privilegiato per attacchi automatizzati e distribuiti.
A differenza degli attacchi diretti ai servizi web tradizionali, i tentativi di brute-force sulle API sono spesso **silenziosi, frammentati e mascherati da traffico legittimo**.

Questo problema si concentra sull’analisi del traffico di rete e delle connessioni verso le API, non sulla validità delle credenziali.

### Scenario operativo

Il problema emerge quando:
- le API risultano operative e rispondono correttamente
- non vengono generati errori evidenti lato server
- le richieste rispettano il formato previsto
- il volume complessivo non supera soglie critiche

Tuttavia, osservando il traffico nel tempo, si nota una **ripetizione sistematica di richieste di autenticazione** o di accesso a endpoint sensibili, spesso provenienti da:
- pochi indirizzi IP
- intervalli temporali regolari
- connessioni brevi ma frequenti

Dal punto di vista applicativo, tutto sembra funzionare normalmente. Il problema è **visibile solo a livello di rete e socket**.

### Obiettivo dell’analisi

Individuare tentativi di brute-force che:
- non saturano il server
- non causano crash o errori
- non violano regole statiche di firewall
- sfruttano la legittimità delle API

L’obiettivo è distinguere:
- utilizzo normale delle API
- test automatizzati legittimi
- attacchi di enumerazione delle credenziali
- tentativi di accesso ripetuti e sistematici

### Caratteristiche del comportamento sospetto

I pattern tipici includono:
- elevato numero di connessioni brevi verso le stesse API
- frequenti aperture e chiusure di socket
- richieste concentrate su endpoint di login o token
- traffico costante anche in orari non operativi

Ulteriori indicatori:
- stesso IP o subnet che colpisce più endpoint
- crescita graduale delle connessioni
- assenza di traffico “funzionale” successivo (es. operazioni bancarie reali)

### Risultati dell’analisi

L’analisi consente di:
- identificare IP o nodi sospetti
- individuare endpoint API maggiormente bersagliati
- correlare tentativi ripetuti con degrado delle risorse
- supportare decisioni di blocco o limitazione

I risultati possono portare a:
- attivazione di rate limiting più restrittivo
- blocco temporaneo di indirizzi IP
- revisione delle politiche di accesso alle API
- miglioramento del monitoring proattivo

### Focus tecnico

La risoluzione del problema si basa su **cattura real-time del traffico HTTP verso l'endpoint di login**, senza analisi dei log applicativi.

Attività principali:
- cattura pacchetti HTTP POST verso `/login` tramite **`tshark`**
- estrazione dell'IP sorgente per ogni tentativo di autenticazione
- conteggio dei tentativi per IP in finestre temporali ridotte
- confronto con soglia di sicurezza (es. 5+ tentativi in 60 secondi)
- blocco proattivo dell'IP tramite **`iptables`** (opzionale)
- segnalazione in blacklist

Strumenti e comandi chiave:
- **`tshark -i lo -f "tcp port 8000"`** → cattura traffico server
- **`tshark -Y "http.request.method == POST and http.request.uri contains \"/login\""`**
- **`tshark -T fields -e ip.src`** → estrae solo IP sorgente
- file temporanei per conteggio tentativi (`/logs/*.tmp`)
- **`iptables -A INPUT -s <ip> -j DROP`** → blocco immediato IP
- **array bash associativi** per tracking in-memory

### Risposta operativa:
Quando il sistema rileva un numero anomalo di richieste ripetute verso gli endpoint del servizio, provenienti dallo stesso indirizzo IP o da pattern riconducibili a tentativi di accesso automatizzati, viene attivata una protezione automatica.

L’indirizzo IP responsabile viene temporaneamente bloccato e le richieste successive vengono rifiutate.
Il livello di logging viene incrementato per consentire un’analisi dettagliata dell’attività sospetta.

L’evento viene registrato come tentativo di intrusione.

### [Elenco dei problemi](#elenco-dei-problemi)
---

## 6-Correlazione tra anomalie di rete e degrado del servizio bancario
In un sistema bancario reale, i problemi più complessi non sono quelli che causano un’interruzione immediata del servizio, ma quelli che **ne degradano progressivamente la qualità** senza generare errori evidenti.

Questo tipo di situazione è particolarmente critico perché:
- i servizi risultano formalmente attivi
- le porte sono aperte
- le API rispondono
- i clienti riescono comunque a operare
Eppure, l’esperienza utente peggiora nel tempo.

Questo problema affronta il tema della **correlazione tra fenomeni di rete apparentemente innocui e il degrado misurabile del servizio bancario**.

### Scenario operativo

Il problema si manifesta quando:
- il server bancario risulta raggiungibile
- non vengono rilevati crash o errori critici
- i servizi restano in ascolto sulle porte previste
- i log applicativi non segnalano anomalie gravi

Tuttavia, si osservano:
- aumento dei tempi di risposta
- rallentamenti nelle operazioni bancarie
- sessioni più lunghe del normale
- timeout sporadici lato client
Dal punto di vista applicativo, il problema NON è immediatamente diagnosticabile.

### Obiettivo dell’analisi

Individuare:
- anomalie di rete
- crescita del numero di connessioni
- aumento dei socket attivi
- utilizzo anomalo delle porte
contribuiscano al degrado progressivo del servizio bancario.

L’obiettivo non è identificare un singolo evento, ma **dimostrare una relazione causale o temporale** tra:
- stato della rete
- comportamento dei servizi
- qualità del servizio percepita

### Caratteristiche del comportamento osservato

I pattern tipici includono:
- crescita graduale delle connessioni TCP
- socket che rimangono aperti più a lungo del previsto
- aumento delle connessioni in stato **`ESTABLISHED`**
- maggiore occupazione delle porte critiche

Ulteriori indicatori:
- backlog di connessioni
- aumento delle connessioni in **`TIME_WAIT`**
- riduzione della capacità di accettare nuove richieste
- rallentamenti anche in assenza di picchi di traffico

### Risultati dell’analisi

L’analisi consente di:
- correlare metriche di rete con degrado del servizio
- distinguere carico legittimo da abuso
- identificare colli di bottiglia a livello di socket
- giustificare interventi correttivi infrastrutturali

I risultati possono portare a:
- ottimizzazione della gestione delle connessioni
- revisione dei timeout
- tuning dei servizi esposti
- miglioramento delle policy di monitoraggio

### Focus tecnico

La risoluzione del problema richiede **analisi della topologia di rete e correlazione tra dispositivi**, senza dipendere da log applicativi.

Attività principali:
- ispezione della configurazione di rete locale tramite **`ip`**
- analisi delle interfacce e degli indirizzi assegnati
- verifica delle route e dei gateway
- mappatura della rete locale tramite **`arp -a`**
- test di raggiungibilità con **`ping`** per misurare RTT
- correlazione tra metriche di rete e degrado percepito

Strumenti e comandi chiave:
- **`ip addr show`** (o `ip a`) → visualizza interfacce e IP
- **`ip route show`** (o `ip r`) → tabella di routing
- **`arp -a`** → cache ARP, mapping IP-MAC
- **`ping -c 4 <ip>`** → test connettività e Round-Trip Time
- **`ping -c 10 -i 0.2`** → ping rapido per stress test
- correlazione manuale tra latenza e degrado servizio

### [Elenco dei problemi](#elenco-dei-problemi)
---

## 7-Rilevamento di pattern anomali nell’utilizzo delle API bancarie
In un sistema bancario moderno, le API non sono utilizzate tutte allo stesso modo. Ogni tipologia di client (app mobile, ATM, servizi interni, integrazioni esterne) presenta **pattern di utilizzo distinti**, prevedibili e ripetibili nel tempo.

Quando questi pattern vengono alterati, anche senza generare errori o picchi evidenti, possono indicare:
- abuso delle API
- automazione non autorizzata
- utilizzo improprio di endpoint sensibili
- compromissione parziale di credenziali

Questo problema si concentra sull’**analisi comportamentale dell’uso delle API**, osservata dal punto di vista della rete.

### Scenario operativo

Il problema emerge quando:
- le API risultano operative
- le risposte sono formalmente corrette
- non si registrano errori applicativi
- il traffico rientra in volumi apparentemente normali

Tuttavia, l’osservazione nel tempo rivela:
- sequenze di chiamate atipiche
- uso ripetuto di endpoint non coerenti con il profilo del client
- mancanza di operazioni successive “logiche”
- traffico API concentrato su specifiche funzionalità

Dal punto di vista applicativo, il comportamento può sembrare legittimo. A livello di rete, invece, emergono **schemi anomali**.

### Obiettivo dell’analisi

Individuare utilizzi delle API che:
- non rispettano il flusso funzionale previsto
- mostrano una sequenza ripetitiva e meccanica
- differiscono dal comportamento medio degli utenti
- risultano incompatibili con il contesto operativo

L’obiettivo è distinguere:
- utilizzo normale delle API
- automazioni lecite
- test o integrazioni errate
- sfruttamento sistematico delle API

### Caratteristiche del comportamento sospetto

I pattern anomali includono:
- chiamate ripetute agli stessi endpoint
- assenza di variabilità nelle richieste
- utilizzo intenso di endpoint informativi
- frequente apertura e chiusura di connessioni

Ulteriori indicatori:
- utilizzo delle API in orari inconsueti
- numero elevato di richieste senza operazioni bancarie reali
- concentrazione del traffico su un sottoinsieme di endpoint
- pattern temporali regolari (tipici di script automatizzati)

### Risultati dell’analisi

L’analisi consente di:
- individuare comportamenti API non coerenti
- separare traffico umano da traffico automatizzato
- identificare endpoint particolarmente esposti
- supportare decisioni di limitazione o revisione

I risultati possono portare a:
- introduzione di controlli comportamentali
- limitazione di endpoint sensibili
- revisione della documentazione API
- rafforzamento delle politiche di sicurezza

### Focus tecnico

L'analisi è basata su **test attivo delle API e cattura del traffico HTTP**, senza accesso ai log applicativi.

Attività principali:
- test sistematico degli endpoint API tramite **`curl`**
- verifica dei codici di stato HTTP (200, 401, 404, 500)
- misurazione dei tempi di risposta
- cattura del traffico HTTP con **`tshark`** per analizzare user-agent
- identificazione di pattern automatizzati (bot, script)
- confronto tra profili di utilizzo umani vs automatizzati

Strumenti e comandi chiave:
- **`curl -X GET/POST http://localhost:8000/api/endpoint`**
- **`curl -w "%{http_code}"`** → codice di stato HTTP
- **`curl -o /dev/null -s -w "%{time_total}"`** → tempo risposta
- **`tshark -Y "http" -T fields -e http.user_agent`**
- **`tshark -Y "http.request.uri contains \"/api\""`**
- analisi frequenza richieste e pattern temporali

### [Elenco dei problemi](#elenco-dei-problemi)
---

## 8-Rilevamento di canali di comunicazione covert all’interno del traffico bancario
In un’infrastruttura bancaria reale, non tutte le minacce si manifestano attraverso traffico voluminoso o comportamenti chiaramente anomali. Alcuni degli scenari più critici riguardano l’uso di canali di **comunicazione covert**, ovvero comunicazioni nascoste all’interno di traffico apparentemente legittimo.

Questo tipo di canali può essere utilizzato per:
- esfiltrazione lenta di dati
- comunicazione con sistemi compromessi
- mantenimento di accessi persistenti
- aggiramento di controlli di sicurezza tradizionali

Il problema affronta l’individuazione di **comunicazioni non previste**, osservabili solo tramite un’analisi approfondita del comportamento di rete.

### Scenario operativo

Il problema si manifesta quando:
- i servizi bancari risultano operativi
- il traffico di rete appare regolare
- le porte utilizzate sono autorizzate
- non vengono generati errori o alert

Tuttavia, osservando il traffico nel tempo, emergono:
- connessioni persistenti anomale
- comunicazioni a intervalli regolari
- utilizzo di porte standard per scopi non previsti
- traffico costante anche in assenza di attività utente

Dal punto di vista funzionale, **nulla sembra fuori posto**.

### Obiettivo dell’analisi

Individuare flussi di comunicazione che:
- sfruttano servizi e porte legittime
- mantengono connessioni persistenti non giustificate
- presentano pattern temporali artificiali
- risultano incoerenti con l’operatività bancaria

L’obiettivo è rilevare:
- canali di controllo nascosti
- tunneling di comunicazioni
- uso improprio di servizi di rete
- compromissioni silenziose dell’infrastruttura

### Caratteristiche del comportamento sospetto

I canali covert presentano spesso:
- traffico a bassa intensità ma continuo
- pacchetti o connessioni a intervalli regolari
- assenza di picchi o burst di traffico
- utilizzo delle stesse porte per periodi prolungati

Ulteriori indicatori:
- connessioni che non producono operazioni bancarie
- socket sempre attivi senza variazioni significative
- traffico che persiste anche durante finestre di inattività
- comunicazioni non correlate a richieste utente

### Risultati dell’analisi

L’analisi consente di:
- individuare flussi di rete sospetti
- distinguere traffico operativo da traffico anomalo
- identificare servizi usati come canali nascosti
- supportare attività di containment e remediation

I risultati possono portare a:
- isolamento del servizio coinvolto
- blocco selettivo delle comunicazioni
- revisione delle policy di rete
- audit di sicurezza approfonditi

### Focus tecnico

La risoluzione del problema si basa su **deep packet inspection** con analisi approfondita del traffico di rete.

Attività principali:
- cattura completa dei pacchetti tramite **`tcpdump`**
- ispezione del payload a livello applicativo
- analisi delle dimensioni dei pacchetti
- rilevamento di anomalie nelle dimensioni (troppo piccoli/grandi)
- identificazione di pattern nascosti nel traffico apparentemente legittimo
- correlazione tra traffico persistente e assenza di operazioni

Strumenti e comandi chiave:
- **`tcpdump -i lo -n tcp port 8000`** → cattura traffico server
- **`tcpdump -X`** → visualizza payload in hex+ASCII
- **`tcpdump -w capture.pcap`** → salva cattura per analisi offline
- **`tcpdump -r capture.pcap`** → legge cattura salvata
- **analisi dimensioni**: confronto tra packet size medio e anomalie
- **analisi pattern**: identificazione di traffico regolare/artificiale

### [Elenco dei problemi](#elenco-dei-problemi)
---

## 9-Rilevamento di incoerenze tra contesto di rete e tipologia di operazione
In un sistema bancario reale, **non tutte le operazioni sono lecite solo perché tecnicamente valide**.
Ogni azione bancaria dovrebbe essere coerente con il **contesto di rete** in cui avviene: origine della connessione, tipo di dispositivo, canale di accesso e modalità di comunicazione.

Questo problema affronta uno scenario spesso trascurato: operazioni **formalmente corrette ma contestualmente incoerenti**, che rappresentano uno dei segnali più affidabili di compromissione.

### Scenario operativo

Il problema si manifesta quando:
- le operazioni bancarie sono valide
- non vengono generati errori applicativi
- le credenziali risultano corrette
- i servizi rispondono normalmente

Tuttavia, analizzando il contesto di rete, emergono situazioni come:
- bonifici effettuati da indirizzi IP tipici degli ATM
- prelievi simulati da connessioni API
- operazioni ad alto impatto provenienti da canali non coerenti
- accessi amministrativi da endpoint pubblici

Dal punto di vista applicativo, l’operazione è accettata.
Dal punto di vista sistemico, il **contesto non torna**.

### Obiettivo dell’analisi

Individuare operazioni che:
- non sono coerenti con il canale di accesso
- violano il modello operativo atteso
- avvengono da contesti di rete incompatibili
- suggeriscono abuso o uso improprio delle credenziali

L’obiettivo è correlare:
- tipo di operazione
- origine della connessione
- porte e servizi utilizzati
- profilo del client
per rilevare comportamenti anomali che **non emergono dall’analisi dei soli dati**.

### Caratteristiche del comportamento sospetto

Le incoerenze tipiche includono:
- ATM che effettuano bonifici
- API che simulano operazioni fisiche
- accessi critici da IP non previsti
- utilizzo di porte corrette da contesti errati

Ulteriori segnali:
- ripetizione sistematica di operazioni incoerent
- assenza di traffico “di contorno” tipico
- utilizzo improprio di endpoint
- mismatch tra ruolo del client e azione eseguita

### Risultati dell’analisi

L’analisi consente di:
- individuare operazioni sospette ad alto rischio
- classificare le incoerenze per gravità
- supportare decisioni di blocco selettivo
- rafforzare i modelli di trust del sistema

I risultati possono portare a:
- invalidazione di sessioni sospette
- sospensione preventiva degli account
- revisione delle regole di accesso
- miglioramento delle policy di sicurezza

### Focus tecnico

La risoluzione del problema richiede **analisi avanzata del percorso di rete e risoluzione DNS inversa**.

Attività principali:
- tracciamento del percorso di rete tramite **`traceroute`**
- conteggio degli hop (salti) tra client e server
- rilevamento di percorsi anomali (troppi hop, route incoerenti)
- risoluzione DNS inversa con **`dig`** per verificare PTR records
- correlazione tra origine IP, percorso di rete e tipo di operazione
- identificazione di mismatch tra contesto e azione

Strumenti e comandi chiave:
- **`traceroute <ip_address>`** → traccia percorso di rete
- **`traceroute -n`** → evita risoluzione DNS durante trace
- **conteggio hop**: `traceroute | wc -l`
- **`dig -x <ip_address>`** → reverse DNS lookup (PTR record)
- **`dig +short -x <ip>`** → solo risultato PTR
- classificazione IP per tipologia (ATM, client, API) in base a hop e DNS

### Risposta operativa:
Quando un’operazione bancaria non risulta coerente con il contesto tecnico della connessione (origine di rete, dispositivo o profilo operativo), il sistema applica una verifica preventiva.

La transazione viene temporaneamente sospesa e classificata come operazione ad alto rischio.
L’utente deve confermare l’operazione tramite un meccanismo di autorizzazione rafforzata prima che possa essere eseguita.

L’evento viene registrato per analisi antifrode e monitoraggio comportamentale.

### [Elenco dei problemi](#elenco-dei-problemi)
---

## 10-Rilevamento di comportamenti “silenziosi” ad alto impatto
Non tutti gli attacchi sono visibili a primo impatto.
In banca, i più pericolosi sono quelli **lenti, distribuiti e apparentemente innocui**.

Analizzare l’evoluzione temporale delle connessioni e delle richieste al server bancario per individuare comportamenti anomali caratterizzati da bassa intensità ma alta persistenza.
L’analisi mira a rilevare pattern che, pur non superando soglie critiche istantanee, producono nel tempo un impatto significativo sulle risorse di rete e sui servizi esposti.

L’obiettivo è individuare **abusi graduali e difficili da rilevare**, tipici degli attacchi mirati a infrastrutture critiche.

Vengono individuati comportamenti a basso impatto immediato che:
- non generano errori
- non saturano il server
- non violano regole evidenti

Attacchi del genere seguono un **pattern ben preciso**:
- poche connessioni per volta
- sempre valide
- sempre sulle porte corrette
- distribuite nel tempo

I risultati sono i seguenti:
- aumento graduale dei socket attivi
- degrado delle performance del server
- difficoltà a distinguere traffico legittimo da abuso

**Focus tecnico**

La risoluzione del problema si basa su **monitoraggio delle metriche temporali delle connessioni TCP**, senza analisi dei contenuti applicativi.

Attività principali:
- monitoraggio delle connessioni TCP attive con **`ss -tno`**
- analisi dei timer di connessione (durata, keepalive, retransmit)
- misurazione della persistenza delle socket nel tempo
- calcolo del rate di richieste (richieste/secondo)
- identificazione di connessioni a lunga durata sospette
- rilevamento di pattern "low and slow"

Strumenti e comandi chiave:
- **`ss -tno state established`** → mostra timer TCP dettagliati
- **`ss -tno | grep "timer:"`** → filtra connessioni con timer attivi
- estrazione durata connessioni da output timer
- **calcolo rate**: numero_richieste / durata_connessione
- confronto con baseline normale (es. < 0.5 req/s = sospetto)
- tracciamento temporale per identificare attacchi distribuiti

### [Elenco dei problemi](#elenco-dei-problemi)
---
---

## Conclusioni

Il progetto ha simulato un’infrastruttura bancaria operante su sistema GNU/Linux, concentrandosi sull’analisi del comportamento di rete, dei servizi esposti e delle interazioni tra client, ATM e API applicative.

Attraverso la generazione controllata di traffico e l’analisi di porte, socket e connessioni attive, sono stati individuati e affrontati diversi scenari critici realistici, tipici di contesti bancari e di infrastrutture critiche.  
I problemi analizzati non si limitano alla semplice estrazione di dati, ma mirano a correlare il contesto di rete con il comportamento applicativo, evidenziando anomalie che, in un ambiente reale, potrebbero indicare frodi, compromissioni o configurazioni errate.

Le soluzioni proposte sono state implementate tramite script Bash modulari e riutilizzabili, progettati per essere eseguiti in ambienti GNU/Linux standard e facilmente adattabili a scenari simili.  
L’approccio adottato privilegia l’analisi comportamentale e infrastrutturale rispetto alla semplice interrogazione dei dati, in linea con le pratiche reali di monitoraggio e sicurezza dei sistemi bancari.

Il progetto dimostra come, anche in un contesto simulato, sia possibile applicare metodologie e strumenti concreti per l’analisi e la protezione di sistemi complessi.
