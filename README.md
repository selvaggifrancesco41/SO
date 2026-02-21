# PROGETTO_SERVER_BANCA
Progetto svolto individualmente che riprende una simulazione realistica in sistema operativo GNU/LINUX

# Contesto del progetto

Il progetto simula un server **GNU/Linux** che ospita un’applicazione bancaria fittizia, utilizzata da clienti simulati per effettuare operazioni tipiche come:

- accessi
- prelievi
- depositi
- bonifici

Il sistema è progettato per generare **traffico applicativo e di rete artificiale ma realistico**, con l’obiettivo di analizzare il comportamento del server, delle connessioni di rete, delle porte e dei socket attivi.

L’intero scenario riproduce una situazione **plausibile e credibile** che potrebbe verificarsi su un server reale in ambiente GNU/Linux.

---

## Obiettivi del progetto

L’obiettivo del progetto è simulare un’infrastruttura bancaria operante su sistema GNU/Linux e analizzarne il comportamento dal punto di vista della rete, dei servizi esposti e delle interazioni tra client, ATM e componenti applicative.

In particolare, il progetto si pone i seguenti obiettivi:

- **simulare un ambiente bancario realistico**, includendo utenti, ATM, API applicative e servizi di rete;
- **generare traffico controllato e plausibile** verso il server, anche tramite l’utilizzo di task schedulati;
- **registrare** in modo strutturato **le richieste** ricevute e le azioni eseguite, mantenendo una traccia cronologica degli eventi;
- **analizzare** porte, socket e connessioni attive per individuare anomalie, incoerenze e comportamenti sospetti;
- **definire** e **risolvere** problematiche realistiche legate alla sicurezza, all’affidabilità e alle prestazioni di un sistema bancario;
- utilizzare prevalentemente strumenti e **comandi di rete** tipici degli ambienti GNU/Linux, riducendo al minimo l’interrogazione diretta dei dati applicativi;
- **progettare soluzioni** tramite script Bash modulari, *riutilizzabili* e *adattabili* a contesti simili.

L’approccio adottato mira a riprodurre scenari e criticità reali, ponendo l’attenzione non solo sulle singole operazioni, ma soprattutto sulla coerenza tra comportamento applicativo e contesto infrastrutturale.

**L’analisi dei problemi viene effettuata attraverso l’individuazione e la definizione di 10 problematiche distinte, coerenti con il contesto simulato e finalizzate all’analisi del comportamento di rete e dei servizi del sistema.**


---

## Elenco dei problemi

1. [Rilevamento di flussi anomali di bonifici in ingresso (AML)](#1-rilevamento-di-flussi-anomali-di-bonifici-in-ingresso-anti-money-laundering)
2. [Individuazione di accessi simultanei sospetti dallo stesso account](#2-individuazione-di-accessi-simultanei-sospetti-dallo-stesso-account)
3. [Analisi degli accessi notturni fuori dal profilo abituale](#3-analisi-degli-accessi-notturni-fuori-dal-profilo-abituale)
4. [Rilevamento ATM che comunicano su porte non autorizzate](#4-rilevamento-atm-che-comunicano-su-porte-non-autorizzate)
5. [Rilevamento tentativi di brute-force sulle API del server](#5-rilevamento-tentativi-di-brute-force-sulle-api-del-server)
6. [Correlazione tra anomalie di rete e degrado del servizio bancario](#6-correlazione-tra-anomalie-di-rete-e-degrado-del-servizio-bancario)
7. [Rilevamento di pattern anomali nell’utilizzo delle API bancarie](#7-rilevamento-di-pattern-anomali-nellutilizzo-delle-api-bancarie)
8. [Rilevamento di canali di comunicazione covert all’interno del traffico bancario](#8-rilevamento-di-canali-di-comunicazione-covert-allinterno-del-traffico-bancario)
9. [Rilevamento di incoerenze tra contesto di rete e tipologia di operazione](#9-rilevamento-di-incoerenze-tra-contesto-di-rete-e-tipologia-di-operazione)
10. [Rilevamento di comportamenti “silenziosi” ad alto impatto (Low & Slow)](#10-rilevamento-di-comportamenti-silenziosi-ad-alto-impatto)


---

## Dataset utilizzato

Il progetto utilizza un file CSV denominato **`clienti_banca.csv`**, che rappresenta l’anagrafica statica dei clienti della banca.

### Intestazione del file

```csv
customer_id,first_name,last_name,tax_code,email,phone_number,address,city,postal_code,country,password_hash,two_factor_enabled,account_status,account_id,iban,account_type,account_balance,currency,card_id,card_number,card_expiry,card_status,last_login,opened_at
```

Il dataset contiene esclusivamente dati simulati ed è utilizzato come base informativa, non come database reale.

I dati anagrafici sono separati dai log applicativi per mantenere una struttura coerente e realistica.

---

### Generazione del traffico e degli eventi

Il traffico applicativo viene generato tramite **script Bash** pianificati con cron, che simulano il comportamento di più clienti che interagiscono contemporaneamente con il server.

Gli script simulano:

- accessi e disconnessioni
- prelievi e depositi
- bonifici verso IBAN differenti
- accessi da indirizzi IP diversi
- sessioni concorrenti

---

## Log degli eventi applicativi

Ogni interazione con il server genera un evento registrato in un file di log strutturato, che rappresenta la **principale fonte** di raccoglimento dati del progetto.

Gli eventi applicativi vengono registrati in tempo reale in un **database SQLite**, scelto per la sua leggerezza, affidabilità e idoneità alla gestione di log cronologici in ambienti GNU/Linux.

### Esempio di file .log

```sql
timestamp,customer_id,ip_address,azione,importo,iban_destinatario,session_duration,source_type
2026-02-02 10:15:03,1023,192.168.1.45,LOGIN,,,,USER
2026-02-02 10:18:21,1023,192.168.1.45,BONIFICO,500,IT60X0542811101000000123456,180,USER

```

### Azioni registrate
- **`LOGIN`**
- **`LOGOUT`**
- **`PRELIEVO`**
- **`DEPOSITO`**
- **`BONIFICO`**

---

## Analisi di rete e di sistema
Il focus principale del progetto **non è l’elaborazione dei dati anagrafici**, ma l’analisi del comportamento del server dal punto di vista di **rete e di sistema**.

### Oggetti dell'analisi
- porte aperte
- socket attivi
- servizi in ascolto
- connessioni simultanee
- utilizzo anomalo delle risorse di rete

---

## Interazione con il dataset clienti
L'interazione con il file **`clienti_banca.csv`** è limitata al recupero delle informazioni di supporto, ad esempio per verificare lo stato di un account o la mail di chi accede.

### Esempio

```terminal
grep ",active," clienti_banca.csv
```
la maggior parte delle analisi viene effettuata **senza interrogare direttamente l'anagrafica**, concentrandosi sui log applicativi e sullo stato del sistema.

---

## Simulazione di dispositivi fisici (ATM)

Il progetto include la simulazione di **dispositivi fisici bancari**, in particolare **ATM (Automated Teller Machine)**, che interagiscono con il server tramite rete, analogamente a quanto avverrebbe in un contesto reale.

Gli ATM simulati utilizzano una subnet dedicata **`(192.168.100.0/24)`**, separata dal traffico degli utenti, al fine di **facilitare l’analisi** delle connessioni di rete e l’individuazione di comportamenti anomali.

Gli ATM sono trattati come **entità distinte dagli utenti finali**, caratterizzate da:
- indirizzo IP dedicato
- comportamento automatico
- operazioni ripetitive (prelievi, interrogazioni)
- assenza di interazione diretta con l’interfaccia utente

---

La simulazione degli ATM consente di introdurre una componente “fisica” nell’ecosistema del progetto, mantenendo un approccio coerente con un ambiente GNU/Linux e con l’analisi delle risorse di rete.


Per distinguere le operazioni effettuate dagli utenti da quelle generate da dispositivi fisici, il database degli eventi include un campo aggiuntivo che identifica la **tipologia di sorgente** dell’evento.

### Schema logico degli eventi:

```sql
timestamp,customer_id,ip_address,azione,importo,iban_destinatario,session_duration,source_type
```
Dove **`source_type`** può assumere valori come:
- **`USER`** -> operazione effettuata da un cliente
- **`ATM`** -> operazione effettuata da un dispositivo fisico

--- 

# Problemi affrontati:

## 1-Rilevamento di flussi anomali di bonifici in ingresso (Anti-Money Laundering)
Nel contesto bancario moderno, una delle principali minacce non deriva da singole operazioni chiaramente fraudolente, ma da **schemi di trasferimento distribuiti**, progettati per aggirare i controlli automatici antiriciclaggio (AML).
Un conto corrente può apparire perfettamente legittimo se analizzato superficialmente, ma diventare sospetto quando si osserva il **comportamento aggregato dei bonifici in ingresso nel tempo**. In particolare, la ricezione ravvicinata di fondi provenienti da **IBAN diversi e non correlati** può indicare attività di money laundering, layering o utilizzo del conto come nodo di smistamento.

### Scenario operativo

Il problema si manifesta quando un cliente riceve, in un intervallo temporale ristretto:

- numerosi bonifici di importo medio-basso
- provenienti da conti diversi
- senza una relazione evidente tra mittenti e beneficiario

Ogni singola transazione risulta formalmente valida, autorizzata e coerente con le regole di sistema. Tuttavia, l’insieme delle operazioni evidenzia un **pattern anomalo** rispetto al profilo abituale del conto.


### Obiettivo dell’analisi

Analizzare i flussi di bonifici in ingresso per individuare conti che presentano comportamenti compatibili con attività sospette, senza basarsi esclusivamente su soglie statiche di importo.

L’analisi mira a:

- rilevare concentrazioni anomale di bonifici nel tempo
- correlare numero di mittenti unici e frequenza delle transazioni
- confrontare il comportamento attuale con lo storico del conto

L’obiettivo finale è **segnalare il conto come potenzialmente sospetto** e attivare misure di verifica preventiva, come l’invio di comunicazioni al cliente o l’escalation verso sistemi AML.

### Caratteristiche del comportamento sospetto

I conti individuati presentano tipicamente:
- molti mittenti diversi
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
