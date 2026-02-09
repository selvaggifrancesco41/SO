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

L’implementazione del problema prevede:
- analisi del file CSV delle transazioni
- raggruppamento per IBAN beneficiario
- conteggio mittenti unici su finestre temporali
- correlazione tra frequenza, importi e tempo
- generazione di alert e log dedicati


### Strumenti e concetti chiave:
- parsing e analisi log applicativi
- finestre temporali scorrevoli
- metriche comportamentali
- simulazione di alert AML

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

L’implementazione del problema prevede:
- analisi dei log di autenticazione
- tracciamento delle sessioni attive
- correlazione temporale tra login e logout
- associazione sessione–IP–timestamp
- rilevamento di overlap temporali

Strumenti e concetti chiave:
- parsing dei log di accesso
- gestione delle sessioni applicative
- correlazione temporale
- analisi per account
- simulazione di alert di sicurezza

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

La risoluzione del problema prevede:
- analisi dei timestamp di login
- aggregazione degli accessi per fascia oraria
- costruzione di baseline temporali per account
- confronto tra attività corrente e storica
- rilevamento di outlier temporali

Strumenti e concetti chiave:
- parsing dei log di accesso
- analisi statistica delle fasce orarie
- correlazione temporale
- profiling comportamentale
- simulazione di policy di sicurezza adattive

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

La risoluzione del problema si basa prevalentemente su **strumenti di rete**, senza interrogazioni dirette al database.

Attività principali:
- monitoraggio delle porte in ascolto
- analisi delle connessioni attive
- verifica dei servizi esposti
- confronto con le policy definite

Strumenti e comandi chiave:
- **`ss -tuln`**
- **`ss -tan`**
- **`netstat -tulnp`**
- **`lsof -i -P -n`**
- **`sudo lsof -i -P -n | grep LISTEN`**
- **`nmap localhost`**
- **`sudo nmap -p- localhost`**

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

La risoluzione del problema è fortemente orientata all’**analisi delle connessioni di rete**, senza necessità di interrogare direttamente il database utenti.

Attività principali:
- monitoraggio delle connessioni verso le API
- conteggio delle richieste nel tempo
- analisi della persistenza dei socket
- individuazione di pattern ripetitivi

Strumenti e comandi chiave:
- **`ss -tan`**
- **`ss -tan | grep :<porta_api>`**
- **`netstat -ant`**
- **`lsof -i -P -n`**
- **`curl`** (per simulare richieste)
- **`nc`** (per test di connessione)

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

La risoluzione del problema richiede analisi temporale e comparativa, non una singola fotografia dello stato del sistema.

Attività principali:
- monitoraggio continuo delle connessioni
- confronto tra periodi di funzionamento normale e degradato
- conteggio dei socket nel tempo
- analisi dello stato delle porte critiche

Strumenti e comandi chiave:
- **`ss -tan`**
- **`ss -s`**
- **`netstat -ant`**
- conteggio socket nel tempo
- **`lsof -i -P -n`**
correlazione con degrado simulato del servizio

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

L’analisi è prevalentemente basata su **osservazione del traffico e delle connessioni**, senza analizzare il payload delle richieste.

Attività principali:
- analisi della frequenza delle connessioni
- osservazione delle sequenze di chiamate
- confronto tra diversi profili di utilizzo
- rilevamento di pattern ripetitivi

Strumenti e comandi chiave:
- **`ss -tan`**
- **`netstat -ant`**
- **`lsof -i -P -n`**
- **`curl`** (simulazione pattern API)
- **`nc`**
- analisi temporale delle connessioni

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

La risoluzione del problema si basa esclusivamente su **osservazione e correlazione del traffico di rete**, senza analisi del contenuto applicativo.

Attività principali:
- analisi della persistenza delle connessioni
- osservazione dei pattern temporali
- verifica dell’uso delle porte standard
- confronto con il comportamento atteso

Strumenti e comandi chiave:
- **`ss -tan`**
- **`ss -s`**
- **`netstat -ant`**
- **`lsof -i -P -n`**
- monitoraggio delle connessioni nel tempo
- **`nc`** (per simulare canali persistenti)

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

La risoluzione del problema richiede **correlazione tra più livelli**, con forte enfasi sulla rete.

Attività principali:
- classificazione degli IP per tipologia (ATM, utenti, API)
- analisi delle porte utilizzate
- correlazione con il tipo di operazione
- confronto con il comportamento atteso

Strumenti e comandi chiave:
- **`ss -tan`**
- **`netstat -ant`**
- **`lsof -i -P -n`**
- **`nmap localhost`**
- classificazione IP per ruolo
- correlazione rete–operazione

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
- **`ss -tan`**
- conteggio socket nel tempo
- porte e servizi
- correlazione con degrado simulato del servizio

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
