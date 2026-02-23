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
./run_problem.sh
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

- **Spiegazione semplificata:** un'operazione lecita da una subnet sbagliata è sospetta.
- **Come rileva:** mappa subnet (clienti/ATM/API/admin) e verifica coerenza azione vs IP.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 70/90), blocca se `risk_score >= 100`, log in `logs/incoerenza_rete_alerts.log`.

### 10 - Low & Slow ad alto impatto

- **Spiegazione semplificata:** poche richieste ma persistenti nel tempo possono degradare il servizio.
- **Come rileva:** individua IP con 3-8 richieste in 60s e rate basso.
- **Dopo la rilevazione:** aggiunge l'`IP` in blacklist (risk 60), blocca se `risk_score >= 100`, log in `logs/low_slow_attacks.log`.

## Note

- Gli script terminano al primo alert per ridurre il rumore.
- I log principali sono in `logs/` e possono essere ruotati o puliti a piacere.
