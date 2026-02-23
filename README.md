# PROGETTO_SERVER_BANCA

## Introduzione

Questo progetto simula un server bancario GNU/Linux con monitoraggio di 10 anomalie
 di sicurezza. Il monitoraggio usa **solo** il flusso eventi in tempo reale scritto
 dal server in `logs/realtime_access.log` e non legge log storici o database per
 input.

Obiettivo principale:
- rilevare anomalie in tempo reale
- accumulare il rischio nel tempo
- garantire risposte rapide con alert immediati

Ogni script:
- legge il flusso con `tail -f`
- applica una finestra temporale di 60 secondi
- scrive un alert in `blacklist.csv`
- termina al primo rilevamento per mantenere i test rapidi

Il contesto e` realistico: flusso continuo, decisioni rapide, e tracciamento
 della recidivita` con risk score cumulativo.

## Architettura (sintesi)

```
/workspaces/SO/
├── script/                       # monitor + generatori di test
├── server/                       # server Flask
├── logs/realtime_access.log      # flusso eventi (input)
├── logs/notifiche_email.txt      # output notifiche (P02, P03)
├── blacklist.csv                 # output alert con risk cumulativo
├── clienti_banca.csv             # anagrafica clienti
└── README.md
```

## Esecuzione

Esegui un problema (monitor + test generator):

```bash
cd /workspaces/SO/script
./run_problem.sh 1
```

`run_problem.sh` avvia anche il server se non e` in esecuzione.

## Flusso eventi

Il server scrive righe nel formato:

```
timestamp|customer_id|ip|azione|importo|iban|session_duration
```

Campi:
- timestamp: data e ora della richiesta
- customer_id: identificativo cliente
- ip: IP sorgente
- azione: LOGIN, BONIFICO, PRELIEVO, DEPOSITO
- importo: valore numerico o vuoto
- iban: IBAN destinatario (solo per BONIFICO)
- session_duration: durata sessione (solo per LOGIN)

## Logica blacklist

Gli alert vengono sempre scritti in `blacklist.csv` con campi:

```
timestamp,tipo_elemento,elemento,azione_rilevata,gravita,recidivita,risk_score,stato,origine_rilevazione,note
```

Regole:
- `recidivita` e `risk_score` sono cumulativi per `tipo_elemento + elemento`.
- Quando il `risk_score` raggiunge 100, lo `stato` diventa `BLOCKED`.
- L accumulo e` gestito dalla funzione condivisa in `script/lib_blacklist.sh`.

Snippet base:

```bash
add_blacklist_entry "ACCOUNT" "$cid" "AZIONE" "GRAVITA" "RISK" "ORIGINE" "NOTE"
```

## Comandi usati (sintesi generale)

Questi comandi sono usati nei monitor e nei test generator:
- `tail -f` per seguire lo stream
- `awk -F` per separare campi
- `sort -u` per rimuovere duplicati
- `wc -l` per contare
- `grep -q` per match senza output
- `cut -d -f` per estrarre campi
- `date -d` e `date +%H` per la logica temporale
- `curl -s -G --data-urlencode` nei generatori

L elenco completo e le spiegazioni dei flag sono in
 `COMANDI_RETE_UTILIZZATI.md`.

## I 10 problemi (contesto, importanza, comandi, soluzione)

Di seguito ogni problema e` descritto con:
- motivazione e contesto
- importanza operativa
- comandi effettivi usati nello script
- logica di rilevamento
- snippet di codice
- caso di test

### P01 AML bonifici

**Contesto e motivazione**

Il riciclaggio di denaro si manifesta con molti bonifici da account diversi verso
 un singolo IBAN in poco tempo. Il singolo bonifico e` lecito, ma il pattern e`anomalo. Il problema e` stato scelto perche` rende visibile la differenza tra
 validita` della singola operazione e anomalia del comportamento aggregato.

**Perche` e` importante**
- riduce esposizione regolatoria
- segnala prima che i fondi siano dispersi
- offre un trigger chiaro per investigazioni AML

**Comandi usati**
- `tail -f` per seguire il flusso
- `awk -F'|'` per estrarre mittenti
- `sort -u` per unici
- `wc -l` per contare

**Logica di rilevamento**
1. legge solo eventi con `azione=BONIFICO`
2. salva mittente e IBAN in uno stato temporaneo
3. conta mittenti unici per IBAN
4. se la soglia e` >= 5, genera alert

**Snippet**

```bash
uniq=$(awk -F'|' -v i="$iban" '$2==i {print $1}' "$STATE" 2>/dev/null | sort -u | wc -l)
if [ $uniq -ge 5 ] && [ -z "${SEEN[$iban]}" ]; then
    add_blacklist_entry "ACCOUNT" "$cid" "FLUSSO_AML" "ALTA" "50" "AML_RETE" "Schema AML: $uniq mittenti verso IBAN $iban"
fi
```

**Cosa risolve**
- identifica schemi AML senza analisi storica estesa
- fornisce un alert prima che il comportamento si ripeta per ore

**Test**
Il generatore `test_01_aml_bonifici.sh` invia 6 bonifici verso lo stesso IBAN con
 mittenti diversi, entro pochi secondi.

**Output atteso**
- riga in `blacklist.csv` con `azione_rilevata=FLUSSO_AML`
- `risk_score` incrementato di 50

---

### P02 Accessi simultanei

**Contesto e motivazione**

Accessi simultanei dallo stesso account ma da IP diversi indicano session hijacking
 o credenziali condivise. E` un segnale forte e tipicamente affidabile. E' scelto
 perchè è immediato, misurabile, e con basso tasso di falsi positivi.

**Perchè è importante**
- segnala compromissione in corso
- permette intervento prima di operazioni sensibili
- attiva notifica al cliente se 2FA non e` attivo

**Comandi usati**
- `tail -f` per lo stream
- `awk -F'|'` e `sort -u` per IP unici
- `wc -l` per conteggio
- `cut -d'|' -f` per estrarre email e 2FA dal CSV

**Logica di rilevamento**
1. registra IP per ogni `customer_id`
2. conta IP unici nella finestra
3. se >= 3, genera alert
4. se 2FA non attivo, scrive notifica

**Snippet**

```bash
ips_unici=$(awk -F'|' -v c="$cid" '$1==c {print $2}' "$STATE" 2>/dev/null | sort -u | wc -l)
if [ $ips_unici -ge 3 ] && [ -z "${SEEN[$cid]}" ]; then
    add_blacklist_entry "ACCOUNT" "$cid" "ACCESSO_SIMULTANEO" "ALTA" "40" "ACCESSI_RETE" "$ips_unici IP simultanei"
fi
```

**Cosa risolve**
- evidenzia account compromessi in tempo reale
- supporta l allarme di sicurezza lato cliente

**Test**
`test_02_accessi_simultanei.sh` crea 4 login paralleli con IP diversi per lo stesso
 account.

**Output atteso**
- riga in `blacklist.csv` con `ACCESSO_SIMULTANEO`
- messaggio in `logs/notifiche_email.txt` se 2FA e` false

---

### P03 Accessi notturni

**Contesto e motivazione**

Gli accessi fuori profilo orario sono un segnale forte. Accessi notturni
 sono tipici di automazioni o attori malevoli. E' stato scelto perchè
 il contesto temporale è semplice da interpretare e utile per escalation.

**Perchè è importante**
- riduce falsi positivi con una regola chiara
- permette notifica del cliente
- evidenzia accessi fuori routine

**Comandi usati**
- `tail -f` per lo stream
- `date -d` per interpretare il timestamp
- `date +%H` per estrarre l ora

**Logica di rilevamento**
1. legge eventi LOGIN
2. determina l ora
3. se 22-06, genera alert
4. invia notifica

**Snippet**

```bash
hour=$(date -d "$ts" '+%H' 2>/dev/null || echo "12")
if [ "$hour" -ge 22 ] || [ "$hour" -lt 6 ]; then
    add_blacklist_entry "ACCOUNT" "$cid" "ACCESSO_NOTTURNO" "MEDIA" "30" "PROFILO_RETE" "Accesso anomalo $hour"
fi
```

**Cosa risolve**
- segnala attività sospetta in orari anomali
- abilita notifica tempestiva al cliente

**Test**
`test_03_accessi_notturni.sh` usa `TEST_MODE=1` per bypassare l orario reale.

**Output atteso**
- riga in `blacklist.csv` con `ACCESSO_NOTTURNO`
- notifica in `logs/notifiche_email.txt`

---

### P04 Subnet ATM

**Contesto e motivazione**

Gli ATM operano da subnet dedicate. Se appare traffico ATM in altri contesti
 e` indice di configurazione errata o compromissione. Il problema è scelto
 perchè è un segnale semplice ma ad alta criticità.

**Perchè è importante**
- gli ATM sono asset critici
- la subnet dedicata e` un confine di sicurezza naturale
- segnala subito anomalie di configurazione o abuso

**Comandi usati**
- `tail -f` per lo stream
- regex su IP per 192.168.30.x

**Logica di rilevamento**
1. legge eventi
2. se IP in subnet ATM, genera alert

**Snippet**

```bash
[[ "$ip" =~ ^192\.168\.30\. ]] || continue
add_blacklist_entry "IP" "$ip" "ATM_ANOMALO" "MEDIA" "35" "RETE_ATM" "IP ATM subnet 192.168.30.x rilevato"
```

**Cosa risolve**
- evidenzia traffico ATM inatteso
- aiuta a isolare rapidamente il nodo sospetto

**Test**
`test_04_atm_porte.sh` invia login da IP 192.168.30.x.

**Output atteso**
- riga in `blacklist.csv` con `ATM_ANOMALO`

---

### P05 Brute-force

**Contesto e motivazione**

Molti tentativi di login dallo stesso IP in poco tempo indicano brute-force.
 E` un problema classico perchè ha segnali semplici e misurabili.

**Perchè è importante**
- individua attacchi prima della compromissione
- consente escalation automatica o manuale

**Comandi usati**
- `tail -f` per lo stream
- `grep` e `wc -l` per contare tentativi

**Logica di rilevamento**
1. registra LOGIN per IP
2. conta tentativi in 60s
3. se >= 5, genera alert

**Snippet**

```bash
attempts=$(grep "^$ip|" "$STATE" 2>/dev/null | wc -l)
if [ $attempts -ge 5 ]; then
    add_blacklist_entry "IP" "$ip" "BRUTEFORCE_LOGIN" "ALTA" "50" "LOGIN_RETE" "$attempts tentativi LOGIN da $ip"
fi
```

**Cosa risolve**
- blocca escalation prima della riuscita dell attacco

**Test**
`test_05_bruteforce.sh` genera 15 login ravvicinati dallo stesso IP.

**Output atteso**
- riga in `blacklist.csv` con `BRUTEFORCE_LOGIN`

---

### P06 IP pubblico inatteso

**Contesto e motivazione**

In una rete interna o controllata, IP pubblici indicano accessi non autorizzati
 o bypass di segmentazione. Il problema è scelto perchè segnala
 violazioni di perimetro.

**Perchè è importante**
- rende visibili accessi da Internet
- aiuta a individuare tunnel o proxy non autorizzati

**Comandi usati**
- `tail -f` per lo stream
- regex per distinguere RFC1918 e pubblici

**Logica di rilevamento**
1. legge IP
2. se non RFC1918, genera alert

**Snippet**

```bash
if [ "$(is_public_ip "$ip")" = "1" ]; then
    add_blacklist_entry "IP" "$ip" "IP_PUBBLICO" "ALTA" "45" "RETE_PUBBLICA" "IP pubblico rilevato: $ip"
fi
```

**Cosa risolve**
- evidenzia accessi sospetti fuori perimetro

**Test**
`test_06_correlazione_rete.sh` invia login da IP pubblici noti.

**Output atteso**
- riga in `blacklist.csv` con `IP_PUBBLICO`

---

### P07 Pattern API

**Contesto e motivazione**

Bot e automazioni generano sequenze ripetitive. E' stato scelto perchè
 protegge l uso legittimo delle API.

**Perchè è importante**
- riduce abuso automatico
- limita degrado del servizio

**Comandi usati**
- `tail -f` per lo stream
- `grep` e `wc -l` per conteggio

**Logica di rilevamento**
1. registra richieste per IP
2. se >= 10 in 60s, genera alert

**Snippet**

```bash
requests=$(grep "^$ip|" "$STATE" 2>/dev/null | wc -l)
if [ $requests -ge 10 ]; then
    add_blacklist_entry "IP" "$ip" "PATTERN_API" "MEDIA" "35" "API_SPAM" "$requests richieste da $ip"
fi
```

**Cosa risolve**
- segnala automazioni sospette

**Test**
`test_07_pattern_api.sh` invia sequenze ripetitive da un IP fisso.

**Output atteso**
- riga in `blacklist.csv` con `PATTERN_API`

---

### P08 Covert channels

**Contesto e motivazione**

Bonifici con importo 0 sono spesso segnali mascherati. Il problema è scelto
 perchè individua canali di comunicazione nascosti.

**Perchè è importante**
- intercetta segnali C2 o esfiltrazioni
- blocca pattern di segnalazione nascosta

**Comandi usati**
- `tail -f` per lo stream
- confronto diretto su `azione` e `importo`

**Logica di rilevamento**
1. se azione BONIFICO
2. se importo 0
3. genera alert

**Snippet**

```bash
if [ "$az" = "BONIFICO" ] && [ "$imp" = "0" ]; then
    add_blacklist_entry "ACCOUNT" "$cid" "COVERT_CHANNEL" "MEDIA" "40" "BONIFICO_ZERO" "Bonifico con importo=0"
fi
```

**Cosa risolve**
- segnala canali covert in transazioni

**Test**
`test_08_covert_channels.sh` invia bonifici con importo=0.

**Output atteso**
- riga in `blacklist.csv` con `COVERT_CHANNEL`

---

### P09 Incoerenza rete

**Contesto e motivazione**

Un ATM non dovrebbe eseguire BONIFICO. Questa incoerenza è un segnale critico.
 E' stato scelto perchè richiede una risposta immediata.

**Perchè è importante**
- segnala compromissione o uso improprio
- attiva subito blocco ad alto rischio

**Comandi usati**
- `tail -f` per lo stream
- regex subnet ATM

**Logica di rilevamento**
1. se IP ATM
2. se azione BONIFICO
3. genera alert con risk 100

**Snippet**

```bash
if [[ "$ip" =~ ^192\.168\.30\. ]] && [ "$az" = "BONIFICO" ]; then
    add_blacklist_entry "IP" "$ip" "INCOERENZA_RETE" "ALTA" "100" "ATM_BONIFICO" "ATM (192.168.30.x) esegue BONIFICO"
fi
```

**Cosa risolve**
- blocco immediato di traffico ATM incoerente

**Test**
`test_09_incoerenza_rete.sh` invia un BONIFICO da IP ATM.

**Output atteso**
- riga in `blacklist.csv` con `INCOERENZA_RETE` e `BLOCKED`

---

### P10 Low & slow

**Contesto e motivazione**

Gli attacchi low & slow non superano soglie immediate ma degradano il servizio
 nel tempo. E' stato scelto perchè è un caso spesso trascurato.

**Perchè è importante**
- individua attacchi lenti prima che diventino sistemici
- integra la difesa con segnali a bassa intensita`

**Comandi usati**
- `tail -f` per lo stream
- `grep` e `wc -l` per conteggio per account

**Logica di rilevamento**
1. verifica importo < 100
2. conta operazioni per account
3. se >= 8, genera alert

**Snippet**

```bash
if [ "$imp" -le 100 ]; then
    count=$(grep "^$cid|" "$STATE" 2>/dev/null | wc -l)
    if [ $count -ge 8 ]; then
        add_blacklist_entry "ACCOUNT" "$cid" "LOW_SLOW" "MEDIA" "35" "ATTACCO_LENTO" "$count operazioni lente/piccole"
    fi
fi
```

**Cosa risolve**
- rileva schemi di attacco distribuito a basso volume

**Test**
`test_10_low_slow.sh` distribuisce 8 operazioni con importo piccolo in ~24s.

**Output atteso**
- riga in `blacklist.csv` con `LOW_SLOW`


## Test

I generatori sono in `script/test_generators/` e vengono richiamati da
 `run_problem.sh`. Ogni test è progettato per superare la soglia del monitor
 corrispondente in un tempo breve.

Note importanti:
- P03 usa `TEST_MODE=1` nei test per bypassare l orario reale.
- P05 e P03 partono in `TEST_MODE` quando eseguiti via `run_problem.sh`.


## Catalogo comandi e flag (in dettaglio)

Questa sezione elenca i comandi usati e i flag con spiegazione estesa.
Ogni riga descrive un comando o un flag specifico.

- `tail -f`: segue un file mentre cresce, utile per stream in tempo reale.
- `tail -n +2`: salta la prima riga e stampa dal secondo record in poi.
- `awk -F'|'`: separatore pipe per parsing log realtime.
- `awk -F','`: separatore virgola per parsing CSV.
- `awk '{print $1}'`: stampa la prima colonna.
- `awk '{print $2}'`: stampa la seconda colonna.
- `sort -u`: ordina e rimuove duplicati.
- `wc -l`: conta il numero di righe.
- `grep -q`: non stampa, usa solo l exit status.
- `grep -E`: usa espressioni regolari estese.
- `grep -o`: stampa solo la parte che matcha.
- `cut -d'|' -f1`: estrae campo 1 da pipe.
- `cut -d'|' -f2`: estrae campo 2 da pipe.
- `cut -d',' -f1`: estrae campo 1 da CSV.
- `cut -d',' -f5`: estrae campo 5 da CSV.
- `date -d`: interpreta timestamp testuale.
- `date +%H`: estrae ora in formato 00-23.
- `date +%s`: timestamp Unix per calcoli.
- `sleep 1`: pausa di 1 secondo.
- `sleep 0.3`: pausa breve per pacing test.
- `curl -s`: output silenzioso.
- `curl -G`: usa query string per parametri.
- `curl --data-urlencode`: encoda parametri in URL.
- `curl --max-time`: timeout totale della richiesta.
- `curl -H`: aggiunge header HTTP.
- `curl -X GET`: forza metodo GET.
- `shuf -n 1`: seleziona una riga casuale.
- `head -1`: prima riga di un file.
- `head -20`: prime 20 righe.
- `ps -p`: verifica esistenza di un PID.
- `ss -ltn`: porta in ascolto TCP numerica.
- `command -v`: verifica presenza di un comando.
- `mkdir -p`: crea directory ricorsivamente.
- `rm -f`: rimuove senza chiedere conferma.
- `printf "%s\n"`: stampa con newline.
- `source venv/bin/activate`: attiva virtualenv.
- `python3 -m venv --upgrade-deps`: crea venv con deps aggiornate.
- `pip install -q`: installa in modo silenzioso.
- `timeout 15`: limita durata di un comando a 15 secondi.
- `env TEST_MODE=1`: imposta variabile d ambiente.
- `declare -A`: dichiara array associativo in bash.
- `IFS='|' read`: legge linee con separatore.
- `2>/dev/null`: sopprime stderr.
- `> /dev/null`: sopprime stdout.
- `>> file`: append su file.
- `> file`: sovrascrive file.
- `kill %1`: termina job in background.
- `wait $!`: attende completamento dell ultimo processo.
- `exit 0`: termina con successo.
- `exit 1`: termina con errore.
- `if [ -z "$var" ]`: vero se stringa vuota.
- `if [ -n "$var" ]`: vero se stringa non vuota.
- `if [ $a -ge $b ]`: confronto numerico maggiore o uguale.
- `if [ $a -lt $b ]`: confronto numerico minore.
- `[[ "$ip" =~ regex ]]`: match regex bash.
- `case $x in ... esac`: scelta multipla.
- `for i in $(seq 1 N)`: loop numerico.
- `while read -r line`: loop su linee.
- `local var=...`: variabile locale in funzione.
- `echo $!`: PID ultimo processo.
- `cat file`: stampa file.
- `sed -n '1,5p'`: stampa righe 1-5.
- `wc -l file`: conta righe in file.
- `head -1 file`: prima riga in file.
- `tail -1 file`: ultima riga in file.

## Walkthrough operativi (step by step)

Ogni walkthrough descrive un flusso realistico di esecuzione.
Le righe sono volutamente dettagliate per fornire contesto completo.

### P01 Walkthrough

1. Avvia il server se non e` attivo.
2. Verifica che `logs/realtime_access.log` sia vuoto o pulito.
3. Esegui `./run_problem.sh 1`.
4. Il monitor si mette in ascolto con `tail -f`.
5. Il generatore invia 6 bonifici verso lo stesso IBAN.
6. Ogni evento e` scritto nel log realtime.
7. Lo script salva `customer_id|iban|importo|timestamp` nello stato.
8. `awk` estrae mittenti unici per IBAN.
9. `sort -u` elimina duplicati.
10. `wc -l` conta i mittenti.
11. La soglia 5 viene superata.
12. Si genera alert in blacklist.
13. `recidivita` diventa 1.
14. `risk_score` aumenta di 50.
15. Lo stato rimane `ACTIVE`.
16. Il monitor termina al primo alert.
17. Il test finisce.
18. Si controlla `blacklist.csv`.
19. La riga ha `FLUSSO_AML`.
20. Verifica coerenza con note e origin.
21. Se ripetuto, il risk aumenta a 100.
22. A 100 lo stato diventa `BLOCKED`.
23. La recidivita` aumenta a 2.
24. Il log di notifica non viene usato per P01.
25. Fine.

### P02 Walkthrough

1. Avvia il server.
2. Avvia `./run_problem.sh 2`.
3. Il monitor usa `tail -f`.
4. Il generatore invia login simultanei.
5. Ogni login ha IP diverso.
6. Lo script salva `customer_id|ip`.
7. `awk` estrae IP per customer.
8. `sort -u` e `wc -l` contano IP unici.
9. Soglia 3 superata.
10. Alert in `blacklist.csv`.
11. Script legge CSV clienti.
12. Estrae email e stato 2FA.
13. Se 2FA false, scrive notifica.
14. `risk_score` aumenta di 40.
15. Stato rimane `ACTIVE`.
16. Monitor termina.
17. Verifica `logs/notifiche_email.txt`.
18. Verifica `blacklist.csv`.
19. Ripetizione incrementa recidivita`.
20. A 100, stato `BLOCKED`.
21. Fine.

### P03 Walkthrough

1. Avvia il server.
2. Avvia `./run_problem.sh 3`.
3. `TEST_MODE=1` rende notturno ogni accesso.
4. Il generatore invia login.
5. Lo script calcola l ora dal timestamp.
6. Con `TEST_MODE`, salta check orario reale.
7. Genera alert in blacklist.
8. Scrive notifica in file.
9. `risk_score` aumenta di 30.
10. Stato `ACTIVE`.
11. Monitor termina.
12. Verifica riga in blacklist.
13. Verifica notifica email.
14. Ripetizione accumula rischio.
15. A 100, stato `BLOCKED`.
16. Fine.

### P04 Walkthrough

1. Avvia il server.
2. Esegui `./run_problem.sh 4`.
3. Generatore usa IP 192.168.30.x.
4. Evento scritto nel log.
5. Regex subnet ATM matcha.
6. Alert scritto in blacklist.
7. `risk_score` +35.
8. Stato `ACTIVE`.
9. Monitor termina.
10. Fine.

### P05 Walkthrough

1. Avvia il server.
2. Esegui `./run_problem.sh 5`.
3. Generatore invia 15 login dallo stesso IP.
4. Ogni login viene salvato nel file di stato.
5. `grep` conta i tentativi.
6. Soglia 5 superata.
7. Alert in blacklist.
8. `risk_score` +50.
9. Monitor termina.
10. Fine.

### P06 Walkthrough

1. Avvia il server.
2. Esegui `./run_problem.sh 6`.
3. Generatore invia login da IP pubblico.
4. Funzione `is_public_ip` ritorna 1.
5. Alert scritto in blacklist.
6. `risk_score` +45.
7. Monitor termina.
8. Fine.

### P07 Walkthrough

1. Avvia il server.
2. Esegui `./run_problem.sh 7`.
3. Generatore invia sequenze ripetitive.
4. Ogni richiesta viene contata.
5. `grep` e `wc -l` calcolano il totale.
6. Soglia 10 superata.
7. Alert in blacklist.
8. `risk_score` +35.
9. Monitor termina.
10. Fine.

### P08 Walkthrough

1. Avvia il server.
2. Esegui `./run_problem.sh 8`.
3. Generatore invia BONIFICO con importo 0.
4. Script rileva azione BONIFICO.
5. Script rileva importo 0.
6. Alert scritto in blacklist.
7. `risk_score` +40.
8. Monitor termina.
9. Fine.

### P09 Walkthrough

1. Avvia il server.
2. Esegui `./run_problem.sh 9`.
3. Generatore invia BONIFICO da IP ATM.
4. Regex subnet ATM matcha.
5. Azione BONIFICO confermata.
6. Alert con risk 100 scritto.
7. Stato `BLOCKED` immediato.
8. Monitor termina.
9. Fine.

### P10 Walkthrough

1. Avvia il server.
2. Esegui `./run_problem.sh 10`.
3. Generatore invia 8 operazioni con importo < 100.
4. Script filtra importi piccoli.
5. Conta operazioni per account.
6. Soglia 8 superata.
7. Alert scritto in blacklist.
8. `risk_score` +35.
9. Monitor termina.
10. Fine.
