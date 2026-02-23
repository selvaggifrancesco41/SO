# PROGETTO_SERVER_BANCA

## Introduzione

Questo progetto simula un server bancario GNU/Linux con monitoraggio di 10 anomalie di sicurezza. Il monitoraggio usa **solo** il flusso eventi in tempo reale scritto dal server in `logs/realtime_access.log` e non legge log storici o database per input.

Ogni script:
- legge il flusso con `tail -f`
- applica una finestra temporale di 60 secondi
- scrive un alert in `blacklist.csv`
- termina al primo rilevamento per mantenere i test rapidi

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

## Logica blacklist

Gli alert vengono sempre scritti in `blacklist.csv` con campi:

```
timestamp,tipo_elemento,elemento,azione_rilevata,gravita,recidivita,risk_score,stato,origine_rilevazione,note
```

- `recidivita` e `risk_score` sono cumulativi per `tipo_elemento + elemento`.
- Quando il `risk_score` raggiunge 100, lo `stato` diventa `BLOCKED`.

La logica di aggiornamento e` centralizzata in `script/lib_blacklist.sh`.

## I 10 problemi (regole correnti)

1. **P01 AML bonifici**: 5+ mittenti unici verso lo stesso IBAN in 60s.
2. **P02 accessi simultanei**: 3+ IP diversi per lo stesso account; notifica se 2FA non attivo.
3. **P03 accessi notturni**: login tra 22:00 e 06:00 (o `TEST_MODE=1`); notifica.
4. **P04 subnet ATM**: IP in 192.168.30.x.
5. **P05 bruteforce**: 5+ LOGIN dallo stesso IP.
6. **P06 IP pubblico**: IP non RFC1918.
7. **P07 pattern API**: 10+ richieste dallo stesso IP.
8. **P08 covert channels**: BONIFICO con importo=0.
9. **P09 incoerenza rete**: IP ATM (192.168.30.x) che esegue BONIFICO (risk 100).
10. **P10 low & slow**: 8+ operazioni con importo < 100 per lo stesso account.

## Test

I generatori sono in `script/test_generators/` e vengono richiamati da `run_problem.sh`.

Note importanti:
- P03 usa `TEST_MODE=1` nei test per bypassare l orario reale.
- P05 e P03 partono in `TEST_MODE` quando eseguiti via `run_problem.sh`.

## Note

- Output terminale minimale (stdout silenziato, log su FD3).
- Notifiche client in `logs/notifiche_email.txt` (P02, P03).
- Nessun input da database o log storici: solo stream in tempo reale.

