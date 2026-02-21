# README - Test Generators per Problemi di Sicurezza

Questo documento spiega come usare gli **script test generators** per simulare anomalie di rete che vengono rilevate dai 10 problemi di sicurezza.

## 📂 Struttura

```
/script/
├── problema_01_aml_bonifici.sh           (monitoraggio)
├── problema_02_accessi_simultanei.sh     (monitoraggio)
├── ... (altri 8 problemi)
└── test_generators/
    ├── test_01_aml_bonifici.sh           (genera anomalie AML)
    ├── test_02_accessi_simultanei.sh     (genera accessi doppi)
    ├── ... (altri 8 test)
```

---

## 🚀 Come funziona

**Terminal 1** → Avvia il monitoraggio (uno dei 10 script problema):
```bash
cd /workspaces/SO/script
./problema_05_bruteforce.sh
```

**Terminal 2** → Avvia il test generator corrispondente:
```bash
cd /workspaces/SO/script/test_generators
./test_05_bruteforce.sh
```

Il **test genera il traffico anomalo** → Il **monitoraggio lo cattura** e lo registra in blacklist ✅

---

## 📋 Test Generators Disponibili

### Test 01: AML - Bonifici anomali
**File:** `test_01_aml_bonifici.sh`

**Cosa fa:** Genera 6 bonifici verso lo **stesso IBAN beneficiario** da indirizzi IP diversi.

**Pattern rilevato:**
- Mittenti unici: 6 (soglia: 3+)
- IBAN beneficiario: IT6012345678901234567890
- Tutti in tempo breve → **AML ALERT**

**Come eseguire:**
```bash
# Terminal 1
./problema_01_aml_bonifici.sh

# Terminal 2 (in parallel)
./test_generators/test_01_aml_bonifici.sh
```

**Output atteso:**
```
[!!!] ANOMALIA AML RILEVATA!
[!!!] IBAN IT6012345678901234567890 ha ricevuto bonifici da 6 mittenti diversi
```

---

### Test 02: Accessi simultanei
**File:** `test_02_accessi_simultanei.sh`

**Cosa fa:** Genera **4 login simultanei** dello stesso account (`mario.rossi`) da IP diversi.

**Pattern rilevato:**
- Account: mario.rossi
- Sessioni contemporanee: 4+ da IP diversi
- In < 5 secondi → **ACCESSO SIMULTANEO ALERT**

**Come eseguire:**
```bash
# Terminal 1
./problema_02_accessi_simultanei.sh

# Terminal 2
./test_generators/test_02_accessi_simultanei.sh
```

**Output atteso:**
```
[!!!] ACCESSO SIMULTANEO RILEVATO!
[!!!] Account mario.rossi ha 4 sessioni attive da IP diversi
```

---

### Test 03: Accessi notturni
**File:** `test_03_accessi_notturni.sh`

**Cosa fa:** Genera 3 login durante la **fascia notturna (22:00-06:00)**.

**Pattern rilevato:**
- Ora: 22:00-06:00
- Login da IP notturno
- Fuori profilo utente → **ACCESSO NOTTURNO ALERT**

**Come eseguire:**
```bash
# Terminal 1 (monitoraggio)
./problema_03_accessi_notturni.sh

# Terminal 2 (test - avverte se non è ora notturna)
./test_generators/test_03_accessi_notturni.sh
```

**Nota:** Se non sei in fascia notturna, il test chiede se cambiare l'ora di sistema.

---

### Test 04: ATM su porte non autorizzate
**File:** `test_04_atm_porte.sh`

**Cosa fa:** Genera connessioni ATM verso **porte fuori policy**.
- Policy: 32768-60999 (porte efimere)
- Test usa porte: 22, 25, 53, 110, 143 (vietate)

**Pattern rilevato:**
- ATM da range 192.168.30.x
- Connessioni a porte non autorizzate
- Ogni ATM anomalo → **ATM ANOMALO ALERT**

**Come eseguire:**
```bash
# Terminal 1
./problema_04_atm_porte.sh

# Terminal 2
./test_generators/test_04_atm_porte.sh
```

**Output atteso:**
```
[!!!] ATM SU PORTA NON AUTORIZZATA!
[!!!] ATM 192.168.30.1 usa porta 22 (vietata!)
```

---

### Test 05: Brute-force login
**File:** `test_05_bruteforce.sh`

**Cosa fa:** Genera **15 tentativi falliti** verso `/login` da uno stesso IP.
- Username: admin
- Passwords: attempt_1, attempt_2, ... (tutte sbagliate)
- Intervallo: 2 secondi tra tentativi
- Soglia: 10+ tentativi in 60 secondi → **BRUTE-FORCE ALERT**

**Pattern rilevato:**
- IP: 192.168.40.100
- Endpoint: /login
- Numero tentativi: 15 in 30 secondi
- Blocco automatico con iptables

**Come eseguire:**
```bash
# Terminal 1
./problema_05_bruteforce.sh

# Terminal 2
./test_generators/test_05_bruteforce.sh
```

**Output atteso:**
```
[!!!] BRUTE-FORCE RILEVATO!
[!!!] IP 192.168.40.100 ha fatto 15 tentativi in 30 secondi
[✓] IP bloccato con iptables
```

---

### Test 06: Correlazione rete - Degradazione
**File:** `test_06_correlazione_rete.sh`

**Cosa fa:** Genera uno **spike di 20 connessioni simultanee** verso il server.

**Pattern rilevato:**
- Socket TCP attive verso 127.0.0.1:8000
- Numero: 20 contemporanee
- Durata: 30 secondi
- Correlazione con degradazione percepita → **DEGRADAZIONE ALERT**

**Come eseguire:**
```bash
# Terminal 1
./problema_06_correlazione_rete.sh

# Terminal 2
./test_generators/test_06_correlazione_rete.sh
```

**Verifica manuale:**
```bash
ss -tan | grep 8000 | wc -l  # Dovrebbe mostrare ~20
```

---

### Test 07: Pattern API anomali (bot)
**File:** `test_07_pattern_api.sh`

**Cosa fa:** Genera una **sequenza RIGIDA di endpoint**:
1. /saldo
2. /bonifico_info  
3. /saldo
4. (ripete)

**Pattern rilevato:**
- Sequenza meccanica e identica
- Assenza di variabilità
- Tipico di bot/automazione
- Numero cicli: 5 → **PATTERN ANOMALO ALERT**

**Come eseguire:**
```bash
# Terminal 1
./problema_07_pattern_api.sh

# Terminal 2
./test_generators/test_07_pattern_api.sh
```

**Output atteso:**
```
[!!!] PATTERN API ANOMALO RILEVATO!
[!!!] Sequenza meccanica da IP 192.168.60.100
[!!!] Tipico di automazione non autorizzata
```

---

### Test 08: Canali covert
**File:** `test_08_covert_channels.sh`

**Cosa fa:** Apre **4 connessioni persistenti senza dati** per 60 secondi.

**Pattern rilevato:**
- Socket attive verso 127.0.0.1:8000
- Rimangono nello stato ESTABLISHED
- Senza trasmissione dati per 60 secondi
- Tipico di esfiltrazione lenta → **COVERT CHANNEL ALERT**

**Come eseguire:**
```bash
# Terminal 1
./problema_08_covert_channels.sh

# Terminal 2
./test_generators/test_08_covert_channels.sh
```

**Verifica manuale durante la connessione:**
```bash
ss -tan | grep 8000    # Vedi connessioni ESTABLISHED senza movimento
tcpdump -i lo -n tcp port 8000  # Vedi assenza di dati
```

---

### Test 09: Incoerenza di rete
**File:** `test_09_incoerenza_rete.sh`

**Cosa fa:** Genera operazioni da **contesti di rete errati**:
1. Bonifico da IP ATM (dovrebbe essere da client)
2. Prelievo da IP API (dovrebbe essere da ATM)
3. Admin login da IP pubblico (dovrebbe essere interno)

**Pattern rilevato:**
- Operazione: Bonifico
- IP sorgente: 192.168.30.1 (range ATM)
- Mismatch! → **INCOERENZA RETE ALERT**

**Come eseguire:**
```bash
# Terminal 1
./problema_09_incoerenza_rete.sh

# Terminal 2
./test_generators/test_09_incoerenza_rete.sh
```

**Output atteso:**
```
[!!!] INCOERENZA RETE RILEVATA!
[!!!] Bonifico da 192.168.30.1 (IP ATM - incoerente!)
[!!!] Risk score elevato
```

---

### Test 10: Low & Slow Attack
**File:** `test_10_low_slow.sh`

**Cosa fa:** Genera **5 richieste spaziate su 120 secondi** (rate molto basso).

**Pattern rilevato:**
- Numero richieste: 5
- Durata: 120 secondi
- Rate: 0.042 req/s (< 0.5 soglia)
- Persistente nel tempo → **LOW & SLOW ALERT**

**Come eseguire:**
```bash
# Terminal 1 (monitoraggio, durata ~2 minuti)
./problema_10_low_slow.sh

# Terminal 2
./test_generators/test_10_low_slow.sh
```

**Output atteso:**
```
[!!!] PATTERN LOW & SLOW RILEVATO!
[!!!] Rate troppo basso: 0.042 req/s
[!!!] Attacco lento ma persistente
```

---

## 🔧 Utilizzo avanzato

### Eseguire un singolo test in modalità interattiva

```bash
cd /workspaces/SO/script/test_generators
./test_05_bruteforce.sh
```

### Eseguire tutti i test in sequenza

```bash
cd /workspaces/SO/script/test_generators
for test in test_*.sh; do
    echo "Esecuzione: $test"
    ./$test
    sleep 5
done
```

### Monitorare più problemi in parallelo

**Apri 3 terminal:**

```bash
# Terminal 1: Monitoraggio AML
./problema_01_aml_bonifici.sh

# Terminal 2: Monitoraggio brute-force
./problema_05_bruteforce.sh

# Terminal 3: Generazione test
./test_generators/test_01_aml_bonifici.sh
./test_generators/test_05_bruteforce.sh
```

---

## 📊 Verifica dei risultati

### Log di ogni problema
```bash
tail -f /workspaces/SO/logs/aml_alerts.log
tail -f /workspaces/SO/logs/bruteforce_alerts.log
tail -f /workspaces/SO/logs/accessi_simultanei.log
# ... etc
```

### Blacklist centralizzata
```bash
cat /workspaces/SO/blacklist.csv
# Mostra tutti gli elementi sospetti rilevati
```

### Connessioni attive
```bash
ss -tan | grep 8000    # Connessioni verso server
netstat -an | grep 8000
```

### Pacchetti catturati
```bash
# Se tshark è disponibile
sudo tshark -i any -f "tcp port 8000"
```

---

## ⚠️ Note importanti

1. **Server deve essere in esecuzione:**
   ```bash
   cd /workspaces/SO/script
   python3 ../server/server.py
   ```

2. **Alcuni test richiedono curl, netcat, tshark:**
   ```bash
   sudo apt-get install curl netcat-openbsd tshark
   ```

3. **Blocco IP con iptables richiede sudo:**
   - Test 05 chiederà password per `sudo iptables`
   - Per evitare: `sudo visudo` e aggiungi `iptables` senza password

4. **Orario di sistema:**
   - Test 03 controlla se siamo in fascia notturna
   - Se no, chiede di cambiare l'ora (necessita sudo)

5. **Durata test:**
   - Variano da 30 secondi (brute-force) a 2 minuti (low & slow)
   - Lascia il test in esecuzione fino al completamento

---

## 🎯 Workflow consigliato

```bash
# 1. Apri terminal 1: avvia monitoraggio
cd /workspaces/SO/script
./problema_05_bruteforce.sh

# 2. Apri terminal 2: attendi che monitoraggio sia pronto
# Vedi messaggi come "[*] In ascolto su porta 8000..."

# 3. Terminal 2: avvia test generatore
cd /workspaces/SO/script/test_generators
./test_05_bruteforce.sh

# 4. Osserva i risultati in tempo reale in terminal 1
# Vedrai gli alert man mano che vengono generati

# 5. Verifica blacklist
cat /workspaces/SO/blacklist.csv
```

---

## 📝 Documentazione correlata

- [README.md](../README.md) - Descrizione dei 10 problemi
- [COMANDI_RETE_UTILIZZATI.md](../COMANDI_RETE_UTILIZZATI.md) - Comandi di monitoraggio
- [MODIFICHE_NETWORK_MONITORING.md](../MODIFICHE_NETWORK_MONITORING.md) - Cambio da database a network

---

**Creato:** 2026-02-21  
**Versione:** 1.0  
**Autore:** Sistema di sicurezza bancaria
