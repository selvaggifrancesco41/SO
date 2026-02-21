# Comandi di Rete Utilizzati nei 10 Problemi

## Riepilogo Completo

Tutti gli script sono stati riscritti per utilizzare **comandi di rete** invece di query SQL sul database.

---

## Script 01: AML Bonifici (problema_01_aml_bonifici.sh)

### Comandi Usati:
- **tshark** - Packet capture per richieste HTTP POST /bonifico
- **awk** - Parsing dati catturati
- **grep -oP** - Estrazione parametri con regex Perl
- **date +%s** - Timestamp Unix per window temporali

### Tecnica:
Cattura pacchetti HTTP in tempo reale, estrae customer_id, IBAN destinatario e importo dall'URI, traccia mittenti unici verso stesso IBAN.

### Database:
Solo lookup puntuale opzionale (non usato per analisi principale).

---

## Script 02: Accessi Simultanei (problema_02_accessi_simultanei.sh)

### Comandi Usati:
- **ss -tn** - Socket statistics per connessioni TCP attive
- **awk** - Estrazione IP remoti
- **cut -d':'** - Separazione IP da porta
- **sort -u** - Rimozione duplicati

### Tecnica:
Monitora connessioni TCP stabilite al server ogni N secondi, conta IP distinti connessi simultaneamente.

### Database:
Solo lookup customer_id da IP (query puntuale con LIMIT 1).

---

## Script 03: Accessi Notturni (problema_03_accessi_notturni.sh)

### Comandi Usati:
- **ss -tn** - Connessioni attive
- **date +%H** - Ora corrente per verifica orario notturno
- **host** - DNS reverse lookup per hostname
- **grep "domain name pointer"** - Filtra PTR record

### Tecnica:
Verifica orario (22:00-06:00), analizza connessioni attive durante fascia notturna, risolve hostname per identificare provider.

### Database:
Lookup customer_id opzionale.

---

## Script 04: ATM Porte (problema_04_atm_porte.sh)

### Comandi Usati:
- **netstat -tn** - Network statistics (alternativa a ss)
- **nc -z -w** - Netcat per port scanning
- **awk, cut** - Parsing output netstat

### Tecnica:
Monitora porte sorgente delle connessioni, identifica porte fuori range autorizzato (non ephemeral 32768-60999), esegue reverse scan con netcat.

### Database:
Lookup ATM_ID/customer_id opzionale.

---

## Script 05: Brute-Force (problema_05_bruteforce.sh)

### Comandi Usati:
- **tshark** - Cattura richieste HTTP /login
- **awk** - Conta tentativi per IP in finestra temporale
- **iptables** - Blocco IP (opzionale, commentato)
- **date +%s** - Timestamp per calcolo finestra

### Tecnica:
Cattura richieste /login in tempo reale, conta tentativi da stesso IP in 60 secondi, può bloccare automaticamente con iptables.

### Database:
Non usato per analisi (solo lookup opzionale).

---

## Script 06: Correlazione Rete (problema_06_correlazione_rete.sh)

### Comandi Usati:
- **ip a** - Mostra indirizzi IP interfacce locali
- **ip r** - Mostra routing table
- **arp -n** - ARP cache per MAC address
- **ping -c -W** - Verifica raggiungibilità e RTT
- **ss** - Connessioni attive

### Tecnica:
Analizza topologia rete locale, verifica se IP appartengono a subnet autorizzate (192.168.x.x, 10.x.x.x, 172.16-31.x.x), recupera MAC da ARP, misura RTT.

### Database:
Lookup customer_id opzionale.

---

## Script 07: Pattern API (problema_07_pattern_api.sh)

### Comandi Usati:
- **curl -w "%{http_code}"** - Test endpoint API
- **tshark** - Cattura richieste HTTP con user-agent
- **grep -iE** - Identifica user-agent sospetti (curl, wget, python, bot, scanner)
- **awk** - Calcolo rate richieste

### Tecnica:
Cattura header HTTP, analizza user-agent per identificare bot/scanner, conta richieste rapide da stesso IP.

### Database:
Lookup customer_id opzionale.

---

## Script 08: Covert Channels (problema_08_covert_channels.sh)

### Comandi Usati:
- **tcpdump -v -s 0** - Deep packet inspection
- **grep -oP 'length \K\d+'** - Estrazione dimensione pacchetto
- **awk, cut** - Parsing output tcpdump

### Tecnica:
Analizza dimensioni pacchetti TCP (anomali se <100 o >1400 bytes), identifica TCP flags sospetti (NULL scan, FIN scan, XMAS scan).

### Database:
Lookup customer_id opzionale.

---

## Script 09: Incoerenza Rete (problema_09_incoerenza_rete.sh)

### Comandi Usati:
- **traceroute -m -w -q** - Analisi path di rete
- **dig -x +short** - DNS reverse lookup (PTR)
- **grep -c "^ "** - Conta hop in traceroute
- **ss** - Connessioni attive

### Tecnica:
Esegue traceroute verso IP connessi, conta numero hop (sospetto se >15), estrae info PTR per geolocalizzazione approssimativa.

### Database:
Lookup customer_id opzionale.

---

## Script 10: Low & Slow (problema_10_low_slow.sh)

### Comandi Usati:
- **ss -tno** - Socket statistics con timer info
- **awk "BEGIN {print ...}"** - Calcoli floating-point (rate)
- **sed -i** - In-place edit state file
- **date +%s** - Timestamp per calcolo durata connessione

### Tecnica:
Monitora durata connessioni TCP, traccia numero richieste per IP, calcola rate (req/s), identifica connessioni lunghe (>60s) con rate basso (<0.5 req/s).

### Database:
Lookup customer_id opzionale.

---

## Tabella Riassuntiva Comandi

| Comando | Script che lo usa | Scopo |
|---------|-------------------|-------|
| **tshark** | 01, 05, 07 | Packet capture HTTP |
| **ss** | 02, 03, 06, 09, 10 | Connessioni TCP attive |
| **netstat** | 04 | Connessioni TCP (alternativa ss) |
| **tcpdump** | 08 | Deep packet inspection |
| **curl** | 07 | Test endpoint API |
| **nc** (netcat) | 04 | Port scanning |
| **host** | 03 | DNS reverse lookup |
| **dig** | 09 | DNS queries avanzate |
| **ping** | 06 | RTT e raggiungibilità |
| **traceroute** | 09 | Analisi path di rete |
| **ip a** | 06 | Interfacce e IP locali |
| **ip r** | 06 | Routing table |
| **arp** | 06 | ARP cache (MAC address) |
| **iptables** | 05 | Firewall (blocco IP) |
| **awk** | Tutti | Parsing e calcoli |
| **grep** | Tutti | Filtraggio output |
| **date** | Tutti | Timestamp e timing |

---

## Spiegazioni Tecniche Aggiunte

### Operatori Bash Test

```bash
[ -z "$var" ]      # True se stringa vuota (zero-length)
[ -n "$var" ]      # True se stringa NON vuota
[ $a -eq $b ]      # Equal (==) per numeri
[ $a -ne $b ]      # Not equal (!=)
[ $a -gt $b ]      # Greater than (>)
[ $a -ge $b ]      # Greater or equal (>=)
[ $a -lt $b ]      # Less than (<)
[ $a -le $b ]      # Less or equal (<=)
```

### AWK
```bash
awk -F','          # Field separator = virgola
awk -v var="val"   # Passa variabile shell ad awk
$3==tipo           # Confronta colonna 3 con variabile
NR>1               # Number of Record > 1 (skip header)
END{print ...}     # Esegue dopo tutte le righe
```

### Grep
```bash
grep -q            # Quiet mode (solo exit code, no output)
grep -c            # Count occorrenze
grep -i            # Case-insensitive
grep -E            # Extended regex (alternation |)
grep -oP           # Output only match, Perl regex
grep -v            # Invert match (righe che NON matchano)
```

### Redirect e Pipe
```bash
2>/dev/null        # Scarta stderr
2>&1               # Redirige stderr su stdout
>>                 # Append al file
>                  # Sovrascrive file
|                  # Pipe output a comando successivo
```

### Cut
```bash
cut -d':' -f1      # Estrae campo 1 delimitato da :
cut -d':' -f1-4    # Campi da 1 a 4
```

### Date
```bash
date +%s           # Timestamp Unix (secondi da epoch)
date +%H           # Ora corrente (00-23)
date +%Y-%m-%d     # Data formato YYYY-MM-DD
date '+%Y-%m-%d %H:%M:%S'  # Datetime completo
```

---

## Nuova Filosofia

### PRIMA (Database):
- ❌ Query SQL massive (GROUP BY, COUNT, AVG)
- ❌ Analisi post-hoc (eventi già accaduti)
- ❌ Dipendenza totale da database salvato

### ADESSO (Network):
- ✅ Comandi di rete in tempo reale
- ✅ Rilevamento mentre eventi accadono
- ✅ Database = solo lookup puntuali (LIMIT 1)
- ✅ Azione immediata possibile (es. iptables)

---

## Installazione Dipendenze

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y \
    tshark \
    tcpdump \
    iproute2 \
    net-tools \
    iputils-ping \
    traceroute \
    dnsutils \
    netcat \
    iptables

# Permessi packet capture senza sudo (opzionale)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo usermod -aG wireshark $USER
```

---

## Note Finali

- **Tutti gli script** monitorano rete in tempo reale
- **Database** usato SOLO per lookup puntuale customer_id (non analisi)
- **Blacklist** aggiornata immediatamente quando anomalia rilevata
- **Commenti tecnici** dettagliati per ogni comando e operatore
- **State files** in `/workspaces/SO/logs/*.tmp` per tracking in-memory

