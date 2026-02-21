# MODIFICHE: Da Database Analysis a Network Monitoring Real-Time

## Riassunto Modifiche

Gli script di sicurezza sono stati completamente riscritti per utilizzare **comandi di rete** invece di query SQL sul database.

## Filosofia Cambiata

### PRIMA (Database-based):
- Interrogazione periodica del database con query SQL
- Analisi post-hoc degli eventi già salvati
- Database = fonte primaria di analisi
- Esecuzione batch schedulata (es. cron)

### ADESSO (Network-based):
- Cattura traffico di rete in tempo reale
- Analisi mentre le richieste avvengono
- Database = solo lookup puntuali per dati utente
- Esecuzione continua con rilevamento immediato

---

## Script Modificati

### 1. problema_01_aml_bonifici.sh - AML Detection

**PRIMA:**
```bash
# Query SQL sul database
QUERY="SELECT customer_id, COUNT(DISTINCT iban_destinatario) 
       FROM eventi 
       WHERE azione='BONIFICO' 
       GROUP BY customer_id..."
ANOMALI=$(sqlite3 "$DB_PATH" "$QUERY")
```

**ADESSO:**
```bash
# Cattura pacchetti HTTP POST /bonifico in tempo reale
tshark -i any -f "tcp port 8000" \
    -Y 'http.request.method == "POST" and http.request.uri contains "bonifico"' \
    -T fields -e ip.src -e http.request.uri | \
while read ip uri; do
    # Analizza pattern di bonifici mentre arrivano
    mittenti_unici=$(awk -F'|' '$3==iban {print $2}' "$STATE_FILE" | sort -u | wc -l)
    if [ $mittenti_unici -ge $SOGLIA ]; then
        # ALERT immediato
    fi
done
```

**COMANDI USATI:**
- `tshark`: Cattura pacchetti di rete (Wireshark CLI)
- `-i any`: Interfaccia qualsiasi
- `-f "tcp port 8000"`: BPF filter per porta server
- `-Y`: Display filter per HTTP POST
- `-T fields`: Output formattato a campi
- `grep -oP`: Estrazione regex Perl
- `awk -F'|'`: Parsing file con pipe separator

**DATABASE:** Solo se serve verificare che customer_id esista (lookup puntuale)

---

### 2. problema_02_accessi_simultanei.sh - Simultaneous Access

**PRIMA:**
```bash
# Query SQL per trovare overlap temporali
QUERY="SELECT customer_id, COUNT(DISTINCT ip_address)
       FROM eventi
       WHERE timestamp BETWEEN ... 
       GROUP BY customer_id"
```

**ADESSO:**
```bash
# Analizza connessioni TCP attive con ss (socket statistics)
ss -tn state established sport = :8000 | \
    awk 'NR>1 {print $5}' | \
    cut -d':' -f1 | \
    sort -u

# Conta IP distinti connessi simultaneamente
if [ $NUM_IPS -ge $SOGLIA ]; then
    # ALERT: troppi IP connessi contemporaneamente
fi
```

**COMANDI USATI:**
- `ss`: Socket statistics (moderno sostituto di netstat)
- `-t`: Solo TCP sockets
- `-n`: Numeric output (no DNS lookup)
- `state established`: Solo connessioni stabilite
- `sport = :8000`: Filtra per source port 8000
- `cut -d':' -f1`: Estrae solo IP da formato IP:porta
- `sort -u`: Ordina e rimuove duplicati

**DATABASE:** Solo lookup per associare IP → customer_id (opzionale)

---

### 3. problema_05_bruteforce.sh - Brute-Force Detection

**PRIMA:**
```bash
# Conta tentativi LOGIN da database
QUERY="SELECT ip_address, COUNT(*) FROM eventi
       WHERE azione='LOGIN' AND timestamp >= ...
       GROUP BY ip_address
       HAVING COUNT(*) >= $SOGLIA"
```

**ADESSO:**
```bash
# Cattura richieste /login in tempo reale
tshark -i any -f "tcp port 8000" \
    -Y 'http.request.uri contains "login"' \
    -T fields -e frame.time_epoch -e ip.src | \
while read timestamp ip; do
    # Conta tentativi da questo IP in finestra temporale
    TENTATIVI=$(awk -F'|' -v window="$START" -v ip="$ip" \
        '$1>=window && $2==ip {count++} END{print count}' "$STATE_FILE")
    
    if [ $TENTATIVI -ge $SOGLIA ]; then
        # ALERT + blocco IP con iptables
        sudo iptables -A INPUT -s "$ip" -j DROP
    fi
done
```

**COMANDI USATI:**
- `tshark`: Packet capture
- `-e frame.time_epoch`: Timestamp Unix del pacchetto
- `date +%s`: Timestamp Unix corrente
- `awk` arithmetic: `$1>=window` confronto numerico
- `iptables -A INPUT -s IP -j DROP`: Blocca IP

**AZIONE AGGIUNTIVA:** Può bloccare IP automaticamente con iptables

---

## Commenti Tecnici Aggiunti

### Operatori Test Bash
```bash
[ -z "$var" ]     # Test if string is zero-length (empty)
[ -n "$var" ]     # Test if string is NOT empty
[ $a -eq $b ]     # Equal (==)
[ $a -ne $b ]     # Not equal (!=)
[ $a -gt $b ]     # Greater than (>)
[ $a -ge $b ]     # Greater or equal (>=)
[ $a -lt $b ]     # Less than (<)
[ $a -le $b ]     # Less or equal (<=)
```

### Comandi Network
```bash
ss -tn                 # List TCP sockets, numeric format
netstat -tn            # Alternativa a ss (deprecato)
tshark -i any          # Capture on all interfaces
tcpdump -i eth0        # Alternativa a tshark
iptables -A INPUT      # Append rule to INPUT chain
```

### Operatori AWK
```bash
awk -F','           # Field separator = comma
awk -v var="val"    # Pass shell variable to awk
$3==tipo            # Compare column 3 with variable
NR>1                # Number of Record > 1 (skip header)
END{print count}    # Execute after processing all lines
```

### Redirect e Pipe
```bash
2>/dev/null         # Redirect stderr to null (discard errors)
2>&1                # Redirect stderr to stdout
>>                  # Append to file
>                   # Overwrite file
| while read        # Pipe output to loop
```

---

## Vantaggi Nuovo Approccio

1. **Real-time detection**: Rileva anomalie mentre avvengono
2. **Network-level monitoring**: Vede traffico anche se non salvato in DB
3. **Immediate action**: Può bloccare IP con iptables automaticamente
4. **No database overhead**: Non interroga massivamente il DB
5. **State files**: Usa file temporanei per tracking in memoria

## Svantaggi

1. **Richiede tshark/tcpdump**: Dipendenze aggiuntive
2. **Può richiedere sudo**: Per packet capture e iptables
3. **CPU/Memory usage**: Cattura pacchetti usa più risorse
4. **Non persistente**: Dati in file temporanei (non DB permanente)

---

## Installazione Dipendenze

```bash
# Debian/Ubuntu
sudo apt-get install tshark iproute2 iptables

# Permessi per cattura pacchetti senza sudo
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```

---

## File di Stato Usati

Gli script ora usano file temporanei per tracciare eventi in memoria:

- `/workspaces/SO/logs/aml_state.tmp` - Bonifici intercettati
- `/workspaces/SO/logs/simultanei_state.tmp` - Connessioni TCP attive
- `/workspaces/SO/logs/bruteforce_state.tmp` - Tentativi login

Format: `timestamp_unix|campo1|campo2|...`

---

## Uso Database Residuo

Il database viene usato SOLO per:

1. **Lookup puntuali** di dati cliente specifico
   ```bash
   sqlite3 "$DB" "SELECT customer_id FROM eventi 
                  WHERE ip_address='$ip' LIMIT 1"
   ```

2. **Verifica esistenza** elemento
   ```bash
   sqlite3 "$DB" "SELECT 1 FROM eventi 
                  WHERE customer_id='$id' LIMIT 1"
   ```

**NON** viene più usato per:
- Aggregazioni complesse (COUNT, GROUP BY, SUM)
- Analisi temporali (datetime range queries)
- Pattern matching su grandi dataset

---

## Prossimi Script da Modificare

Gli script rimanenti (problema_03, 04, 06-10) seguono ancora il vecchio approccio database. 
Possono essere modificati con pattern simili:

- **problema_03** (accessi notturni): `ss -tn` + check orario
- **problema_04** (ATM porte): `netstat -tnp` + filter porta ATM
- **problema_06** (correlazione): `tcpdump` multi-host
- **problema_07** (pattern API): `tshark` HTTP methods
- **problema_08** (covert channels): Deep packet inspection
- **problema_09** (incoerenza): `ss` + geolocation check
- **problema_10** (low&slow): Rate limiting in tempo reale

