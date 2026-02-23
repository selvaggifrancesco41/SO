# Comandi di Rete Utilizzati nei 10 Problemi

Questo documento sintetizza i comandi di rete usati dagli script in [script/](script/). Le query SQLite restano solo per lookup puntuali o per leggere i log, ma il focus e' sul contesto di rete.

## Elenco per problema

### 01 - AML Bonifici

- `tshark` (se disponibile) per analisi HTTP in tempo reale.
- `awk`, `grep`, `sort` per parsing del traffico e conteggio mittenti.

### 02 - Accessi simultanei

- `ss` per socket TCP attive.
- `awk`, `cut`, `sort` per estrazione e conteggio IP.

### 03 - Accessi notturni

- `ss` per connessioni attive.
- `date +%H` per fascia oraria.
- `host` per reverse DNS.

### 04 - ATM porte anomale

- `netstat` (o `ss`) per porte e connessioni.
- `nc` (netcat) per verifiche rapide su porte sospette.

### 05 - Brute-force login

- `tshark` per intercettare richieste di login (quando usato in tempo reale).
- `iptables` per blocchi automatici su IP con `risk_score` elevato.

### 06 - Correlazione rete

- `ip a` e `ip r` per interfacce e routing.
- `arp -n` per mappare IP/MAC.
- `ping` per RTT e raggiungibilita'.
- `ss` per socket attive.

### 07 - Pattern API

- `curl` per test endpoint e tempi di risposta.
- `tshark` per user-agent e richieste HTTP.
- `grep -iE` per identificare user-agent sospetti.

### 08 - Covert channels

- `tcpdump` per ispezione pacchetti (payload/size) quando attivo.
- `awk`, `grep` per pattern su dimensioni pacchetto.

### 09 - Incoerenza rete

- `traceroute` per path di rete.
- `dig -x` per reverse DNS.
- `ss` per connessioni attive.

### 10 - Low & Slow

- `ss -tno` per durata e timer connessioni.
- `awk` per calcolo rate.

## Note operative

- I blocchi automatici usano `iptables` quando disponibile.
- La maggior parte dei comandi e' eseguita in tempo reale, senza aggregazioni SQL pesanti.
