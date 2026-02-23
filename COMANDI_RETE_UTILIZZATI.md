# Comandi e Flag Utilizzati negli Script

Questo documento descrive i comandi reali usati negli script `.sh` **attuali**. Il monitoraggio si basa sul flusso `logs/realtime_access.log` e non usa comandi di rete come input.

## Comandi usati nei monitor

- `tail -f`: segue il file in tempo reale (stream eventi).
- `awk -F`: imposta il separatore di campo (CSV o pipe `|`).
- `sort -u`: ordina e rimuove duplicati.
- `wc -l`: conta il numero di righe.
- `grep -q`: ricerca senza output, solo exit status.
- `cut -d -f`: seleziona campi con separatore specifico.
- `date -d`: parse di timestamp in formato testo.
- `date -u`: data in UTC (usata nei reset dei test).

## Comandi usati nei test generator

- `curl -s`: output silenzioso.
- `curl -G`: passa parametri in query string.
- `curl --data-urlencode`: URL-encode dei parametri.
- `curl --max-time`: timeout totale della richiesta.
- `tail -n +2`: salta l'header del CSV.
- `shuf -n 1`: seleziona una riga casuale.
- `cut -d',' -f1`: seleziona il primo campo del CSV.

## Comandi di supporto

- `ss -ltn`: verifica se la porta 8000 e` in ascolto (solo per avvio server).
- `ps -p`: verifica l'esistenza del PID.
- `command -v`: controlla la presenza di un comando nel PATH.

## Note

- Gli script non leggono database o log storici per input.
- Gli alert vengono sempre scritti in `blacklist.csv` con risk cumulativo e stato `BLOCKED` a 100.
