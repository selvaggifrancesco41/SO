#!/bin/bash

# TEST GENERATOR 04: Anomalia ATM su porte non autorizzate
#
# SCOPO: Simulare connessioni ATM verso porte fuori dal range autorizzato
#        Range autorizzato: 32768-60999 (porte efimere)
#        Questo pattern viene rilevato da problema_04_atm_porte.sh
#
# METODO: Usa /dev/tcp di bash per creare connessioni verso porte non autorizzate
# PREREQUISITO: server Flask in esecuzione

# Output minimale: poche righe, facile da leggere
log() {
    # Stampa una riga sintetica
    printf "%s\n" "$1"
}

# Output minimale di avvio
log "T04 start"

# Parametri server e sorgente dati
SERVER="localhost"
SERVER_PORT=8000
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

# Seleziona 1 ACCOUNT CASUALE dal CSV per ATM
CUSTOMER_ID=$(tail -n +2 "$CSV_CLIENTI" | shuf -n 1 | cut -d',' -f1)

# Genera IP ATM casuale nel range monitorato (192.168.30.1-254)
ATM_IP="192.168.30.$((RANDOM % 254 + 1))"

# Generiamo richiesta HTTP da IP ATM simulato
# Il server la registrerà e il monitoring rileverà la porta sorgente anomala

# Simula un login da ATM (il monitoring controllerà la porta sorgente)
curl -s -G "http://$SERVER:$SERVER_PORT/login" \
    --data-urlencode "customer_id=$CUSTOMER_ID" \
    --data-urlencode "session_duration=10" \
    -H "X-Forwarded-For: $ATM_IP" > /dev/null

# Attende la registrazione della richiesta
sleep 1

# Output minimale di fine
log "T04 done"

