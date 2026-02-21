#!/bin/bash

# TEST GENERATOR 04: Anomalia ATM su porte non autorizzate
#
# SCOPO: Simulare connessioni ATM verso porte fuori dal range autorizzato
#        Range autorizzato: 32768-60999 (porte efimere)
#        Questo pattern viene rilevato da problema_04_atm_porte.sh
#
# METODO: Usa nc (netcat) per creare connessioni verso porte non autorizzate
# PREREQUISITO: netcat installato e server Flask in esecuzione

echo "================================================================================"
echo "[TEST 04] Generazione anomalia - ATM su porte non autorizzate"
echo "================================================================================"

# Verifica netcat disponibile
if ! command -v nc &> /dev/null; then
    echo "[!] ERRORE: netcat non installato"
    echo "[*] Installa con: sudo apt-get install netcat-openbsd"
    exit 1
fi

ATM_IPS=("192.168.30.1" "192.168.30.2" "192.168.30.3")
UNAUTHORIZED_PORTS=(22 25 53 110 143)  # SSH, SMTP, DNS, POP3, IMAP - fuori policy
AUTHORIZED_PORT_MIN=32768
AUTHORIZED_PORT_MAX=60999

echo "[*] ATM da testare: ${ATM_IPS[@]}"
echo "[*] Porte non autorizzate da usare: ${UNAUTHORIZED_PORTS[@]}"
echo "[*] Policy autorizzata: $AUTHORIZED_PORT_MIN-$AUTHORIZED_PORT_MAX"
echo ""

echo "[TEST] Generazione connessioni ATM su porte non autorizzate..."

# Per ogni ATM, tenta connessioni su porte non autorizzate
for i in {0..2}; do
    ATM_ID="${ATM_IPS[$i]}"
    UNAUTHORIZED_PORT="${UNAUTHORIZED_PORTS[$((i % 5))]}"
    
    echo "[+] ATM $ATM_ID → porta non autorizzata $UNAUTHORIZED_PORT"
    
    # nc -zv: test connessione (-z: scan, -v: verbose)
    # timeout: evita blocchi se la porta non risponde
    timeout 2 nc -zv localhost $UNAUTHORIZED_PORT 2>&1 &
    
    sleep 0.5
done

echo ""
echo "[✓] Connessioni ATM su porte non autorizzate generate"
echo "[*] Controlla il log: tail -f logs/atm_porte_alerts.log"
echo "[*] Verifica con: netstat -tn | grep ESTABLISHED"
wait
