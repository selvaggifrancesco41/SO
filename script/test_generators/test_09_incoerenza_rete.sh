#!/bin/bash

# TEST GENERATOR 09: Anomalia incoerenza rete - operazione da contesto errato
#
# SCOPO: Simulare operazioni da indirizzi IP sospetti
#        es. bonifico da range ATM invece da range client
#        Viene rilevato da problema_09_incoerenza_rete.sh
#
# METODO: Operazioni da IP che non dovrebbero farle

SERVER="http://localhost:8000"

echo "================================================================================"
echo "[TEST 09] Generazione anomalia - operazione da contesto di rete incoerente"
echo "================================================================================"
echo "[*] Simula BONIFICO da IP di ATM (dovrebbe essere da client normale)"
echo "[*] Simula PRELIEVO da IP di API (dovrebbe essere da ATM)"
echo ""

echo "[TEST] Operazioni da contesti incoerenti..."

# Operazione 1: Bonifico da IP ATM (anomalo)
echo "[+] Bonifico da 192.168.30.1 (range ATM - INCOERENTE!)"
curl -s -X POST "$SERVER/bonifico" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 192.168.30.1" \
    -d '{
        "iban_mittente": "IT1234...",
        "iban_beneficiario": "IT5678...",
        "importo": 50000
    }' 2>/dev/null &

sleep 1

# Operazione 2: Prelievo da IP API (anomalo)
echo "[+] Prelievo da 192.168.40.50 (range API - INCOERENTE!)"
curl -s -X POST "$SERVER/prelievo" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 192.168.40.50" \
    -d '{
        "importo": 500,
        "nominativo": "test"
    }' 2>/dev/null &

sleep 1

# Operazione 3: Login amministratore da IP pubblico (anomalo)
echo "[+] Admin login da 203.0.113.25 (IP pubblico esterno - INCOERENTE!)"
curl -s -X POST "$SERVER/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 203.0.113.25" \
    -d '{
        "username": "admin",
        "password": "admin_pass"
    }' 2>/dev/null &

echo ""
echo "[✓] Operazioni incoerenti generate"
echo "[*] Sono FORMALMENTE CORRETTE ma contestualmente SOSPETTE"
echo "[*] Log: tail -f logs/incoerenza_rete.log"
wait
