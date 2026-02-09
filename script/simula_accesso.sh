#!/bin/bash

# directory reale dello script
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

SERVER_URL="http://localhost:8000"
CSV="$BASE_DIR/../clienti_banca.csv"


# estrae una riga casuale (salta header)
RIGA=$(tail -n +2 "$CSV" | shuf -n 1)

# campi CSV
CUSTOMER_ID=$(echo "$RIGA" | cut -d',' -f1)
IBAN=$(echo "$RIGA" | cut -d',' -f17)

# azione casuale
AZIONE=$(shuf -n1 -e login bonifico prelievo deposito)

# parametri random
IMPORTO=$(shuf -i 10-2000 -n 1)
SESSION_DURATION=$(shuf -i 30-900 -n 1)

case "$AZIONE" in
  login)
    curl -s "$SERVER_URL/login?customer_id=$CUSTOMER_ID&session_duration=$SESSION_DURATION" >/dev/null
    ;;
  bonifico)
    curl -s "$SERVER_URL/bonifico?customer_id=$CUSTOMER_ID&importo=$IMPORTO&iban=$IBAN" >/dev/null
    ;;
  prelievo)
    curl -s "$SERVER_URL/prelievo?customer_id=$CUSTOMER_ID&importo=$IMPORTO" >/dev/null
    ;;
  deposito)
    curl -s "$SERVER_URL/deposito?customer_id=$CUSTOMER_ID&importo=$IMPORTO" >/dev/null
    ;;
esac
