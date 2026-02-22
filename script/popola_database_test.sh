#!/bin/bash

################################################################################
# SCRIPT DI POPOLAMENTO DATABASE CON DATI REALISTICI E ANOMALI
################################################################################
#
# DESCRIZIONE:
# Questo script popola il database bank_logs.db con dati simulati che
# includono sia comportamenti normali che anomali, per testare i 10 problemi.
#
# GENERAZIONE:
# - Utenti normali con pattern regolari
# - Utenti con accessi notturni
# - Utenti con accessi simultanei da IP diversi
# - ATM normali e ATM compromessi
# - Pattern di brute-force
# - Pattern Low & Slow
# - Flussi AML sospetti
#
################################################################################

DB_PATH="/workspaces/SO/data/bank_logs.db"
CSV_CLIENTI="/workspaces/SO/clienti_banca.csv"

echo "================================================================================"
echo "POPOLAMENTO DATABASE CON DATI REALISTICI E ANOMALI"
echo "================================================================================"
echo ""

# Inizializza il database se non esiste
python3 << 'EOF'
import sqlite3
import os

DB_PATH = "/workspaces/SO/data/bank_logs.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Crea tabella eventi se non esiste
cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        customer_id INTEGER,
        ip_address TEXT,
        azione TEXT,
        importo REAL,
        iban_destinatario TEXT,
        session_duration INTEGER
    )
""")

conn.commit()
conn.close()
print("[✓] Database inizializzato")
EOF

echo ""
echo "[*] Generazione dati realistici..."
echo ""

# Genera dati con Python
python3 << 'EOF'
import sqlite3
import random
import csv
from datetime import datetime, timedelta

DB_PATH = "/workspaces/SO/data/bank_logs.db"
CSV_PATH = "/workspaces/SO/clienti_banca.csv"

# Leggi i clienti dal CSV
clienti = []
with open(CSV_PATH, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        clienti.append({
            'customer_id': row['customer_id'],
            'iban': row['iban']
        })

print(f"[*] Caricati {len(clienti)} clienti dal CSV")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# ============================================================================
# SCENARIO 1: UTENTI NORMALI (80% del traffico)
# ============================================================================
print("[*] Generazione traffico normale...")

eventi_normali = []
now = datetime.now()

for _ in range(150):  # 150 operazioni normali
    cliente = random.choice(clienti)
    
    # Orari diurni (8-20)
    giorni_fa = random.randint(0, 7)
    ora = random.randint(8, 20)
    minuto = random.randint(0, 59)
    secondo = random.randint(0, 59)
    
    timestamp = (now - timedelta(days=giorni_fa)).replace(
        hour=ora, minute=minuto, second=secondo
    ).isoformat()
    
    ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    porta = random.randint(8000, 8002)
    azione = random.choice(['LOGIN', 'PRELIEVO', 'BONIFICO'])
    
    if azione == 'LOGIN':
        eventi_normali.append((timestamp, cliente['customer_id'], ip, azione, None, None, None))
    elif azione == 'PRELIEVO':
        importo = random.randint(50, 500)
        eventi_normali.append((timestamp, cliente['customer_id'], ip, azione, importo, None, None))
    else:  # BONIFICO
        importo = random.randint(100, 1000)
        iban_dest = random.choice(clienti)['iban']
        eventi_normali.append((timestamp, cliente['customer_id'], ip, azione, importo, iban_dest, None))

cur.executemany("INSERT INTO logs (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration) VALUES (?, ?, ?, ?, ?, ?, ?)", eventi_normali)
print(f"[✓] Inseriti {len(eventi_normali)} eventi normali")

# ============================================================================
# SCENARIO 2: ACCESSI NOTTURNI ANOMALI (Problema 3)
# ============================================================================
print("[*] Generazione accessi notturni anomali...")

eventi_notturni = []
customer_notturno = clienti[0]['customer_id']  # Un cliente specifico

for _ in range(8):  # 8 accessi notturni
    giorni_fa = random.randint(0, 5)
    ora = random.randint(1, 5)  # 01:00 - 05:00
    
    timestamp = (now - timedelta(days=giorni_fa)).replace(
        hour=ora, minute=random.randint(0, 59), second=random.randint(0, 59)
    ).isoformat()
    
    ip = f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    eventi_notturni.append((timestamp, customer_notturno, ip, 'LOGIN', None, None, None, 8000, 'USER'))

cur.executemany("INSERT INTO logs (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration) VALUES (?, ?, ?, ?, ?, ?, ?)", eventi_notturni)
print(f"[✓] Inseriti {len(eventi_notturni)} accessi notturni per customer {customer_notturno}")

# ============================================================================
# SCENARIO 3: ACCESSI SIMULTANEI (Problema 2)
# ============================================================================
print("[*] Generazione accessi simultanei...")

eventi_simultanei = []
customer_simultaneo = clienti[1]['customer_id']

base_time = now - timedelta(hours=2)
ip1 = "10.20.30.40"
ip2 = "192.168.50.60"

# Due login quasi contemporanei
eventi_simultanei.append((base_time.isoformat(), customer_simultaneo, ip1, 'LOGIN', None, None, None, 8000, 'USER'))
eventi_simultanei.append(((base_time + timedelta(seconds=30)).isoformat(), customer_simultaneo, ip2, 'LOGIN', None, None, None, 8000, 'USER'))

cur.executemany("INSERT INTO logs (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration) VALUES (?, ?, ?, ?, ?, ?, ?)", eventi_simultanei)
print(f"[✓] Inseriti {len(eventi_simultanei)} accessi simultanei per customer {customer_simultaneo}")

# ============================================================================
# SCENARIO 4: ATM CON PORTE ANOMALE (Problema 4)
# ============================================================================
print("[*] Generazione ATM normali e compromessi...")

eventi_atm = []

# ATM normali
for i in range(5):
    ip_atm = f"192.168.100.{10+i}"
    for _ in range(random.randint(3, 8)):
        timestamp = (now - timedelta(days=random.randint(0, 3))).isoformat()
        cliente = random.choice(clienti)
        azione = random.choice(['PRELIEVO', 'DEPOSITO'])
        importo = random.randint(20, 200)
        eventi_atm.append((timestamp, cliente['customer_id'], ip_atm, azione, importo, None, None, 8000, 'ATM'))

# ATM compromesso (fa bonifici - anomalo!)
ip_atm_bad = "192.168.100.99"
for _ in range(3):
    timestamp = (now - timedelta(days=random.randint(0, 2))).isoformat()
    cliente = random.choice(clienti)
    iban_dest = random.choice(clienti)['iban']
    eventi_atm.append((timestamp, cliente['customer_id'], ip_atm_bad, 'BONIFICO', 500, iban_dest, None, 9999, 'ATM'))

cur.executemany("INSERT INTO logs (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration) VALUES (?, ?, ?, ?, ?, ?, ?)", eventi_atm)
print(f"[✓] Inseriti {len(eventi_atm)} eventi ATM (inclusi anomali)")

# ============================================================================
# SCENARIO 5: BRUTE-FORCE (Problema 5)
# ============================================================================
print("[*] Generazione pattern brute-force...")

eventi_brute = []
ip_attaccante = "45.67.89.123"

base_time = now - timedelta(hours=1)
for i in range(25):  # 25 tentativi in 1 ora
    timestamp = (base_time + timedelta(seconds=i*120)).isoformat()
    eventi_brute.append((timestamp, random.choice(clienti)['customer_id'], ip_attaccante, 'LOGIN', None, None, None, 8000, 'USER'))

cur.executemany("INSERT INTO logs (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration) VALUES (?, ?, ?, ?, ?, ?, ?)", eventi_brute)
print(f"[✓] Inseriti {len(eventi_brute)} tentativi brute-force da IP {ip_attaccante}")

# ============================================================================
# SCENARIO 6: FLUSSO AML ANOMALO (Problema 1)
# ============================================================================
print("[*] Generazione flusso AML sospetto...")

eventi_aml = []
iban_sospetto = clienti[5]['customer_id']

# 10 bonifici da mittenti diversi verso lo stesso account
for i in range(10):
    timestamp = (now - timedelta(days=random.randint(0, 6))).isoformat()
    mittente = clienti[20+i]['customer_id']
    ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    importo = random.randint(150, 400)
    
    # Il bonifico "va verso" iban_sospetto, ma nel db registriamo dal punto di vista del mittente
    eventi_aml.append((timestamp, mittente, ip, 'BONIFICO', importo, clienti[5]['iban'], None, 8000, 'USER'))

cur.executemany("INSERT INTO logs (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration) VALUES (?, ?, ?, ?, ?, ?, ?)", eventi_aml)
print(f"[✓] Inseriti {len(eventi_aml)} bonifici verso account sospetto AML")

# ============================================================================
# SCENARIO 7: LOW & SLOW (Problema 10)
# ============================================================================
print("[*] Generazione pattern Low & Slow...")

eventi_low_slow = []
customer_low_slow = clienti[10]['customer_id']
ip_low_slow = "88.99.100.101"

# 25 prelievi piccoli distribuiti in 7 giorni
for i in range(25):
    giorni_fa = i % 7
    ora = random.randint(9, 18)
    timestamp = (now - timedelta(days=giorni_fa)).replace(
        hour=ora, minute=random.randint(0, 59)
    ).isoformat()
    
    importo = random.randint(50, 95)  # Importi piccoli ma frequenti
    eventi_low_slow.append((timestamp, customer_low_slow, ip_low_slow, 'PRELIEVO', importo, None, None, 8000, 'USER'))

cur.executemany("INSERT INTO logs (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration) VALUES (?, ?, ?, ?, ?, ?, ?)", eventi_low_slow)
print(f"[✓] Inseriti {len(eventi_low_slow)} eventi Low & Slow")

# ============================================================================
# SCENARIO 8: PATTERN API ANOMALI (Problema 7)
# ============================================================================
print("[*] Generazione pattern API ripetitivi...")

eventi_api = []
ip_bot = "77.88.99.100"

for i in range(20):
    timestamp = (now - timedelta(hours=5) + timedelta(minutes=i*10)).isoformat()
    eventi_api.append((timestamp, random.choice(clienti)['customer_id'], ip_bot, 'LOGIN', None, None, None, 8000, 'USER'))

cur.executemany("INSERT INTO logs (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration) VALUES (?, ?, ?, ?, ?, ?, ?)", eventi_api)
print(f"[✓] Inseriti {len(eventi_api)} eventi con pattern API meccanico")

conn.commit()
conn.close()

print("")
print("[✓] Database popolato con successo!")
print("")
print("RIEPILOGO DATI INSERITI:")
print("--------------------------------")
print(f"  • Operazioni normali:        {len(eventi_normali)}")
print(f"  • Accessi notturni anomali:  {len(eventi_notturni)}")
print(f"  • Accessi simultanei:        {len(eventi_simultanei)}")
print(f"  • Eventi ATM:                {len(eventi_atm)}")
print(f"  • Tentativi brute-force:     {len(eventi_brute)}")
print(f"  • Flusso AML sospetto:       {len(eventi_aml)}")
print(f"  • Pattern Low & Slow:        {len(eventi_low_slow)}")
print(f"  • Pattern API meccanici:     {len(eventi_api)}")
print("")
totale = (len(eventi_normali) + len(eventi_notturni) + len(eventi_simultanei) + 
          len(eventi_atm) + len(eventi_brute) + len(eventi_aml) + 
          len(eventi_low_slow) + len(eventi_api))
print(f"TOTALE EVENTI:                 {totale}")

EOF

echo ""
echo "================================================================================"
echo "[✓] POPOLAMENTO COMPLETATO"
echo ""
echo "Database:    $DB_PATH"
echo ""
echo "Ora puoi eseguire gli script di analisi con:"
echo "  cd /workspaces/SO/script"
echo "  ./esegui_tutti_controlli.sh"
echo ""
echo "================================================================================"
