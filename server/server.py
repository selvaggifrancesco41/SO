from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime
import logging
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "bank_logs.db")
LOG_PATH = os.path.join(BASE_DIR, "logs", "server.log")

# crea le cartelle se non esistono
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)


# --- logging ---
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

# --- database init ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
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

init_db()

def salva_evento(customer_id, azione, importo=None, iban=None, session_duration=None):
    timestamp = datetime.now().isoformat()
    ip = request.remote_addr

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs
        (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, customer_id, ip, azione, importo, iban, session_duration))
    conn.commit()
    conn.close()

    logging.info(
        f"{azione} customer_id={customer_id} ip={ip} importo={importo} iban={iban}"
    )

@app.route("/login", methods=["GET"])
def login():
    customer_id = request.args.get("customer_id")
    durata = request.args.get("session_duration", 0)

    salva_evento(customer_id, "LOGIN", session_duration=durata)
    return jsonify({"status": "ok", "azione": "login"})

@app.route("/bonifico", methods=["GET"])
def bonifico():
    customer_id = request.args.get("customer_id")
    importo = request.args.get("importo")
    iban = request.args.get("iban")

    salva_evento(customer_id, "BONIFICO", importo, iban)
    return jsonify({"status": "ok", "azione": "bonifico"})

@app.route("/prelievo", methods=["GET"])
def prelievo():
    customer_id = request.args.get("customer_id")
    importo = request.args.get("importo")

    salva_evento(customer_id, "PRELIEVO", importo)
    return jsonify({"status": "ok", "azione": "prelievo"})



@app.route("/deposito", methods=["GET"])
def deposito():
    customer_id = request.args.get("customer_id")
    importo = request.args.get("importo")

    salva_evento(customer_id, "DEPOSITO", importo)
    return jsonify({"status": "ok", "azione": "deposito"})

if __name__ == "__main__":
    print("[+] Avvio server bancario simulato...")
    app.run(host="0.0.0.0", port=8000, debug=False)

