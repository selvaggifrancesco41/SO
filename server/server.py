# Flask: web framework; request/jsonify for HTTP input/output.
from flask import Flask, request, jsonify
# csv: parse blacklist.csv with headers.
import csv
# sqlite3: local database to store request logs.
import sqlite3
# datetime: timestamps for log entries.
from datetime import datetime
# logging: file-based server logging.
import logging
# os: path utilities and file metadata (mtime).
import os

# Create the Flask application instance.
app = Flask(__name__)

# Resolve the project base directory (two levels above this file).
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# SQLite database where every request event is persisted.
DB_PATH = os.path.join(BASE_DIR, "data", "bank_logs.db")
# Server log file (high-level info, including blocks).
LOG_PATH = os.path.join(BASE_DIR, "logs", "server.log")
# Real-time stream used by the monitoring scripts.
REALTIME_LOG_PATH = os.path.join(BASE_DIR, "logs", "realtime_access.log")
# Blacklist CSV updated by detection scripts.
BLACKLIST_PATH = os.path.join(BASE_DIR, "blacklist.csv")

# Create directories if missing to avoid runtime errors.
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)


# --- logging ---
# Configure Python logging to append to LOG_PATH.
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

# --- database init ---
# Initialize the SQLite database with the logs table (if absent).
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

# Ensure the DB schema exists on startup.
init_db()

# Cache for blacklist contents to avoid re-reading CSV every request.
_blocked_cache = {"mtime": None, "ips": set(), "accounts": set()}

def _get_client_ip():
    # Use X-Forwarded-For for simulated IPs; fallback to remote_addr.
    ip = request.headers.get("X-Forwarded-For")
    if ip:
        ip = ip.split(",")[0].strip()
    else:
        ip = request.remote_addr
    return ip

def _load_blocked_from_blacklist():
    # Read blocked IPs/accounts from CSV with a simple mtime cache.
    try:
        mtime = os.path.getmtime(BLACKLIST_PATH)
    except OSError:
        # If file is missing/unreadable, treat as empty blacklist.
        _blocked_cache["mtime"] = None
        _blocked_cache["ips"] = set()
        _blocked_cache["accounts"] = set()
        return _blocked_cache["ips"], _blocked_cache["accounts"]

    # Return cached values if the file has not changed.
    if _blocked_cache["mtime"] == mtime:
        return _blocked_cache["ips"], _blocked_cache["accounts"]

    # Rebuild sets of blocked identifiers from CSV rows.
    blocked_ips = set()
    blocked_accounts = set()
    with open(BLACKLIST_PATH, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("stato") != "BLOCKED":
                continue
            if row.get("tipo_elemento") == "IP":
                blocked_ips.add(row.get("elemento"))
            elif row.get("tipo_elemento") == "ACCOUNT":
                blocked_accounts.add(row.get("elemento"))

    # Update cache after a successful read.
    _blocked_cache["mtime"] = mtime
    _blocked_cache["ips"] = blocked_ips
    _blocked_cache["accounts"] = blocked_accounts
    return blocked_ips, blocked_accounts

@app.before_request
def block_if_blacklisted():
    # Intercept every request before route handling.
    ip = _get_client_ip()
    customer_id = request.args.get("customer_id")
    blocked_ips, blocked_accounts = _load_blocked_from_blacklist()

    # If IP or account is blocked, short-circuit with 403.
    if ip in blocked_ips or (customer_id and customer_id in blocked_accounts):
        # Log blocked attempts for audit visibility.
        logging.info(f"BLOCCATO customer_id={customer_id} ip={ip}")
        return jsonify({"status": "blocked"}), 403

def salva_evento(customer_id, azione, importo=None, iban=None, session_duration=None):
    # Generate ISO timestamp for consistent logs and DB entries.
    timestamp = datetime.now().isoformat()

    # Resolve the client IP once per event.
    ip = _get_client_ip()

    # Persist the event into SQLite for historical analysis.
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs
        (timestamp, customer_id, ip_address, azione, importo, iban_destinatario, session_duration)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, customer_id, ip, azione, importo, iban, session_duration))
    conn.commit()
    conn.close()

    # Append a structured real-time line for the monitoring scripts.
    # Format: timestamp|customer_id|ip|azione|importo|iban|session_duration
    with open(REALTIME_LOG_PATH, "a") as f:
        f.write(f"{timestamp}|{customer_id}|{ip}|{azione}|{importo or ''}|{iban or ''}|{session_duration or ''}\n")

    # Write a concise summary to the server log.
    logging.info(
        f"{azione} customer_id={customer_id} ip={ip} importo={importo} iban={iban}"
    )

@app.route("/login", methods=["GET"])
def login():
    # Read customer_id and optional session duration from query string.
    customer_id = request.args.get("customer_id")
    durata = request.args.get("session_duration", 0)

    # Log the login event.
    salva_evento(customer_id, "LOGIN", session_duration=durata)
    return jsonify({"status": "ok", "azione": "login"})

@app.route("/bonifico", methods=["GET"])
def bonifico():
    # Read customer_id, amount, and destination IBAN from query string.
    customer_id = request.args.get("customer_id")
    importo = request.args.get("importo")
    iban = request.args.get("iban")

    # Log the transfer event.
    salva_evento(customer_id, "BONIFICO", importo, iban)
    return jsonify({"status": "ok", "azione": "bonifico"})

@app.route("/prelievo", methods=["GET"])
def prelievo():
    # Read customer_id and amount from query string.
    customer_id = request.args.get("customer_id")
    importo = request.args.get("importo")

    # Log the withdrawal event.
    salva_evento(customer_id, "PRELIEVO", importo)
    return jsonify({"status": "ok", "azione": "prelievo"})



@app.route("/deposito", methods=["GET"])
def deposito():
    # Read customer_id and amount from query string.
    customer_id = request.args.get("customer_id")
    importo = request.args.get("importo")

    # Log the deposit event.
    salva_evento(customer_id, "DEPOSITO", importo)
    return jsonify({"status": "ok", "azione": "deposito"})

if __name__ == "__main__":
    # Start the Flask development server on all interfaces.
    print("[+] Avvio server bancario simulato...")
    app.run(host="0.0.0.0", port=8000, debug=False)

