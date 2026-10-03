import os
import sqlite3
import hashlib
import secrets
import time
import json
import urllib.request
import urllib.error
from functools import wraps

from flask import Flask, request, jsonify, session, g, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "swap.db")
KEY_PATH = os.path.join(BASE_DIR, ".fernet.key")

TOKENS_PER_KEY = int(os.environ.get("TOKENS_PER_KEY", "5000"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# --- encryption key for API keys at rest (auto-generated on first run, gitignored) ---
if os.path.exists(KEY_PATH):
    with open(KEY_PATH, "rb") as f:
        FERNET_KEY = f.read()
else:
    FERNET_KEY = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(FERNET_KEY)
    os.chmod(KEY_PATH, 0o600)
fernet = Fernet(FERNET_KEY)

PROVIDERS = {
    "openai":    {"label": "OpenAI",    "prefix": "sk-"},
    "anthropic": {"label": "Anthropic", "prefix": "sk-ant-"},
    "google":    {"label": "Google / Gemini", "prefix": None},
}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token_balance INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS api_keys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            provider TEXT NOT NULL,
            key_hash TEXT UNIQUE NOT NULL,
            encrypted_key TEXT NOT NULL,
            last4 TEXT NOT NULL,
            validated TEXT NOT NULL,
            credited_tokens INTEGER NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            kind TEXT NOT NULL,
            amount INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        """
    )
    db.commit()
    db.close()


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user_id"):
            return jsonify({"error": "not logged in"}), 401
        return fn(*a, **kw)
    return wrapper


def current_user(db):
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def record_transaction(db, user_id, kind, amount, reason):
    db.execute(
        "INSERT INTO transactions(user_id, kind, amount, reason, created_at) VALUES (?,?,?,?,?)",
        (user_id, kind, amount, reason, time.time()),
    )


def validate_key_live(provider, api_key):
    """Best-effort real check against the provider. Never raises; falls back to format check."""
    try:
        if provider == "openai":
            req = urllib.request.Request(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            urllib.request.urlopen(req, timeout=6)
            return "live-verified"
        if provider == "anthropic":
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
            )
            urllib.request.urlopen(req, timeout=6)
            return "live-verified"
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "rejected"
        return "format-only"
    except Exception:
        return "format-only"
    return "format-only"


@app.route("/")
def index():
    return render_template("index.html", providers=PROVIDERS, tokens_per_key=TOKENS_PER_KEY)


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or "@" not in email or len(password) < 8:
        return jsonify({"error": "valid email and password (8+ chars) required"}), 400

    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        return jsonify({"error": "email already registered"}), 409

    cur = db.execute(
        "INSERT INTO users(email, password_hash, token_balance, created_at) VALUES (?,?,?,?)",
        (email, generate_password_hash(password), 0, time.time()),
    )
    db.commit()
    session["user_id"] = cur.lastrowid
    return jsonify({"ok": True, "email": email, "token_balance": 0})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "invalid email or password"}), 401

    session["user_id"] = user["id"]
    return jsonify({"ok": True, "email": user["email"], "token_balance": user["token_balance"]})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def me():
    if not session.get("user_id"):
        return jsonify({"logged_in": False})
    db = get_db()
    user = current_user(db)
    if not user:
        session.clear()
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "email": user["email"], "token_balance": user["token_balance"]})


@app.route("/api/keys/submit", methods=["POST"])
@login_required
def submit_key():
    data = request.get_json(force=True, silent=True) or {}
    provider = data.get("provider")
    api_key = (data.get("api_key") or "").strip()

    if provider not in PROVIDERS:
        return jsonify({"error": "unknown provider"}), 400
    if len(api_key) < 12:
        return jsonify({"error": "that doesn't look like a real API key"}), 400
    prefix = PROVIDERS[provider]["prefix"]
    if prefix and not api_key.startswith(prefix):
        return jsonify({"error": f"{PROVIDERS[provider]['label']} keys should start with '{prefix}'"}), 400

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    db = get_db()
    if db.execute("SELECT 1 FROM api_keys WHERE key_hash = ?", (key_hash,)).fetchone():
        return jsonify({"error": "this key has already been redeemed"}), 409

    validated = validate_key_live(provider, api_key)
    if validated == "rejected":
        return jsonify({"error": "provider rejected this key (invalid or revoked)"}), 400

    encrypted = fernet.encrypt(api_key.encode()).decode()
    last4 = api_key[-4:]
    user = current_user(db)

    db.execute(
        """INSERT INTO api_keys(user_id, provider, key_hash, encrypted_key, last4, validated, credited_tokens, created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (user["id"], provider, key_hash, encrypted, last4, validated, TOKENS_PER_KEY, time.time()),
    )
    db.execute(
        "UPDATE users SET token_balance = token_balance + ? WHERE id = ?",
        (TOKENS_PER_KEY, user["id"]),
    )
    record_transaction(db, user["id"], "credit", TOKENS_PER_KEY, f"{provider} key redeemed ({validated})")
    db.commit()

    new_balance = db.execute("SELECT token_balance FROM users WHERE id = ?", (user["id"],)).fetchone()[0]
    return jsonify({"ok": True, "credited": TOKENS_PER_KEY, "validated": validated, "token_balance": new_balance})


@app.route("/api/keys")
@login_required
def list_keys():
    db = get_db()
    rows = db.execute(
        "SELECT provider, last4, validated, credited_tokens, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/spend", methods=["POST"])
@login_required
def spend():
    data = request.get_json(force=True, silent=True) or {}
    amount = int(data.get("amount") or 0)
    reason = data.get("reason") or "feature access"
    if amount <= 0:
        return jsonify({"error": "amount must be positive"}), 400

    db = get_db()
    user = current_user(db)
    if user["token_balance"] < amount:
        return jsonify({"error": "insufficient token balance"}), 402

    db.execute("UPDATE users SET token_balance = token_balance - ? WHERE id = ?", (amount, user["id"]))
    record_transaction(db, user["id"], "debit", amount, reason)
    db.commit()

    new_balance = db.execute("SELECT token_balance FROM users WHERE id = ?", (user["id"],)).fetchone()[0]
    return jsonify({"ok": True, "token_balance": new_balance})


@app.route("/api/transactions")
@login_required
def transactions():
    db = get_db()
    rows = db.execute(
        "SELECT kind, amount, reason, created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 100",
        (session["user_id"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=8421, debug=True)
