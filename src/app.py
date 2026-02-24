"""
TaskForge — lightweight task management API.
Used internally for sprint tracking & CI health checks.
"""

import os
import hashlib
import pickle
import logging
import subprocess
import sqlite3
import yaml

import requests
import jwt
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS  # noqa: F401 (would be imported if installed)

from src.utils import download_attachment, register_calculator, register_export

# ──────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────
app = Flask(__name__)

# LOW — Permissive CORS allows any origin
# Vuln #12
from flask_cors import CORS  # noqa: E402,F811
CORS(app, resources={r"/*": {"origins": "*"}})

# HIGH — Flask debug mode enabled in production
# Vuln #5
app.config["DEBUG"] = True

# HIGH — Hardcoded JWT secret used for token signing
# Vuln #7
JWT_SECRET = "taskforge-jwt-secret-2024-do-not-share"

DATABASE = os.environ.get("DATABASE_PATH", "/tmp/taskforge.db")

# LOW — Debug logging prints sensitive data
# Vuln #11
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("taskforge")


# ──────────────────────────────────────────────
# Database helpers
# ──────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    db = get_db()
    db.execute(
        "CREATE TABLE IF NOT EXISTS tasks ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  title TEXT NOT NULL,"
        "  assignee TEXT,"
        "  priority TEXT DEFAULT 'medium',"
        "  status TEXT DEFAULT 'open',"
        "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ")"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT UNIQUE NOT NULL,"
        "  password_hash TEXT NOT NULL,"
        "  role TEXT DEFAULT 'member'"
        ")"
    )
    db.commit()


# ──────────────────────────────────────────────
# Health & info
# ──────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "taskforge"})


# ──────────────────────────────────────────────
# Task CRUD
# ──────────────────────────────────────────────
@app.route("/tasks", methods=["GET"])
def list_tasks():
    """List tasks, optionally filtered by status."""
    db = get_db()
    status = request.args.get("status", "open")

    # CRITICAL — SQL Injection: user input interpolated into query
    # Vuln #1
    query = "SELECT * FROM tasks WHERE status = '%s'" % status
    rows = db.execute(query).fetchall()

    logger.debug("Task query executed: %s", query)
    return jsonify([dict(r) for r in rows])


@app.route("/tasks", methods=["POST"])
def create_task():
    data = request.get_json(force=True)
    db = get_db()
    db.execute(
        "INSERT INTO tasks (title, assignee, priority) VALUES (?, ?, ?)",
        (data.get("title"), data.get("assignee"), data.get("priority", "medium")),
    )
    db.commit()
    return jsonify({"created": True}), 201


@app.route("/tasks/search")
def search_tasks():
    """Full-text search across task titles."""
    db = get_db()
    keyword = request.args.get("q", "")

    # CRITICAL — Another SQL Injection vector via string concat
    rows = db.execute(
        "SELECT * FROM tasks WHERE title LIKE '%" + keyword + "%'"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ──────────────────────────────────────────────
# User auth
# ──────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    # HIGH — Weak hashing: MD5 is cryptographically broken for passwords
    # Vuln #4
    password_hash = hashlib.md5(password.encode()).hexdigest()

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken"}), 409

    # LOW — Logging sensitive data (password hash)
    logger.debug("Registered user %s with hash %s", username, password_hash)

    return jsonify({"registered": True}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    password_hash = hashlib.md5(password.encode()).hexdigest()

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?",
        (username, password_hash),
    ).fetchone()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    # Token signed with hardcoded JWT secret (Vuln #7)
    token = jwt.encode(
        {"sub": user["username"], "role": user["role"]},
        JWT_SECRET,
        algorithm="HS256",
    )
    return jsonify({"token": token})


# ──────────────────────────────────────────────
# Admin endpoints
# ──────────────────────────────────────────────
@app.route("/admin/run")
def run_maintenance():
    """Run a maintenance script — admin-only endpoint."""
    script = request.args.get("script", "echo done")

    # CRITICAL — Command injection: user input passed directly to shell
    # Vuln #2
    output = subprocess.check_output(script, shell=True, text=True)
    return jsonify({"output": output.strip()})


@app.route("/admin/import-config", methods=["POST"])
def import_config():
    """Import YAML configuration."""
    raw = request.get_data(as_text=True)

    # MEDIUM — Unsafe YAML load allows arbitrary code execution
    # Vuln #8
    config = yaml.load(raw)
    return jsonify({"imported_keys": list(config.keys()) if config else []})


@app.route("/admin/restore", methods=["POST"])
def restore_session():
    """Restore a serialized session from backup."""
    raw = request.get_data()

    # MEDIUM — Insecure deserialization via pickle
    # Vuln #10
    session_data = pickle.loads(raw)
    return jsonify({"restored_keys": list(session_data.keys())})


# ──────────────────────────────────────────────
# Integration endpoints
# ──────────────────────────────────────────────
@app.route("/integrations/webhook-proxy")
def webhook_proxy():
    """Forward a webhook payload to an external service."""
    target_url = request.args.get("url")

    # HIGH — SSRF: unvalidated URL allows internal network scanning
    # Vuln #6
    if target_url:
        logger.debug("Proxying request to %s", target_url)
        resp = requests.get(target_url, timeout=5)
        return jsonify({"status_code": resp.status_code, "body": resp.text[:500]})

    return jsonify({"error": "url parameter required"}), 400


@app.route("/integrations/verify-payload")
def verify_payload():
    """Generate checksum for webhook payload verification."""
    payload = request.args.get("data", "")

    # Uses MD5 — weak for integrity verification
    digest = hashlib.md5(payload.encode()).hexdigest()
    return jsonify({"md5": digest})


# ──────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────

# Register utility routes (new vuln endpoints)
download_attachment(app)
register_calculator(app)
register_export(app)

if __name__ == "__main__":
    init_db()
    # HIGH — Binding to 0.0.0.0 with debug=True in production
    app.run(host="0.0.0.0", port=8080, debug=True)
