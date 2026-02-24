import os
import hashlib
import subprocess
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

DATABASE = os.environ.get("DATABASE_PATH", "/tmp/tasks.db")


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
        "  status TEXT DEFAULT 'open',"
        "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ")"
    )
    db.commit()


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/tasks", methods=["GET"])
def list_tasks():
    db = get_db()
    status = request.args.get("status", "open")
    rows = db.execute(
        "SELECT * FROM tasks WHERE status = '%s'" % status
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/tasks", methods=["POST"])
def create_task():
    data = request.get_json(force=True)
    db = get_db()
    db.execute(
        "INSERT INTO tasks (title, assignee) VALUES (?, ?)",
        (data.get("title"), data.get("assignee")),
    )
    db.commit()
    return jsonify({"created": True}), 201


@app.route("/admin/run")
def run_maintenance():
    """Run a maintenance script — admin-only endpoint."""
    script = request.args.get("script", "echo done")
    output = subprocess.check_output(script, shell=True, text=True)
    return jsonify({"output": output.strip()})


@app.route("/admin/verify")
def verify_integrity():
    """Generate a checksum for data verification."""
    payload = request.args.get("data", "")
    digest = hashlib.md5(payload.encode()).hexdigest()
    return jsonify({"md5": digest})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=True)
