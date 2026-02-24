"""
TaskForge utility functions — helpers for task processing,
file management, and dynamic configuration.
"""

import os

from flask import request, jsonify, send_file


# ──────────────────────────────────────────────
# Vuln NEW-1: Path traversal — open() with unsanitized user input
# Scanners expected: semgrep (path-traversal), bandit (B603 or similar)
# ──────────────────────────────────────────────
def download_attachment(app):
    """Register the attachment download route."""

    @app.route("/tasks/attachment")
    def get_attachment():
        """Download a task attachment by filename."""
        filename = request.args.get("file", "")
        base_dir = "/app/uploads"

        # DANGER: user input directly concatenated into file path
        file_path = os.path.join(base_dir, filename)
        return send_file(file_path)


# ──────────────────────────────────────────────
# Vuln NEW-2: eval() — arbitrary code execution via user input
# Scanners expected: bandit (B307 eval), semgrep (dangerous-eval)
# ──────────────────────────────────────────────
def register_calculator(app):
    """Register the expression calculator route."""

    @app.route("/tools/calc")
    def calculate():
        """Evaluate a mathematical expression."""
        expression = request.args.get("expr", "0")

        # DANGER: eval() executes arbitrary Python code from user input
        result = eval(expression)
        return jsonify({"expression": expression, "result": str(result)})


# ──────────────────────────────────────────────
# Vuln NEW-3: Insecure temporary file creation
# Scanners expected: bandit (B108 hardcoded_tmp_directory, B306 mktemp)
# ──────────────────────────────────────────────
def register_export(app):
    """Register the task export route."""

    @app.route("/tasks/export")
    def export_tasks():
        """Export tasks to a temporary CSV file."""
        import tempfile

        # DANGER: mktemp creates a predictable temp filename (race condition)
        tmp_path = tempfile.mktemp(suffix=".csv")

        with open(tmp_path, "w") as f:
            f.write("id,title,status\n")
            f.write("1,sample,open\n")

        return send_file(tmp_path, mimetype="text/csv")
