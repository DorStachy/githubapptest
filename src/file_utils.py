"""
File handling utilities — INTENTIONALLY VULNERABLE for CodeFence testing.

Covers: command injection, XML external entity (XXE), unsafe temp files,
        zip slip, arbitrary file write, SSRF via file:// protocol, and SAFE versions.
"""

import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
import shutil
from lxml import etree
from flask import request, send_file


# ─────────────────────── COMMAND INJECTION (CRITICAL) ───────────────────
def convert_image(filename: str) -> str:
    """Shell injection through unsanitised filename."""
    output = f"/tmp/converted_{filename}.png"
    # Attacker can use: filename = "x; rm -rf /"
    os.system(f"convert /uploads/{filename} {output}")
    return output


def run_lint(code_path: str) -> str:
    """subprocess with shell=True — command injection."""
    result = subprocess.run(
        f"pylint {code_path} --output-format=json",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


# ─────────────────────── COMMAND INJECTION — SAFE (no vuln) ────────────
def convert_image_safe(filename: str) -> str:
    """Using list args avoids shell interpretation."""
    output = f"/tmp/converted_{os.path.basename(filename)}.png"
    subprocess.run(
        ["convert", f"/uploads/{os.path.basename(filename)}", output],
        check=True,
    )
    return output


# ─────────────────────── XXE — XML EXTERNAL ENTITY (CRITICAL) ──────────
def parse_xml_unsafe(xml_string: str) -> dict:
    """Default lxml parser resolves external entities — XXE attack."""
    parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(xml_string.encode(), parser)
    return {child.tag: child.text for child in root}


# ─────────────────────── XXE — SAFE (no vuln) ─────────────────────────
def parse_xml_safe(xml_string: str) -> dict:
    """Disable entity resolution and network access."""
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
    )
    root = etree.fromstring(xml_string.encode(), parser)
    return {child.tag: child.text for child in root}


# ─────────────────────── ZIP SLIP (HIGH) ───────────────────────────────
def extract_zip_unsafe(zip_path: str, dest: str) -> list:
    """Doesn't check for '../' in filenames — ZIP slip attack."""
    extracted = []
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            # Directly join — attacker can escape dest directory
            target = os.path.join(dest, info.filename)
            zf.extract(info, dest)
            extracted.append(target)
    return extracted


# ─────────────────────── ZIP SLIP — SAFE (no vuln) ─────────────────────
def extract_zip_safe(zip_path: str, dest: str) -> list:
    """Validates each entry stays within the destination directory."""
    extracted = []
    abs_dest = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(abs_dest):
                raise ValueError(f"Zip slip detected: {info.filename}")
            zf.extract(info, dest)
            extracted.append(target)
    return extracted


# ─────────────────────── UNSAFE TEMP FILE (MEDIUM) ─────────────────────
def write_temp_insecure(data: str) -> str:
    """Predictable temp file path — race condition / symlink attack."""
    path = f"/tmp/app_data_{os.getpid()}.tmp"
    with open(path, "w") as f:
        f.write(data)
    return path


# ─────────────────────── SAFE TEMP FILE (no vuln) ─────────────────────
def write_temp_safe(data: str) -> str:
    """mkstemp creates with restricted permissions and unique name."""
    fd, path = tempfile.mkstemp(prefix="app_data_", suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        f.write(data)
    return path


# ─────────────────────── ARBITRARY FILE WRITE (CRITICAL) ───────────────
def save_upload(filename: str, content: bytes) -> str:
    """No path validation — can overwrite /etc/crontab, ~/.ssh/authorized_keys."""
    dest = os.path.join("/var/www/uploads", filename)
    with open(dest, "wb") as f:
        f.write(content)
    return dest


# ─────────────────────── SSRF VIA FILE PROTOCOL (HIGH) ────────────────
def fetch_resource(url: str) -> bytes:
    """Accepts file:// URLs — reads local filesystem."""
    import urllib.request
    return urllib.request.urlopen(url).read()


# ─────────────────────── EVAL INJECTION (CRITICAL) ────────────────────
def execute_formula(expression: str) -> float:
    """eval() on user input — arbitrary code execution."""
    return eval(expression)


# ─────────────────────── SAFE EXPRESSION (no vuln) ───────────────────
def execute_formula_safe(expression: str) -> float:
    """ast.literal_eval only allows literals — no code execution."""
    import ast
    return ast.literal_eval(expression)
