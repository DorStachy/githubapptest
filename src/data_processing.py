"""
Data processing utilities — INTENTIONALLY VULNERABLE for CodeFence testing.

Covers: YAML deserialization, pickle, template injection, LDAP injection,
        unsafe regex, HTTP header injection, and SAFE counterparts.
"""

import yaml
import pickle
import re
import ldap3
from jinja2 import Template, Environment, select_autoescape
from flask import request, make_response


# ─────────────────────── YAML DESERIALIZATION (CRITICAL) ────────────────
def load_config_unsafe(yaml_string: str) -> dict:
    """yaml.load without Loader — can execute arbitrary Python."""
    return yaml.load(yaml_string)


# ─────────────────────── YAML — SAFE (no vuln) ────────────────────────
def load_config_safe(yaml_string: str) -> dict:
    """SafeLoader prevents code execution."""
    return yaml.safe_load(yaml_string)


# ─────────────────────── PICKLE DESERIALIZATION (CRITICAL) ─────────────
def deserialize_object(data: bytes) -> object:
    """pickle.loads on untrusted data = arbitrary code execution."""
    return pickle.loads(data)


# ─────────────────────── PICKLE — SAFE ALTERNATIVE (no vuln) ──────────
def deserialize_object_safe(data: str) -> dict:
    """Use JSON for untrusted data."""
    import json
    return json.loads(data)


# ─────────────────────── TEMPLATE INJECTION / SSTI (CRITICAL) ─────────
def render_greeting(username: str) -> str:
    """User input directly in Jinja2 template string — SSTI attack."""
    template = Template(f"Hello {username}, welcome!")
    return template.render()


# ─────────────────────── SSTI — SAFE (no vuln) ───────────────────────
def render_greeting_safe(username: str) -> str:
    """Pass user input as variable, not template source."""
    env = Environment(autoescape=select_autoescape(['html']))
    template = env.from_string("Hello {{ name }}, welcome!")
    return template.render(name=username)


# ─────────────────────── LDAP INJECTION (HIGH) ──────────────────────
def find_user_ldap(username: str) -> list:
    """Unsanitised input in LDAP filter — injection attack."""
    server = ldap3.Server('ldap://ldap.internal:389')
    conn = ldap3.Connection(server, auto_bind=True)
    # Attacker can use: username = "admin)(|(password=*)"
    conn.search(
        'dc=company,dc=com',
        f'(&(objectClass=person)(uid={username}))',
        attributes=['cn', 'mail'],
    )
    return conn.entries


# ─────────────────────── LDAP — SAFE (no vuln) ─────────────────────
def find_user_ldap_safe(username: str) -> list:
    """Escape special LDAP characters."""
    from ldap3.utils.conv import escape_filter_chars
    safe_username = escape_filter_chars(username)
    server = ldap3.Server('ldap://ldap.internal:389')
    conn = ldap3.Connection(server, auto_bind=True)
    conn.search(
        'dc=company,dc=com',
        f'(&(objectClass=person)(uid={safe_username}))',
        attributes=['cn', 'mail'],
    )
    return conn.entries


# ─────────────────────── REGEX DOS / REDOS (MEDIUM) ────────────────
def validate_url(url: str) -> bool:
    """Catastrophic backtracking on crafted input."""
    pattern = r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
    return bool(re.match(pattern, url))


# ─────────────────────── SAFE REGEX (no vuln) ─────────────────────
def validate_url_safe(url: str) -> bool:
    """Simple non-backtracking pattern."""
    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except ValueError:
        return False


# ─────────────────────── HTTP HEADER INJECTION (HIGH) ──────────────
def set_redirect_header(url: str):
    """CRLF injection in response header."""
    response = make_response('', 302)
    # Attacker can inject: url = "http://evil.com\r\nSet-Cookie: admin=true"
    response.headers['Location'] = url
    return response


# ─────────────────────── INFORMATION DISCLOSURE (LOW) ──────────────
def debug_endpoint():
    """Exposes internal state to any caller."""
    import sys
    import platform
    return {
        'python_version': sys.version,
        'platform': platform.platform(),
        'env': dict(__import__('os').environ),   # leaks ALL env vars!
        'modules': list(sys.modules.keys()),
    }


# ─────────────────────── SAFE DEBUG (no vuln) ────────────────────
def health_check():
    """Returns only non-sensitive info."""
    return {'status': 'ok', 'uptime': 'healthy'}
