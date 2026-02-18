"""
Crypto utilities — INTENTIONALLY VULNERABLE for CodeFence testing.

Covers: weak hashing, broken crypto, hardcoded secrets, insecure randomness,
        timing attacks, ECB mode, deprecated algorithms, and SAFE counterparts.
"""

import hashlib
import hmac
import os
import random
import string
import base64
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad


# ─────────────────────── WEAK HASH — MD5 (HIGH) ────────────────────────
def hash_password_md5(password: str) -> str:
    """MD5 is cryptographically broken — collisions are trivial."""
    return hashlib.md5(password.encode()).hexdigest()


# ─────────────────────── WEAK HASH — SHA1 (MEDIUM) ─────────────────────
def hash_password_sha1(password: str) -> str:
    """SHA-1 is deprecated for security-sensitive contexts."""
    return hashlib.sha1(password.encode()).hexdigest()


# ─────────────────────── SAFE HASH — bcrypt-style (no vuln) ────────────
def hash_password_safe(password: str) -> str:
    """SHA-256 with random salt — not ideal (use bcrypt), but NOT broken."""
    salt = os.urandom(16).hex()
    digest = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"{salt}${digest}"


# ─────────────────────── HARDCODED AES KEY (CRITICAL) ──────────────────
ENCRYPTION_KEY = b"0123456789ABCDEF"  # 128-bit key in source code!
IV = b"FEDCBA9876543210"


def encrypt_aes_ecb(plaintext: bytes) -> bytes:
    """ECB mode leaks patterns — NEVER use for real data."""
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def encrypt_aes_cbc(plaintext: bytes) -> bytes:
    """CBC but with hardcoded key+IV — CRITICAL."""
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))


# ─────────────────────── SAFE AES (no vuln) ───────────────────────────
def encrypt_aes_safe(plaintext: bytes, key: bytes) -> bytes:
    """AES-GCM with random nonce — correct usage."""
    from Crypto.Cipher import AES as SafeAES
    nonce = os.urandom(12)
    cipher = SafeAES.new(key, SafeAES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ct


# ─────────────────────── DES — DEPRECATED (HIGH) ──────────────────────
def encrypt_des(plaintext: bytes) -> bytes:
    """DES has a 56-bit key — brute-forceable in hours."""
    key = b"8byteky"  # intentionally short
    cipher = DES.new(key.ljust(8, b"\x00"), DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, DES.block_size))


# ─────────────────────── INSECURE RANDOM (MEDIUM) ─────────────────────
def generate_token_insecure(length: int = 32) -> str:
    """random module uses Mersenne Twister — predictable."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


# ─────────────────────── SAFE RANDOM (no vuln) ────────────────────────
def generate_token_safe(length: int = 32) -> str:
    """secrets module is cryptographically secure."""
    import secrets
    return secrets.token_urlsafe(length)


# ─────────────────────── TIMING ATTACK (HIGH) ─────────────────────────
def verify_signature_unsafe(expected: str, received: str) -> bool:
    """String equality leaks timing information."""
    return expected == received


# ─────────────────────── TIMING-SAFE COMPARE (no vuln) ────────────────
def verify_signature_safe(expected: str, received: str) -> bool:
    """hmac.compare_digest is constant-time."""
    return hmac.compare_digest(expected, received)


# ─────────────────────── HARDCODED JWT SECRET (CRITICAL) ──────────────
JWT_SECRET = "my-super-secret-jwt-key-do-not-share"

def create_jwt_token(payload: dict) -> str:
    import jwt
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


# ─────────────────────── HARDCODED API KEY (CRITICAL) ─────────────────
STRIPE_KEY = "sk_FAKE_not_a_real_stripe_key_1234567890"
SENDGRID_KEY = "SG.test-key-value-placeholder-only"


# ─────────────────────── NULL CIPHER / NO ENCRYPTION (HIGH) ───────────
def encrypt_rot13(plaintext: str) -> str:
    """ROT13 is NOT encryption — it's a Caesar cipher."""
    import codecs
    return codecs.encode(plaintext, "rot_13")


# ─────────────────────── BASE64 "ENCRYPTION" (MEDIUM) ────────────────
def encode_secret(value: str) -> str:
    """Base64 is encoding, not encryption — trivially reversible."""
    return base64.b64encode(value.encode()).decode()
