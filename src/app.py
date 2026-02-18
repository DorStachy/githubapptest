"""
Bandit targets — Python security anti-patterns.
WARNING: Intentionally vulnerable code for scanner testing.
"""

import os
import pickle
import subprocess
import hashlib


# B105: hardcoded_password_string
DB_PASSWORD = "SuperSecretPassword123!"


def run_user_command(user_input: str) -> str:
    """B602: subprocess_popen_with_shell_equals_true"""
    result = subprocess.Popen(user_input, shell=True, stdout=subprocess.PIPE)
    return result.stdout.read().decode()


def unsafe_eval(expression: str):
    """B307: eval used"""
    return eval(expression)


def load_data(data: bytes):
    """B301: pickle.loads"""
    return pickle.loads(data)


def weak_hash(password: str) -> str:
    """B303: use of insecure MD5 hash"""
    return hashlib.md5(password.encode()).hexdigest()


def run_system_command(cmd: str):
    """B605: start_process_with_a_shell"""
    os.system(cmd)


if __name__ == "__main__":
    print(run_user_command("echo hello"))
    print(unsafe_eval("2 + 2"))
    print(weak_hash("password"))
