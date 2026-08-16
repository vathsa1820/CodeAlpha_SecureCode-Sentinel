# SECURITY NOTICE: THIS FILE IS AN INTENTIONAL VULNERABILITY TEST FIXTURE ONLY.
# NEVER EXECUTE, IMPORT, OR RUN THIS FILE. IT IS USED STRICTLY FOR STATIC ANALYSIS TESTING.

import os
import random
import hashlib
import subprocess

# 1. Hardcoded Secret / Password
ADMIN_PASSWORD = "SuperSecretPassword123!"
API_KEY = "secret_api_key_xyz_98765"

def process_user_expression(user_input: str):
    """
    VULNERABILITY: Unsafe dynamic evaluation using eval()
    """
    print(f"Evaluating user expression: {user_input}")
    return eval(user_input)  # Bandit: B307 / Semgrep: unsafe-eval-exec

def run_system_diagnostic(user_command: str):
    """
    VULNERABILITY: Unsafe command execution with shell=True
    """
    print(f"Running command: {user_command}")
    # Bandit: B602 / Semgrep: dangerous-subprocess-shell
    result = subprocess.run(f"ping -c 1 {user_command}", shell=True, capture_output=True)
    return result.stdout

def generate_session_token() -> str:
    """
    VULNERABILITY: Use of insecure pseudo-random generator for sensitive tokens
    """
    # Semgrep: insecure-randomness
    token = str(random.randint(100000, 999999))
    return token

def hash_user_password(password: str) -> str:
    """
    VULNERABILITY: Use of weak cryptographic hash algorithm (MD5)
    """
    # Semgrep: insecure-hash-algorithm
    return hashlib.md5(password.encode("utf-8")).hexdigest()
