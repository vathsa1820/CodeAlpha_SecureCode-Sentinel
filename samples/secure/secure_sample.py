# SECURITY NOTICE: THIS FILE IS A SECURE CODING TEST FIXTURE ONLY.
# NEVER EXECUTE, IMPORT, OR RUN THIS FILE. IT IS USED STRICTLY FOR STATIC ANALYSIS TESTING.

import os
import ast
import secrets
import hashlib

# 1. Configuration loaded securely from environment variables
DB_HOST = os.getenv("DB_HOST", "localhost")
APP_ENV = os.getenv("APP_ENV", "production")

def process_user_expression(user_input: str):
    """
    SECURE: Using ast.literal_eval for safe mathematical/literal parsing
    """
    print("Safely parsing literal expression")
    try:
        return ast.literal_eval(user_input)
    except (ValueError, SyntaxError):
        return None

def generate_session_token() -> str:
    """
    SECURE: Using secrets module for cryptographically strong random token generation
    """
    return secrets.token_hex(32)

def hash_user_password(password: str) -> str:
    """
    SECURE: Using SHA-256 for secure cryptographic hashing
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()
