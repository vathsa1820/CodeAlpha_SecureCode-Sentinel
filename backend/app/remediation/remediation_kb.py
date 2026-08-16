from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class RemediationGuidance(BaseModel):
    """
    Deterministic remediation guidance schema for security findings.
    """
    title: str = Field(..., description="Actionable title for remediation guidance")
    explanation: str = Field(..., description="Technical explanation of the security vulnerability")
    impact: str = Field(..., description="Potential security impact if left unaddressed")
    recommendation: str = Field(..., description="Specific step-by-step remediation recommendation")
    best_practice: str = Field(..., description="Industry standard secure coding best practice")
    secure_example: str = Field(..., description="Remediated code example demonstrating safe coding")
    cwe: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID")

# Central Knowledge Base for deterministic remediation guidance
REMEDIATION_KB: Dict[str, RemediationGuidance] = {
    "CODE_INJECTION": RemediationGuidance(
        title="Avoid Dynamic Code Execution",
        explanation="Dynamic code evaluation functions like eval() or exec() parse and execute arbitrary text strings as Python code at runtime.",
        impact="If untrusted user input reaches eval() or exec(), an attacker can execute arbitrary system commands, bypass security controls, or gain full control of the host process.",
        recommendation="Replace eval() and exec() with safer parsing mechanisms such as ast.literal_eval() for safe data structure parsing, or explicit mathematical parser libraries.",
        best_practice="Never pass user-controlled input directly to dynamic code evaluators.",
        secure_example="""import ast

# SECURE: Use ast.literal_eval for safe literal evaluation
try:
    result = ast.literal_eval(user_input)
except (ValueError, SyntaxError):
    result = None""",
        cwe="CWE-95",
    ),

    "COMMAND_INJECTION": RemediationGuidance(
        title="Prevent OS Command Injection",
        explanation="Invoking system shells with shell=True or passing unsanitized strings to command execution functions allows shell command separators (&, |, ;) to inject arbitrary commands.",
        impact="Attackers can execute unauthorized system commands, read sensitive files, modify system configurations, or launch remote shells.",
        recommendation="Disable shell execution by setting shell=False and pass command arguments as a list of strings rather than a single concatenated string.",
        best_practice="Avoid invoking system command shells directly. Use native Python libraries or strictly validated argument arrays with shell=False.",
        secure_example="""import subprocess

# SECURE: Pass arguments as an array with shell=False
allowed_ip = "127.0.0.1"
result = subprocess.run(["ping", "-c", "1", allowed_ip], shell=False, capture_output=True)""",
        cwe="CWE-78",
    ),

    "HARDCODED_SECRET": RemediationGuidance(
        title="Remove Hardcoded Credentials and Secrets",
        explanation="Storing passwords, API keys, private keys, or access tokens directly in source code exposes credentials in version control systems and distribution packages.",
        impact="Compromised credentials allow unauthorized access to production infrastructure, third-party APIs, and sensitive database systems.",
        recommendation="Extract all credentials from source code into environment variables or use a secret management solution (e.g. AWS Secrets Manager, HashiCorp Vault).",
        best_practice="Load sensitive configuration at runtime from environment variables or secure key vaults.",
        secure_example="""import os

# SECURE: Retrieve credentials from environment variables
api_key = os.environ.get("API_KEY")
if not api_key:
    raise ValueError("API_KEY environment variable is not configured")""",
        cwe="CWE-798",
    ),

    "INSECURE_RANDOMNESS": RemediationGuidance(
        title="Use Cryptographically Secure Random Generators",
        explanation="The standard 'random' module uses the Mersenne Twister algorithm, which is pseudo-random and deterministic if previous outputs or seeds are observed.",
        impact="Predictable random values can lead to session hijacking, token forgery, or compromised cryptographic keys.",
        recommendation="Replace the standard 'random' module with Python's 'secrets' module for security-sensitive operations such as token, password, or key generation.",
        best_practice="Use cryptographically secure random number generators (CSPRNG) for all security operations.",
        secure_example="""import secrets

# SECURE: Use secrets module for cryptographically secure tokens
session_token = secrets.token_hex(32)""",
        cwe="CWE-330",
    ),

    "WEAK_CRYPTOGRAPHY": RemediationGuidance(
        title="Upgrade Weak Cryptographic Hash Functions",
        explanation="Legacy hash functions like MD5 and SHA-1 suffer from well-documented collision vulnerabilities and practical attack vectors.",
        impact="Collision vulnerabilities enable message forgery, digital signature tampering, and compromised password hashing.",
        recommendation="Upgrade legacy MD5 or SHA-1 hashes to strong algorithms such as SHA-256, SHA-512, or dedicated password hashing algorithms (Argon2, bcrypt, PBKDF2).",
        best_practice="Use SHA-256 or SHA-512 for general hashing, and Argon2/bcrypt for password storage.",
        secure_example="""import hashlib

# SECURE: Use SHA-256 for cryptographic hashing
secure_hash = hashlib.sha256(data.encode("utf-8")).hexdigest()""",
        cwe="CWE-327",
    ),

    "INSECURE_DESERIALIZATION": RemediationGuidance(
        title="Prevent Unsafe Object Deserialization",
        explanation="Deserializing untrusted data with modules like 'pickle' or 'marshal' can instantiate arbitrary Python objects and trigger code execution during unpickling.",
        impact="Remote Code Execution (RCE) during data deserialization.",
        recommendation="Avoid pickling untrusted data. Use safe data interchange formats such as JSON, Protocol Buffers, or MessagePack.",
        best_practice="Never deserialize untrusted byte streams using pickle.",
        secure_example="""import json

# SECURE: Use JSON for safe structured data serialization
data = json.loads(untrusted_json_string)""",
        cwe="CWE-502",
    ),

    "PATH_TRAVERSAL": RemediationGuidance(
        title="Sanitize File Path Inputs",
        explanation="Accepting file path inputs containing directory traversal sequences (../) allows reading or writing files outside the intended target directory.",
        impact="Unauthorized file exposure, arbitrary file write, or system file overwrite.",
        recommendation="Sanitize input file names using os.path.basename() and verify resolved canonical paths using os.path.abspath().",
        best_practice="Validate target file paths against a strict base directory boundary before performing file I/O operations.",
        secure_example="""import os

# SECURE: Validate file path resides within base directory
safe_name = os.path.basename(user_filename)
target_path = os.path.abspath(os.path.join(BASE_DIR, safe_name))
if not target_path.startswith(os.path.abspath(BASE_DIR)):
    raise ValueError("Access denied: path traversal attempt")""",
        cwe="CWE-22",
    ),
}

DEFAULT_REMEDIATION = RemediationGuidance(
    title="Review Code Security Finding",
    explanation="Static analysis identified a potential code quality or security rule violation.",
    impact="Unvalidated or non-standard code patterns may increase application attack surface.",
    recommendation="Review the flagged code snippet and apply standard secure coding practices.",
    best_practice="Validate all external inputs, enforce strict error handling, and adhere to least-privilege access principles.",
    secure_example="""# Validate all inputs and ensure safe operational boundaries
def process_data(input_val):
    if not isinstance(input_val, str) or len(input_val) > 100:
        raise ValueError("Invalid input")
    return input_val.strip()""",
    cwe=None,
)
