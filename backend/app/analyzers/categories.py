import hashlib
from enum import Enum
from typing import Optional, Dict, Any, List

# OWASP Top 10 Version Standard: OWASP Top 10:2021
OWASP_VERSION = "OWASP Top 10:2021"

class VulnerabilityCategory(str, Enum):
    INJECTION = "INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    CODE_INJECTION = "CODE_INJECTION"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    WEAK_CRYPTOGRAPHY = "WEAK_CRYPTOGRAPHY"
    INSECURE_RANDOMNESS = "INSECURE_RANDOMNESS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    AUTHENTICATION = "AUTHENTICATION"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    CONFIGURATION = "CONFIGURATION"
    OTHER = "OTHER"

RULE_CATEGORY_MAP = {
    # Bandit rules
    "B307": VulnerabilityCategory.CODE_INJECTION.value,        # eval
    "B102": VulnerabilityCategory.CODE_INJECTION.value,        # exec
    "B602": VulnerabilityCategory.COMMAND_INJECTION.value,     # shell=True
    "B601": VulnerabilityCategory.COMMAND_INJECTION.value,     # paramiko exec_command
    "B603": VulnerabilityCategory.COMMAND_INJECTION.value,     # subprocess without shell
    "B604": VulnerabilityCategory.COMMAND_INJECTION.value,     # shell=True func
    "B105": VulnerabilityCategory.HARDCODED_SECRET.value,      # hardcoded_password_string
    "B106": VulnerabilityCategory.HARDCODED_SECRET.value,      # hardcoded_password_funcarg
    "B107": VulnerabilityCategory.HARDCODED_SECRET.value,      # hardcoded_password_default
    "B311": VulnerabilityCategory.INSECURE_RANDOMNESS.value,   # random
    "B303": VulnerabilityCategory.WEAK_CRYPTOGRAPHY.value,     # md5
    "B304": VulnerabilityCategory.WEAK_CRYPTOGRAPHY.value,     # ciphers
    "B305": VulnerabilityCategory.WEAK_CRYPTOGRAPHY.value,     # block ciphers
    "B301": VulnerabilityCategory.INSECURE_DESERIALIZATION.value, # pickle
    "B302": VulnerabilityCategory.INSECURE_DESERIALIZATION.value, # marshal

    # Semgrep rule IDs
    "unsafe-eval-exec": VulnerabilityCategory.CODE_INJECTION.value,
    "dangerous-subprocess-shell": VulnerabilityCategory.COMMAND_INJECTION.value,
    "hardcoded-password-secret": VulnerabilityCategory.HARDCODED_SECRET.value,
    "insecure-randomness": VulnerabilityCategory.INSECURE_RANDOMNESS.value,
    "insecure-hash-algorithm": VulnerabilityCategory.WEAK_CRYPTOGRAPHY.value,
}

CWE_CATEGORY_MAP = {
    "CWE-95": VulnerabilityCategory.CODE_INJECTION.value,
    "CWE-94": VulnerabilityCategory.CODE_INJECTION.value,
    "CWE-78": VulnerabilityCategory.COMMAND_INJECTION.value,
    "CWE-77": VulnerabilityCategory.COMMAND_INJECTION.value,
    "CWE-89": VulnerabilityCategory.INJECTION.value,
    "CWE-798": VulnerabilityCategory.HARDCODED_SECRET.value,
    "CWE-259": VulnerabilityCategory.HARDCODED_SECRET.value,
    "CWE-330": VulnerabilityCategory.INSECURE_RANDOMNESS.value,
    "CWE-338": VulnerabilityCategory.INSECURE_RANDOMNESS.value,
    "CWE-327": VulnerabilityCategory.WEAK_CRYPTOGRAPHY.value,
    "CWE-328": VulnerabilityCategory.WEAK_CRYPTOGRAPHY.value,
    "CWE-22": VulnerabilityCategory.PATH_TRAVERSAL.value,
    "CWE-502": VulnerabilityCategory.INSECURE_DESERIALIZATION.value,
    "CWE-287": VulnerabilityCategory.AUTHENTICATION.value,
    "CWE-20": VulnerabilityCategory.INPUT_VALIDATION.value,
}

RULE_CWE_MAP = {
    "B307": "CWE-95",
    "B102": "CWE-95",
    "unsafe-eval-exec": "CWE-95",
    "B602": "CWE-78",
    "B601": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "dangerous-subprocess-shell": "CWE-78",
    "B105": "CWE-798",
    "B106": "CWE-798",
    "B107": "CWE-798",
    "hardcoded-password-secret": "CWE-798",
    "B311": "CWE-330",
    "insecure-randomness": "CWE-330",
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "insecure-hash-algorithm": "CWE-327",
    "B301": "CWE-502",
    "B302": "CWE-502",
}

# Centralized OWASP Top 10:2021 mapping dictionary
CATEGORY_OWASP_MAP = {
    VulnerabilityCategory.CODE_INJECTION.value: "A03:2021-Injection",
    VulnerabilityCategory.COMMAND_INJECTION.value: "A03:2021-Injection",
    VulnerabilityCategory.INJECTION.value: "A03:2021-Injection",
    VulnerabilityCategory.INPUT_VALIDATION.value: "A03:2021-Injection",
    VulnerabilityCategory.HARDCODED_SECRET.value: "A07:2021-Identification and Authentication Failures",
    VulnerabilityCategory.AUTHENTICATION.value: "A07:2021-Identification and Authentication Failures",
    VulnerabilityCategory.WEAK_CRYPTOGRAPHY.value: "A02:2021-Cryptographic Failures",
    VulnerabilityCategory.INSECURE_RANDOMNESS.value: "A02:2021-Cryptographic Failures",
    VulnerabilityCategory.INSECURE_DESERIALIZATION.value: "A08:2021-Software and Data Integrity Failures",
    VulnerabilityCategory.PATH_TRAVERSAL.value: "A01:2021-Broken Access Control",
    VulnerabilityCategory.CONFIGURATION.value: "A05:2021-Security Misconfiguration",
}

def map_finding_category(rule_id: str, cwe: Optional[str] = None, title: str = "") -> str:
    """
    Centralized mapping of findings to a controlled vulnerability category.
    """
    if rule_id in RULE_CATEGORY_MAP:
        return RULE_CATEGORY_MAP[rule_id]

    if cwe and cwe.upper() in CWE_CATEGORY_MAP:
        return CWE_CATEGORY_MAP[cwe.upper()]

    title_lower = title.lower()
    if "eval" in title_lower or "exec" in title_lower or "dynamic code" in title_lower:
        return VulnerabilityCategory.CODE_INJECTION.value
    if "command" in title_lower or "subprocess" in title_lower or "shell" in title_lower:
        return VulnerabilityCategory.COMMAND_INJECTION.value
    if "password" in title_lower or "secret" in title_lower or "credential" in title_lower or "token" in title_lower:
        return VulnerabilityCategory.HARDCODED_SECRET.value
    if "random" in title_lower:
        return VulnerabilityCategory.INSECURE_RANDOMNESS.value
    if "hash" in title_lower or "crypto" in title_lower or "md5" in title_lower or "sha1" in title_lower:
        return VulnerabilityCategory.WEAK_CRYPTOGRAPHY.value
    if "deserialize" in title_lower or "pickle" in title_lower:
        return VulnerabilityCategory.INSECURE_DESERIALIZATION.value
    if "path" in title_lower or "traversal" in title_lower:
        return VulnerabilityCategory.PATH_TRAVERSAL.value

    return VulnerabilityCategory.OTHER.value

def map_rule_to_cwe(rule_id: str, category: str, cwe_provided: Optional[str] = None) -> Optional[str]:
    """
    Map rule ID or category to standardized CWE identifier.
    Returns None if unmapped.
    """
    if cwe_provided and cwe_provided.startswith("CWE-"):
        return cwe_provided

    if rule_id in RULE_CWE_MAP:
        return RULE_CWE_MAP[rule_id]

    # Category fallbacks
    category_cwe_defaults = {
        VulnerabilityCategory.CODE_INJECTION.value: "CWE-95",
        VulnerabilityCategory.COMMAND_INJECTION.value: "CWE-78",
        VulnerabilityCategory.HARDCODED_SECRET.value: "CWE-798",
        VulnerabilityCategory.INSECURE_RANDOMNESS.value: "CWE-330",
        VulnerabilityCategory.WEAK_CRYPTOGRAPHY.value: "CWE-327",
        VulnerabilityCategory.INSECURE_DESERIALIZATION.value: "CWE-502",
        VulnerabilityCategory.PATH_TRAVERSAL.value: "CWE-22",
    }

    return category_cwe_defaults.get(category, None)

def map_category_to_owasp(category: str) -> Optional[str]:
    """
    Map vulnerability category to OWASP Top 10:2021 classification.
    Returns None if unmapped.
    """
    return CATEGORY_OWASP_MAP.get(category, None)

def normalize_confidence(val: Optional[str]) -> str:
    """
    Normalize static analyzer confidence representation to 'HIGH', 'MEDIUM', or 'LOW'.
    Default fallback is 'MEDIUM'.
    """
    if not val:
        return "MEDIUM"

    val_upper = val.upper().strip()
    if val_upper in ["HIGH", "CERTAIN", "HIGH_CONFIDENCE"]:
        return "HIGH"
    if val_upper in ["LOW", "EXPERIMENTAL", "LOW_CONFIDENCE"]:
        return "LOW"
    if val_upper in ["MEDIUM", "CONFIRMED", "MEDIUM_CONFIDENCE"]:
        return "MEDIUM"

    return "MEDIUM"

def generate_fingerprint(
    category: str,
    cwe: Optional[str],
    source_file: Optional[str],
    line_start: int,
    line_end: int,
    rule_id: str,
) -> str:
    """
    Generate a deterministic SHA-256 fingerprint string representing the physical vulnerability instance.
    Independent of timestamps, UUIDs, or transient runtime metadata.
    """
    safe_file = (source_file or "input.py").replace("\\", "/").split("/")[-1]
    safe_cwe = (cwe or "NONE").upper()
    safe_cat = (category or "OTHER").upper()
    safe_rule = (rule_id or "UNKNOWN").upper()

    raw_key = f"{safe_cat}:{safe_cwe}:{safe_file}:{line_start}:{line_end}:{safe_rule}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

def extract_source_context(
    source_code: str,
    line_start: int,
    line_end: int,
    context_lines: int = 2,
) -> Dict[str, Optional[str]]:
    """
    Extract plain text code context before, at, and after the target line range.
    Does NOT execute source code. Returns plain text snippets.
    """
    if not source_code:
        return {"context_before": None, "vulnerable_code": None, "context_after": None}

    lines = source_code.splitlines()
    total_lines = len(lines)

    if line_start < 1 or line_start > total_lines:
        return {"context_before": None, "vulnerable_code": None, "context_after": None}

    # 1-indexed to 0-indexed adjustment
    start_idx = line_start - 1
    end_idx = min(total_lines, line_end)

    before_start = max(0, start_idx - context_lines)
    before_lines = lines[before_start:start_idx]

    vuln_lines = lines[start_idx:end_idx]

    after_end = min(total_lines, end_idx + context_lines)
    after_lines = lines[end_idx:after_end]

    return {
        "context_before": "\n".join(before_lines) if before_lines else None,
        "vulnerable_code": "\n".join(vuln_lines) if vuln_lines else None,
        "context_after": "\n".join(after_lines) if after_lines else None,
    }
