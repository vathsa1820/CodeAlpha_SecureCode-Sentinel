#!/usr/bin/env python3
import os
import sys
import re

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SECRET_PATTERNS = [
    (r"-----BEGIN\s+(RSA|OPENSSH|DSA|EC)\s+PRIVATE\s+KEY-----", "Private Key Header"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
    (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live Secret Key"),
    (r"xox[a-z0-9]-[0-9a-zA-Z]{10,48}", "Slack Token"),
    (r"bearer\s+[a-zA-Z0-9_\-\.]{50,}", "Hardcoded Bearer Token"),
]

EXCLUDE_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".pytest_cache",
    "dist",
    "build",
    "coverage",
}

EXCLUDE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".ico", ".pyc", ".bin", ".tar", ".gz", ".zip", ".lock"
}

def run_secret_scan() -> bool:
    print("==================================================")
    print("[+] Running Automated Secret Scanning Audit...")
    print("==================================================")

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    violations = []

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in EXCLUDE_EXTENSIONS:
                continue

            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, project_root)

            if rel_path in ["scripts/secret_scan.py", ".env.example"]:
                continue

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern, desc in SECRET_PATTERNS:
                    matches = list(re.finditer(pattern, content))
                    for match in matches:
                        line_num = content[:match.start()].count("\n") + 1
                        line_text = content.splitlines()[line_num - 1].strip()
                        violations.append((rel_path, line_num, desc, line_text))
            except Exception as err:
                print(f"[!] Error scanning file {rel_path}: {err}")

    if violations:
        print("\n[FAIL] SECRET SCAN FAILED! Likely committed credentials detected:\n")
        for file, line, desc, snippet in violations:
            print(f"  • {file}:{line} — {desc}")
            print(f"    Snippet: {snippet[:80]}...\n")
        return False

    print("[OK] Secret scan passed cleanly. Zero hardcoded credentials found in repository.\n")
    return True

if __name__ == "__main__":
    success = run_secret_scan()
    sys.exit(0 if success else 1)
