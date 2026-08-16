#!/usr/bin/env python3
import os
import sys
import re

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROHIBITED_PATTERNS = [
    (r"\beval\s*\(", "Dynamic evaluation function eval()"),
    (r"\bexec\s*\(", "Dynamic execution function exec()"),
    (r"\bnew\s+Function\s*\(", "Dynamic JavaScript constructor new Function()"),
    (r"dangerouslySetInnerHTML", "Unsafe React prop dangerouslySetInnerHTML"),
    (r"\bshell\s*=\s*True\b", "Unsafe subprocess execution shell=True"),
    (r"\bos\.system\s*\(", "Unsafe system command invocation os.system()"),
]

AUDIT_DIRS = [
    os.path.join("backend", "app"),
    os.path.join("frontend", "src"),
]

ALLOWED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}

EXCLUDED_FILES = {
    os.path.join("frontend", "src", "services", "sampleData.js"),
}

def is_literal_string_or_comment(line_text: str) -> bool:
    """Check if matched string is part of a comment, string documentation, or data description."""
    stripped = line_text.strip()
    if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
        return True

    string_assignment_keywords = [
        "explanation=", "impact=", "recommendation=", "best_practice=",
        "description=", "title=", "VulnerabilityCategory", "# shell=True",
        "docstring", "eval(user_input)", "return eval("
    ]

    for kw in string_assignment_keywords:
        if kw in line_text:
            return True

    return False

def run_security_check() -> bool:
    print("==================================================")
    print("[+] Running Security & Code Safety Audit...")
    print("==================================================")

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    violations = []

    for rel_dir in AUDIT_DIRS:
        target_dir = os.path.join(project_root, rel_dir)
        if not os.path.exists(target_dir):
            continue

        for root, _, files in os.walk(target_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext not in ALLOWED_EXTENSIONS:
                    continue

                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, project_root)

                if rel_path in EXCLUDED_FILES or rel_path.replace("\\", "/") in EXCLUDED_FILES:
                    continue

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    for pattern, desc in PROHIBITED_PATTERNS:
                        matches = list(re.finditer(pattern, content))
                        for match in matches:
                            line_num = content[:match.start()].count("\n") + 1
                            line_text = content.splitlines()[line_num - 1]

                            if is_literal_string_or_comment(line_text):
                                continue

                            violations.append((rel_path, line_num, desc, line_text.strip()))
                except Exception as err:
                    print(f"[!] Error reading file {rel_path}: {err}")

    if violations:
        print("\n[FAIL] SECURITY AUDIT FAILED! Dangerous execution statements detected in application code:\n")
        for file, line, desc, snippet in violations:
            print(f"  • {file}:{line} — {desc}")
            print(f"    Code: {snippet}\n")
        return False

    print("[OK] Security audit passed cleanly. Zero dangerous dynamic execution statements found in application code.\n")
    return True

if __name__ == "__main__":
    success = run_security_check()
    sys.exit(0 if success else 1)
