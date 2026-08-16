import os
import sys
import json
import shutil
import tempfile
import logging
import subprocess
from typing import List
from app.config import ANALYZER_TIMEOUT_SECONDS
from app.models.findings import Finding
from app.analyzers.normalizer import normalize_semgrep_finding

logger = logging.getLogger(__name__)

def get_semgrep_rules_path() -> str:
    """
    Return absolute path to custom Semgrep rules file.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "..", "..", ".."))
    rules_path = os.path.join(project_root, "rules", "semgrep", "python-security.yml")
    return rules_path

def resolve_executable(tool_name: str) -> str:
    r"""
    Cross-platform executable path resolver for static analysis tools.

    Priority:
    1. PATH lookup using shutil.which()
    2. Active Python environment executable directory:
       - <python-dir> directly (which is /venv/bin on Linux/macOS or \venv\Scripts on Windows)
       - <python-dir>/bin
       - <python-dir>/Scripts
       - <python-dir>/../bin
    """
    # 1. PATH lookup
    found = shutil.which(tool_name)
    if found:
        return found

    # 2. Check active Python environment executable directory
    python_dir = os.path.dirname(sys.executable)
    search_dirs = [
        python_dir,                                         # Direct bin/Scripts directory of Python interpreter
        os.path.join(python_dir, "bin"),                   # Subfolder bin
        os.path.join(python_dir, "Scripts"),               # Subfolder Scripts (Windows)
        os.path.join(os.path.dirname(python_dir), "bin"),   # Parent bin
    ]
    extensions = [".exe", ".cmd", ".bat", ""] if sys.platform == "win32" else ["", ".exe", ".cmd", ".bat"]

    for s_dir in search_dirs:
        if not os.path.exists(s_dir):
            continue
        for ext in extensions:
            candidate = os.path.join(s_dir, f"{tool_name}{ext}")
            if os.path.isfile(candidate):
                if hasattr(os, "X_OK") and sys.platform != "win32":
                    if candidate.endswith((".exe", ".cmd", ".bat")) or os.access(candidate, os.X_OK):
                        return candidate
                else:
                    return candidate

    return None

def build_semgrep_cmd(rules_path: str, temp_file_path: str) -> List[str]:
    """
    Safely construct command argument array for Semgrep execution (shell=False).
    Resolves executable cross-platform across Windows, Linux, and macOS.
    """
    args = [
        "scan",
        "--config",
        rules_path,
        temp_file_path,
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--metrics=off",
    ]
    exe = resolve_executable("semgrep")
    if exe:
        return [exe] + args

    # Fallback to binary name; subprocess handles PATH lookup or raises FileNotFoundError cleanly
    return ["semgrep"] + args

def run_semgrep_analysis(code: str, filename: str = "input.py") -> List[Finding]:
    """
    Perform static security analysis using Semgrep.

    STRICT SECURITY REQUIREMENTS:
    1. Source code is written strictly as plain text into an isolated temporary directory.
    2. Code is NEVER imported, executed, compiled, or dynamically evaluated.
    3. Filename is sanitized with os.path.basename to prevent filesystem path traversal.
    4. Subprocess execution uses explicit list arguments (shell=False).
    5. Subprocess timeout is enforced strictly via ANALYZER_TIMEOUT_SECONDS.
    6. Temporary files are guaranteed destroyed in a finally block.
    """
    findings: List[Finding] = []
    if not code or not code.strip():
        return findings

    rules_path = get_semgrep_rules_path()
    if not os.path.exists(rules_path):
        logger.warning(f"Semgrep rules file not found at {rules_path}. Skipping Semgrep analysis.")
        return findings

    safe_basename = os.path.basename(filename) or "target.py"

    temp_dir = tempfile.mkdtemp(prefix="sentinel_semgrep_")
    temp_file_path = os.path.join(temp_dir, safe_basename)

    try:
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write(code)

        cmd = build_semgrep_cmd(rules_path, temp_file_path)

        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"
        python_dir = os.path.dirname(sys.executable)
        extra_paths = [
            python_dir,
            os.path.join(python_dir, "bin"),
            os.path.join(python_dir, "Scripts"),
        ]
        valid_paths = [p for p in extra_paths if os.path.exists(p)]
        if valid_paths:
            env["PATH"] = os.pathsep.join(valid_paths) + os.pathsep + env.get("PATH", "")

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=ANALYZER_TIMEOUT_SECONDS,
        )

        if result.stdout:
            try:
                data = json.loads(result.stdout)
                results_list = data.get("results", [])
                for idx, item in enumerate(results_list):
                    finding = normalize_semgrep_finding(item, filename, idx + 1, code)
                    findings.append(finding)
            except json.JSONDecodeError as err:
                logger.warning(f"Failed to parse Semgrep JSON output: {err}")

    except FileNotFoundError as fnf_err:
        logger.warning(f"Semgrep executable not found in PATH or Python environment: {fnf_err}")
        return findings
    except subprocess.TimeoutExpired:
        logger.error(f"Semgrep static analysis timed out after {ANALYZER_TIMEOUT_SECONDS} seconds.")
        raise RuntimeError(f"Semgrep static analysis execution timed out after {ANALYZER_TIMEOUT_SECONDS}s.")
    except Exception as e:
        logger.error(f"Error during Semgrep static analysis execution: {e}")
        raise
    finally:
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as cleanup_err:
                logger.warning(f"Failed to clean up temporary directory {cleanup_err}")

    return findings
