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
from app.analyzers.normalizer import normalize_bandit_finding

logger = logging.getLogger(__name__)

def build_bandit_cmd(temp_file_path: str) -> List[str]:
    """
    Safely construct command argument array for Bandit execution (shell=False).
    Checks PATH, Python Scripts directory, and python -m fallback.
    """
    args = ["-f", "json", "-r", temp_file_path]
    found = shutil.which("bandit")
    if found:
        return [found] + args

    scripts_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
    for ext in [".exe", ".cmd", ".bat", ""]:
        candidate = os.path.join(scripts_dir, f"bandit{ext}")
        if os.path.exists(candidate):
            return [candidate] + args

    # Fallback to module invocation via active python interpreter
    return [sys.executable, "-m", "bandit"] + args

def run_bandit_analysis(code: str, filename: str = "input.py") -> List[Finding]:
    """
    Perform static security analysis using Bandit.

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

    safe_basename = os.path.basename(filename) or "target.py"

    temp_dir = tempfile.mkdtemp(prefix="sentinel_bandit_")
    temp_file_path = os.path.join(temp_dir, safe_basename)

    try:
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write(code)

        cmd = build_bandit_cmd(temp_file_path)

        env = os.environ.copy()
        scripts_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
        if os.path.exists(scripts_dir):
            env["PATH"] = scripts_dir + os.pathsep + env.get("PATH", "")

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
                    finding = normalize_bandit_finding(item, filename, idx + 1, code)
                    findings.append(finding)
            except json.JSONDecodeError as err:
                logger.warning(f"Failed to parse Bandit JSON output: {err}")

    except subprocess.TimeoutExpired:
        logger.error(f"Bandit static analysis timed out after {ANALYZER_TIMEOUT_SECONDS} seconds.")
        raise RuntimeError(f"Bandit static analysis execution timed out after {ANALYZER_TIMEOUT_SECONDS}s.")
    except Exception as e:
        logger.error(f"Error during Bandit static analysis execution: {e}")
        raise
    finally:
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as cleanup_err:
                logger.warning(f"Failed to clean up temporary directory {temp_dir}: {cleanup_err}")

    return findings
