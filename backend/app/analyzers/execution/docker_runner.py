import os
import json
import shutil
import tempfile
import logging
import subprocess
from typing import List, Tuple
from app.config import (
    DOCKER_ANALYZER_IMAGE,
    DOCKER_MEMORY_LIMIT,
    DOCKER_CPU_LIMIT,
    DOCKER_PIDS_LIMIT,
    DOCKER_TIMEOUT_SECONDS,
    DOCKER_TMPFS_SIZE,
    DOCKER_USER,
)
from app.models.findings import Finding
from app.analyzers.execution.base import BaseAnalyzerRunner
from app.analyzers.normalizer import normalize_bandit_finding, normalize_semgrep_finding

logger = logging.getLogger(__name__)

def build_docker_cmd(analyzer_type: str, temp_host_file_path: str) -> List[str]:
    """
    Safely construct Docker CLI invocation argument array (shell=False).

    HARDENED CONTAINER ISOLATION FLAGS:
    - --rm: Automatically remove container on completion
    - --network=none: Zero network connectivity
    - --read-only: Read-only root filesystem
    - --user 10001:10001: Non-root execution
    - --tmpfs /tmp:rw,noexec,nosuid,size=64m: Restricted writable temporary storage
    - --cpus, --memory, --pids-limit: Strict resource consumption bounds
    - -v {temp_host_file_path}:/tmp/source.py:ro: Mounts only the target code read-only
    """
    base_docker_flags = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        f"--user={DOCKER_USER}",
        f"--tmpfs=/tmp:rw,noexec,nosuid,size={DOCKER_TMPFS_SIZE}",
        f"--cpus={DOCKER_CPU_LIMIT}",
        f"--memory={DOCKER_MEMORY_LIMIT}",
        f"--pids-limit={DOCKER_PIDS_LIMIT}",
        "-v",
        f"{temp_host_file_path}:/tmp/source.py:ro",
        DOCKER_ANALYZER_IMAGE,
    ]

    if analyzer_type == "bandit":
        return base_docker_flags + ["bandit", "-f", "json", "-r", "/tmp/source.py"]
    elif analyzer_type == "semgrep":
        return base_docker_flags + [
            "semgrep",
            "scan",
            "--config",
            "/rules/python-security.yml",
            "/tmp/source.py",
            "--json",
            "--quiet",
            "--no-git-ignore",
        ]
    else:
        raise ValueError(f"Unknown analyzer type for Docker runner: {analyzer_type}")

class DockerAnalyzerRunner(BaseAnalyzerRunner):
    """
    Containerized Docker execution runner providing isolated static analysis.
    """

    @property
    def execution_mode(self) -> str:
        return "docker"

    def run_bandit(self, code: str, filename: str = "input.py") -> Tuple[List[Finding], bool, str]:
        findings: List[Finding] = []
        if not code or not code.strip():
            return findings, True, ""

        temp_dir = tempfile.mkdtemp(prefix="sentinel_docker_bandit_")
        temp_file_path = os.path.join(temp_dir, "source.py")

        try:
            with open(temp_file_path, "w", encoding="utf-8") as f:
                f.write(code)

            cmd = build_docker_cmd("bandit", temp_file_path)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=DOCKER_TIMEOUT_SECONDS,
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    results_list = data.get("results", [])
                    for idx, item in enumerate(results_list):
                        finding = normalize_bandit_finding(item, filename, idx + 1, code)
                        findings.append(finding)
                except json.JSONDecodeError as err:
                    logger.warning(f"Failed to parse Docker Bandit JSON output: {err}")

            return findings, True, ""

        except subprocess.TimeoutExpired:
            logger.error(f"Docker Bandit execution timed out after {DOCKER_TIMEOUT_SECONDS}s.")
            return [], False, f"Isolated Bandit analyzer execution timed out after {DOCKER_TIMEOUT_SECONDS}s."
        except FileNotFoundError:
            logger.error("Docker executable not found on host system.")
            return [], False, "Docker container engine is not installed or available on host."
        except Exception as err:
            logger.error(f"Docker Bandit execution failed: {err}")
            return [], False, "Isolated analyzer execution failed."
        finally:
            if os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception as cleanup_err:
                    logger.warning(f"Failed to clean up Docker temp dir {temp_dir}: {cleanup_err}")

    def run_semgrep(self, code: str, filename: str = "input.py") -> Tuple[List[Finding], bool, str]:
        findings: List[Finding] = []
        if not code or not code.strip():
            return findings, True, ""

        temp_dir = tempfile.mkdtemp(prefix="sentinel_docker_semgrep_")
        temp_file_path = os.path.join(temp_dir, "source.py")

        try:
            with open(temp_file_path, "w", encoding="utf-8") as f:
                f.write(code)

            cmd = build_docker_cmd("semgrep", temp_file_path)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=DOCKER_TIMEOUT_SECONDS,
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    results_list = data.get("results", [])
                    for idx, item in enumerate(results_list):
                        finding = normalize_semgrep_finding(item, filename, idx + 1, code)
                        findings.append(finding)
                except json.JSONDecodeError as err:
                    logger.warning(f"Failed to parse Docker Semgrep JSON output: {err}")

            return findings, True, ""

        except subprocess.TimeoutExpired:
            logger.error(f"Docker Semgrep execution timed out after {DOCKER_TIMEOUT_SECONDS}s.")
            return [], False, f"Isolated Semgrep analyzer execution timed out after {DOCKER_TIMEOUT_SECONDS}s."
        except FileNotFoundError:
            logger.error("Docker executable not found on host system.")
            return [], False, "Docker container engine is not installed or available on host."
        except Exception as err:
            logger.error(f"Docker Semgrep execution failed: {err}")
            return [], False, "Isolated analyzer execution failed."
        finally:
            if os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception as cleanup_err:
                    logger.warning(f"Failed to clean up Docker temp dir {temp_dir}: {cleanup_err}")
