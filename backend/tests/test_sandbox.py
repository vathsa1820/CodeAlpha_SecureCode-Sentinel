import os
import pytest
from app.config import (
    ANALYZER_MODE,
    DOCKER_ANALYZER_IMAGE,
    DOCKER_MEMORY_LIMIT,
    DOCKER_CPU_LIMIT,
    DOCKER_PIDS_LIMIT,
    DOCKER_TIMEOUT_SECONDS,
    DOCKER_TMPFS_SIZE,
    DOCKER_USER,
)
from app.analyzers.execution import get_analyzer_runner
from app.analyzers.execution.local_runner import LocalAnalyzerRunner
from app.analyzers.execution.docker_runner import DockerAnalyzerRunner, build_docker_cmd
from app.analyzers.analyzer_service import analyze_python_code

def test_docker_config_loaded():
    """Verify Docker configuration variables are initialized properly."""
    assert ANALYZER_MODE in ["local", "docker"]
    assert DOCKER_ANALYZER_IMAGE is not None
    assert DOCKER_MEMORY_LIMIT == "512m"
    assert DOCKER_CPU_LIMIT == "1.0"
    assert DOCKER_PIDS_LIMIT == 64
    assert DOCKER_TIMEOUT_SECONDS == 30
    assert DOCKER_TMPFS_SIZE == "64m"
    assert DOCKER_USER == "10001:10001"

def test_local_mode_default_and_functional():
    """Verify local mode runner selection and static analysis execution."""
    runner = get_analyzer_runner("local")
    assert isinstance(runner, LocalAnalyzerRunner)
    assert runner.execution_mode == "local"

    code = "import eval\neval('1+1')"
    findings, ok, err = runner.run_bandit(code, "test.py")
    assert ok is True
    assert len(findings) > 0

def test_docker_runner_selection():
    """Verify get_analyzer_runner selects DockerAnalyzerRunner when mode='docker'."""
    runner = get_analyzer_runner("docker")
    assert isinstance(runner, DockerAnalyzerRunner)
    assert runner.execution_mode == "docker"

def test_docker_command_security_flags():
    """Verify Docker CLI argument array construction contains all security hardening flags."""
    dummy_host_file = "C:\\tmp\\sentinel_test\\source.py"
    cmd = build_docker_cmd("bandit", dummy_host_file)

    # 1. shell=False: Returns Python list of string arguments
    assert isinstance(cmd, list)
    assert cmd[0] == "docker"
    assert cmd[1] == "run"

    # 2. Hardened Security Flags
    assert "--rm" in cmd
    assert "--network=none" in cmd
    assert "--read-only" in cmd
    assert f"--user={DOCKER_USER}" in cmd
    assert f"--tmpfs=/tmp:rw,noexec,nosuid,size={DOCKER_TMPFS_SIZE}" in cmd

    # 3. Resource Limits
    assert f"--cpus={DOCKER_CPU_LIMIT}" in cmd
    assert f"--memory={DOCKER_MEMORY_LIMIT}" in cmd
    assert f"--pids-limit={DOCKER_PIDS_LIMIT}" in cmd

    # 4. Target Image
    assert DOCKER_ANALYZER_IMAGE in cmd

    # 5. Command arguments (Bandit json mode)
    assert "bandit" in cmd
    assert "-f" in cmd
    assert "json" in cmd
    assert "/tmp/source.py" in cmd

def test_user_filename_isolation():
    """
    Verify malicious user-controlled filenames (e.g. traversal paths) are NOT passed
    as Docker CLI volume flags or container arguments.
    """
    malicious_filename = "../../../etc/shadow.py"
    dummy_host_file = "C:\\tmp\\sentinel_test\\source.py"

    cmd = build_docker_cmd("bandit", dummy_host_file)

    # Verify user filename is strictly excluded from Docker arguments
    for arg in cmd:
        assert malicious_filename not in arg
        assert "shadow" not in arg
        assert "etc" not in arg

    # Verify volume mount strictly maps host tempfile to /tmp/source.py
    v_index = cmd.index("-v")
    mount_spec = cmd[v_index + 1]
    assert mount_spec.endswith(":/tmp/source.py:ro")

def test_host_isolation():
    """
    Verify Docker container invocation mounts ONLY the specific source file read-only
    and does NOT mount project root, user home, or host filesystem.
    """
    dummy_host_file = "C:\\tmp\\sentinel_test\\source.py"
    cmd = build_docker_cmd("bandit", dummy_host_file)

    v_flags = [cmd[i+1] for i, x in enumerate(cmd) if x == "-v"]
    assert len(v_flags) == 1
    assert v_flags[0] == f"{dummy_host_file}:/tmp/source.py:ro"

def test_docker_unavailable_handled_safely():
    """Verify when Docker engine is missing or unavailable, runner returns safe failure status."""
    runner = DockerAnalyzerRunner()
    # Execute with dummy code
    findings, ok, err = runner.run_bandit("x = 1", "test.py")

    # Should safely return ok=False or findings list without raising unhandled exception
    assert isinstance(findings, list)
    assert isinstance(ok, bool)
    assert isinstance(err, str)

def test_source_non_execution_regression_both_modes():
    """
    NON-EXECUTION REGRESSION TEST (BOTH MODES):
    Verify source code containing execution commands does NOT execute in local or docker runner mode.
    """
    marker_local = "sentinel_local_regression_marker.tmp"
    if os.path.exists(marker_local):
        os.remove(marker_local)

    code = f"""
import os
with open("{marker_local}", "w") as f:
    f.write("EXECUTED")
"""

    # 1. Test in Local Mode
    res_local = analyze_python_code(code, "marker.py", runner_mode="local")
    assert res_local.status == "completed"
    assert not os.path.exists(marker_local), "SECURITY FAILURE: Source executed in local mode!"

    # 2. Test in Docker Mode
    marker_docker = "sentinel_docker_regression_marker.tmp"
    if os.path.exists(marker_docker):
        os.remove(marker_docker)

    code_docker = f"""
import os
with open("{marker_docker}", "w") as f:
    f.write("EXECUTED")
"""
    res_docker = analyze_python_code(code_docker, "marker.py", runner_mode="docker")
    assert res_docker.status == "completed"
    assert not os.path.exists(marker_docker), "SECURITY FAILURE: Source executed in docker mode!"
