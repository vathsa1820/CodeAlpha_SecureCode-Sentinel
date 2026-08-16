import os
import sys
import shutil
import pytest
from unittest.mock import patch, MagicMock
from app.analyzers.bandit_analyzer import resolve_executable as resolve_bandit, build_bandit_cmd
from app.analyzers.semgrep_analyzer import resolve_executable as resolve_semgrep, build_semgrep_cmd

def test_executable_resolution_path_lookup():
    """Verify shutil.which PATH lookup takes highest priority."""
    with patch("shutil.which", return_value="/usr/local/bin/bandit"):
        res = resolve_bandit("bandit")
        assert res == "/usr/local/bin/bandit"

def test_executable_resolution_linux_bin_path(tmp_path):
    """Verify Linux/macOS bin directory resolution when PATH lookup fails."""
    python_dir = str(tmp_path)
    bin_dir = os.path.join(python_dir, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    fake_exe = os.path.join(bin_dir, "semgrep")
    with open(fake_exe, "w") as f:
        f.write("#!/bin/sh\nexit 0")
    os.chmod(fake_exe, 0o755)

    with patch("shutil.which", return_value=None):
        with patch.object(sys, "executable", os.path.join(python_dir, "bin", "python")):
            res = resolve_semgrep("semgrep")
            assert res == fake_exe

def test_executable_resolution_windows_scripts_path(tmp_path):
    """Verify Windows Scripts directory resolution when PATH lookup fails."""
    python_dir = str(tmp_path)
    scripts_dir = os.path.join(python_dir, "Scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    fake_exe = os.path.join(scripts_dir, "bandit.exe")
    with open(fake_exe, "w") as f:
        f.write("binary")

    with patch("shutil.which", return_value=None):
        with patch.object(sys, "executable", os.path.join(python_dir, "python.exe")):
            res = resolve_bandit("bandit")
            assert res == fake_exe

def test_executable_resolution_missing_fallback():
    """Verify None is returned when executable cannot be resolved."""
    with patch("shutil.which", return_value=None):
        with patch("os.path.isfile", return_value=False):
            res = resolve_bandit("nonexistent_tool_123")
            assert res is None

def test_build_bandit_cmd_structure():
    """Verify build_bandit_cmd produces list argument array without shell=True."""
    cmd = build_bandit_cmd("/tmp/test.py")
    assert isinstance(cmd, list)
    assert "-f" in cmd
    assert "json" in cmd
    assert "/tmp/test.py" in cmd

def test_build_semgrep_cmd_structure():
    """Verify build_semgrep_cmd produces list argument array without python -m fallback."""
    cmd = build_semgrep_cmd("/rules/python.yml", "/tmp/test.py")
    assert isinstance(cmd, list)
    assert "scan" in cmd
    assert "--config" in cmd
    assert "--json" in cmd
    assert "/tmp/test.py" in cmd
    assert "python" not in cmd[0] or cmd[0].endswith("semgrep") or cmd[0].endswith("semgrep.exe")

def test_user_filename_isolation_in_cmd():
    """Verify malicious filenames do not affect executable resolution or command array structure."""
    malicious_filename = "; rm -rf / ;"
    cmd = build_bandit_cmd(malicious_filename)
    assert isinstance(cmd, list)
    assert cmd[-1] == malicious_filename
    assert cmd[0] != malicious_filename
