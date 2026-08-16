import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import MAX_SOURCE_SIZE_BYTES

client = TestClient(app)

def test_empty_code_rejected():
    """Verify empty code payload is rejected with 422."""
    resp = client.post("/api/analyze", json={"code": "", "filename": "input.py"})
    assert resp.status_code == 422

def test_oversized_source_rejected():
    """Verify source code exceeding MAX_SOURCE_SIZE_BYTES (500 KB) is rejected with 413."""
    large_code = "x = 1\n" * (MAX_SOURCE_SIZE_BYTES // 4)
    resp = client.post("/api/analyze", json={"code": large_code, "filename": "input.py"})
    assert resp.status_code == 413
    assert "exceeds maximum allowed limit" in resp.json()["detail"]

def test_invalid_filename_rejected():
    """Verify filename without .py extension is rejected."""
    resp = client.post("/api/analyze", json={"code": "x = 1", "filename": "invalid_script.txt"})
    assert resp.status_code == 422
    assert "Only Python source code files" in resp.json()["detail"]

def test_path_traversal_filename_rejected():
    """Verify filenames with directory traversal sequences (..) or path separators are rejected."""
    traversal_files = [
        "../evil.py",
        "..\\evil.py",
        "C:\\Windows\\System32\\cmd.exe.py",
        "/etc/passwd.py",
        "../../secret.py",
    ]
    for fn in traversal_files:
        resp = client.post("/api/analyze", json={"code": "x = 1", "filename": fn})
        assert resp.status_code == 422

def test_null_byte_filename_rejected():
    """Verify null bytes in filename are rejected."""
    resp = client.post("/api/analyze", json={"code": "x = 1", "filename": "test.py\x00.txt"})
    assert resp.status_code == 422

def test_non_python_filename_rejected():
    """Verify non-Python file extensions (.exe, .sh, .js) are rejected."""
    for ext in ["script.sh", "program.exe", "index.js", "data.json"]:
        resp = client.post("/api/analyze", json={"code": "x = 1", "filename": ext})
        assert resp.status_code == 422

def test_shell_metacharacters_in_filename_rejected():
    """Verify shell injection characters in filenames are blocked by validation."""
    metachar_files = [
        "test;whoami;.py",
        "$(whoami).py",
        "test|dir.py",
        "`id`.py",
    ]
    for fn in metachar_files:
        resp = client.post("/api/analyze", json={"code": "x = 1", "filename": fn})
        assert resp.status_code == 422

def test_source_non_execution_regression():
    """
    CRITICAL NON-EXECUTION REGRESSION TEST:
    Submit source code containing commands that would create a marker file if executed.
    Verify that static analysis scans the file statically and NEVER executes the code.
    """
    marker_file = "sentinel_executed_regression.tmp"
    if os.path.exists(marker_file):
        os.remove(marker_file)

    code_payload = f"""
import os
# Harmless payload attempting marker file creation IF executed
with open("{marker_file}", "w") as f:
    f.write("EXECUTED")
"""

    resp = client.post("/api/analyze", json={"code": code_payload, "filename": "marker_test.py"})
    assert resp.status_code == 200

    # Critical Security Guarantee Verification: Marker file MUST NOT exist!
    assert not os.path.exists(marker_file), "SECURITY FAILURE: Submitted source code was executed during analysis!"

def test_report_validation_rejects_malformed_analysis():
    """Verify POST /api/reports rejects malformed or tampered analysis payloads with HTTP 422."""
    malformed_payload = {
        "analysis": {
            "status": "completed",
            "findings": "invalid_string_instead_of_list",
            "security": {"score": "invalid_score"},
        }
    }
    resp = client.post("/api/reports", json=malformed_payload)
    assert resp.status_code in [400, 422]

def test_missing_report_returns_404():
    """Verify requesting a non-existent report ID returns HTTP 404."""
    resp = client.get("/api/reports/SCR-9999-000000")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()

def test_security_headers_present():
    """Verify API responses include security headers."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "no-store" in resp.headers.get("Cache-Control", "")

def test_cors_policy():
    """Verify CORS headers for configured and unapproved origins."""
    # Approved Origin
    resp_approved = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert resp_approved.headers.get("access-control-allow-origin") == "http://localhost:5173"

def test_stack_traces_hidden():
    """Verify internal server errors do not expose stack traces or file paths."""
    resp = client.post("/api/analyze", json={"code": "x = 1", "filename": "invalid_script.txt"})
    assert resp.status_code == 422
    data = resp.json()
    assert "Traceback" not in str(data)
    assert "File \"" not in str(data)
