import os
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# Helper paths to test samples
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VULNERABLE_SAMPLE_PATH = os.path.join(PROJECT_ROOT, "samples", "vulnerable", "vulnerable_sample.py")
SECURE_SAMPLE_PATH = os.path.join(PROJECT_ROOT, "samples", "secure", "secure_sample.py")

def test_empty_code_rejected():
    """
    Verify empty code payload returns HTTP 400 or 422 response.
    """
    response = client.post("/api/analyze", json={"code": "   ", "filename": "test.py"})
    assert response.status_code in [400, 422]
    assert "empty" in response.json()["detail"].lower()

def test_valid_simple_code_analysis():
    """
    Verify valid simple Python code analyzes successfully without error.
    """
    payload = {"code": "def hello():\n    print('Hello World')\n", "filename": "hello.py"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["language"] == "python"
    assert "findings" in data
    assert "summary" in data
    assert "security" in data
    assert data["security"]["score"] == 100
    assert data["security"]["risk_level"] == "MINIMAL"

def test_vulnerable_source_analysis():
    """
    Verify vulnerable Python sample produces detected findings from Bandit/Semgrep with remediation.
    """
    with open(VULNERABLE_SAMPLE_PATH, "r", encoding="utf-8") as f:
        vulnerable_code = f.read()

    response = client.post("/api/analyze", json={"code": vulnerable_code, "filename": "vulnerable_sample.py"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"

    findings = data["findings"]
    assert len(findings) > 0, "Vulnerable code sample should produce static analysis findings."

    # Verify finding structure and remediation mapping
    first_finding = findings[0]
    required_keys = [
        "id", "analyzer", "rule_id", "title", "description",
        "severity", "confidence", "category", "line_start", "line_end"
    ]
    for key in required_keys:
        assert key in first_finding, f"Finding missing required field: {key}"

    assert first_finding["remediation"] is not None
    assert "title" in first_finding["remediation"]

def test_secure_source_high_score_vs_vulnerable_low_score():
    """
    Verify secure Python sample receives high score while vulnerable sample receives lower score.
    """
    with open(VULNERABLE_SAMPLE_PATH, "r", encoding="utf-8") as f:
        vuln_code = f.read()

    with open(SECURE_SAMPLE_PATH, "r", encoding="utf-8") as f:
        sec_code = f.read()

    vuln_resp = client.post("/api/analyze", json={"code": vuln_code, "filename": "vuln.py"})
    sec_resp = client.post("/api/analyze", json={"code": sec_code, "filename": "sec.py"})

    vuln_data = vuln_resp.json()
    sec_data = sec_resp.json()

    sec_score = sec_data["security"]["score"]
    vuln_score = vuln_data["security"]["score"]

    assert sec_score >= 90, f"Secure sample should receive high security score (got {sec_score})"
    assert vuln_score < sec_score, f"Vulnerable score ({vuln_score}) should be lower than secure score ({sec_score})"
    assert vuln_data["security"]["risk_level"] in ["HIGH", "CRITICAL", "MEDIUM"]

def test_summary_counts_match_findings():
    """
    Verify summary total and severity counts strictly match the list of findings.
    """
    with open(VULNERABLE_SAMPLE_PATH, "r", encoding="utf-8") as f:
        code = f.read()

    response = client.post("/api/analyze", json={"code": code, "filename": "test.py"})
    data = response.json()
    summary = data["summary"]
    findings = data["findings"]

    assert summary["total"] == len(findings)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] += 1

    assert summary["critical"] == counts["CRITICAL"]
    assert summary["high"] == counts["HIGH"]
    assert summary["medium"] == counts["MEDIUM"]
    assert summary["low"] == counts["LOW"]
    assert summary["info"] == counts["INFO"]

def test_non_execution_guarantee():
    """
    CRITICAL SECURITY TEST:
    Verify submitted source code containing execution commands (e.g. creating a file)
    is NEVER executed by the analysis engine.
    """
    canary_file = os.path.join(PROJECT_ROOT, "backend", "tests", "MUST_NEVER_EXIST_CANARY.txt")
    if os.path.exists(canary_file):
        os.remove(canary_file)

    # Malicious payload that would create a canary file if executed or imported
    canary_path_str = canary_file.replace('\\', '/')
    malicious_code = f"""
import os
os.system("echo EXECUTED > {canary_path_str}")
eval("os.system('echo EXECUTED')")
"""

    response = client.post("/api/analyze", json={"code": malicious_code, "filename": "malicious.py"})
    assert response.status_code == 200

    # Assert that the canary file was NEVER created
    assert not os.path.exists(canary_file), "SECURITY FAILURE: Submitted source code was executed!"
