import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from app.main import app
from app.models.findings import AnalysisResult
from app.models.report import SecurityReport
from app.reports.report_generator import generate_security_report, generate_report_id
from app.reports import history_service, report_service
from app.analyzers.analyzer_service import analyze_python_code

client = TestClient(app)

@pytest.fixture(autouse=True)
def clear_history_fixture():
    """Clear report history store before and after each test."""
    history_service.clear_reports()
    yield
    history_service.clear_reports()

def test_report_id_generation():
    """Verify report ID format follows SCR-2026-XXXXXX."""
    rid = generate_report_id()
    assert rid.startswith("SCR-")
    assert len(rid) >= 12

def test_report_generation_from_analysis():
    """Verify generating a report from a valid AnalysisResult object."""
    code = "import eval\neval('1+1')"
    analysis = analyze_python_code(code, "test.py")
    report = generate_security_report(analysis)

    assert isinstance(report, SecurityReport)
    assert report.report_id.startswith("SCR-")
    assert report.security_score == analysis.security.score
    assert report.risk_level == analysis.security.risk_level
    assert report.logical_vulnerabilities == len(analysis.findings)
    assert report.raw_detections == analysis.security.raw_detections

def test_report_timestamp_validity():
    """Verify report generated_at is a valid timezone-aware UTC ISO timestamp."""
    code = "x = 1"
    analysis = analyze_python_code(code, "test.py")
    report = generate_security_report(analysis)

    dt = datetime.fromisoformat(report.generated_at)
    assert dt is not None
    assert dt.tzinfo is not None

def test_zero_finding_report():
    """Verify report metrics when zero vulnerabilities are detected."""
    code = "def safe_add(a, b):\n    return a + b\n"
    analysis = analyze_python_code(code, "secure.py")
    report = generate_security_report(analysis)

    assert report.security_score == 100
    assert report.risk_level == "MINIMAL"
    assert report.logical_vulnerabilities == 0
    assert report.raw_detections == 0
    assert report.severity_breakdown.critical.percentage == 0.0
    assert report.severity_breakdown.high.percentage == 0.0
    assert len(report.remediation_summary.categories) == 0

def test_vulnerable_sample_report():
    """Verify report generation for vulnerable python sample."""
    code = """
import eval
import subprocess
import hashlib
import random

eval(user_input)
subprocess.run(cmd, shell=True)
key = "SECRET_12345"
h = hashlib.md5(b"test").hexdigest()
token = random.randint(1, 100)
"""
    analysis = analyze_python_code(code, "vulnerable_sample.py")
    report = generate_security_report(analysis)

    assert report.executive_summary.target_file == "vulnerable_sample.py"
    assert report.logical_vulnerabilities > 0
    assert report.raw_detections >= report.logical_vulnerabilities
    assert len(report.findings) == report.logical_vulnerabilities
    assert len(report.remediation_summary.categories) > 0

def test_severity_percentage_calculation():
    """Verify percentage calculations for severity breakdown."""
    code = "import eval\neval('1+1')"
    analysis = analyze_python_code(code, "sample.py")
    report = generate_security_report(analysis)

    sb = report.severity_breakdown
    total_pct = (
        sb.critical.percentage +
        sb.high.percentage +
        sb.medium.percentage +
        sb.low.percentage +
        sb.info.percentage
    )
    if report.logical_vulnerabilities > 0:
        assert abs(total_pct - 100.0) < 0.2
    else:
        assert total_pct == 0.0

def test_remediation_summary_only_detected_categories():
    """Verify remediation summary only contains categories of actual findings."""
    code = "import eval\neval('1+1')"
    analysis = analyze_python_code(code, "eval_only.py")
    report = generate_security_report(analysis)

    cat_names = [c.category for c in report.remediation_summary.categories]
    assert "CODE_INJECTION" in cat_names
    assert "PATH_TRAVERSAL" not in cat_names

def test_history_service_create_list_get_delete():
    """Verify in-memory session report store operations."""
    code = "x = 1"
    analysis = analyze_python_code(code, "test.py")
    report = report_service.create_report_from_analysis(analysis)

    assert len(history_service.list_reports()) == 1

    fetched = history_service.get_report_by_id(report.report_id)
    assert fetched is not None
    assert fetched.report_id == report.report_id

    deleted = history_service.delete_report(report.report_id)
    assert deleted is True
    assert history_service.get_report_by_id(report.report_id) is None
    assert len(history_service.list_reports()) == 0

def test_reports_api_endpoints():
    """Verify POST /api/reports, GET /api/reports, and GET /api/reports/{id}."""
    code = "import eval\neval('1+1')"
    analysis = analyze_python_code(code, "api_test.py")

    # POST /api/reports
    resp = client.post("/api/reports", json={"analysis": analysis.model_dump()})
    assert resp.status_code == 201
    data = resp.json()
    assert "report_id" in data
    rid = data["report_id"]

    # GET /api/reports
    list_resp = client.get("/api/reports")
    assert list_resp.status_code == 200
    reports = list_resp.json()
    assert len(reports) == 1
    assert reports[0]["report_id"] == rid

    # GET /api/reports/{id}
    get_resp = client.get(f"/api/reports/{rid}")
    assert get_resp.status_code == 200
    assert get_resp.json()["report_id"] == rid

    # GET missing report returns 404
    missing_resp = client.get("/api/reports/SCR-2026-999999")
    assert missing_resp.status_code == 404
