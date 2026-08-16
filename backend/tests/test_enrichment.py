import pytest
from app.models.findings import Finding
from app.analyzers.categories import (
    map_finding_category,
    map_rule_to_cwe,
    map_category_to_owasp,
    normalize_confidence,
    generate_fingerprint,
    extract_source_context,
    OWASP_VERSION,
)
from app.analyzers.normalizer import (
    normalize_bandit_finding,
    normalize_semgrep_finding,
    parse_cwe_string,
)
from app.analyzers.correlator import correlate_findings
from app.analyzers.analyzer_service import analyze_python_code

def test_fingerprint_stability():
    """Verify that fingerprint is deterministic across repeated runs."""
    fp1 = generate_fingerprint("CODE_INJECTION", "CWE-95", "vulnerable.py", 10, 10, "B307")
    fp2 = generate_fingerprint("CODE_INJECTION", "CWE-95", "vulnerable.py", 10, 10, "B307")
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex digest

def test_different_findings_different_fingerprints():
    """Verify different finding attributes produce distinct fingerprints."""
    fp1 = generate_fingerprint("CODE_INJECTION", "CWE-95", "vulnerable.py", 10, 10, "B307")
    fp2 = generate_fingerprint("COMMAND_INJECTION", "CWE-78", "vulnerable.py", 15, 15, "B602")
    assert fp1 != fp2

def test_confidence_normalization():
    """Verify confidence values are normalized strictly to HIGH, MEDIUM, LOW."""
    assert normalize_confidence("HIGH") == "HIGH"
    assert normalize_confidence("certain") == "HIGH"
    assert normalize_confidence("LOW") == "LOW"
    assert normalize_confidence("experimental") == "LOW"
    assert normalize_confidence("MEDIUM") == "MEDIUM"
    assert normalize_confidence("unknown") == "MEDIUM"
    assert normalize_confidence(None) == "MEDIUM"

def test_confidence_independent_from_severity():
    """Verify severity CRITICAL with confidence MEDIUM remains possible."""
    finding = Finding(
        id="test-1",
        analyzer="bandit",
        rule_id="B307",
        title="Eval injection",
        description="Eval test",
        severity="CRITICAL",
        confidence="MEDIUM",
        line_start=5,
        line_end=5,
    )
    assert finding.severity == "CRITICAL"
    assert finding.confidence == "MEDIUM"

def test_cwe_mapping():
    """Verify standardized CWE mappings and null returns for unknown."""
    assert map_rule_to_cwe("B307", "CODE_INJECTION") == "CWE-95"
    assert map_rule_to_cwe("B602", "COMMAND_INJECTION") == "CWE-78"
    assert map_rule_to_cwe("B105", "HARDCODED_SECRET") == "CWE-798"
    assert map_rule_to_cwe("B311", "INSECURE_RANDOMNESS") == "CWE-330"
    assert map_rule_to_cwe("unknown_rule", "OTHER") is None

def test_owasp_mapping():
    """Verify OWASP Top 10:2021 mapping taxonomy."""
    assert map_category_to_owasp("CODE_INJECTION") == "A03:2021-Injection"
    assert map_category_to_owasp("COMMAND_INJECTION") == "A03:2021-Injection"
    assert map_category_to_owasp("HARDCODED_SECRET") == "A07:2021-Identification and Authentication Failures"
    assert map_category_to_owasp("WEAK_CRYPTOGRAPHY") == "A02:2021-Cryptographic Failures"
    assert map_category_to_owasp("PATH_TRAVERSAL") == "A01:2021-Broken Access Control"
    assert map_category_to_owasp("OTHER") is None
    assert OWASP_VERSION == "OWASP Top 10:2021"

def test_evidence_structure():
    """Verify evidence object structure."""
    item = {
        "test_id": "B307",
        "line_number": 12,
        "issue_severity": "HIGH",
        "issue_confidence": "HIGH",
        "code": "eval(user_input)",
    }
    finding = normalize_bandit_finding(item, "test.py", 1, "eval(user_input)")
    assert finding.evidence is not None
    assert finding.evidence["source"] == "eval(user_input)"
    assert finding.evidence["line_start"] == 12
    assert finding.evidence["matched_rule"] == "B307"
    assert finding.evidence["analyzers"] == ["bandit"]

def test_source_context_extraction():
    """Verify context_before, vulnerable_code, and context_after line slicing."""
    code = "line1 = 1\nline2 = 2\neval(user_input)\nline4 = 4\nline5 = 5"
    ctx = extract_source_context(code, line_start=3, line_end=3, context_lines=2)
    assert ctx["context_before"] == "line1 = 1\nline2 = 2"
    assert ctx["vulnerable_code"] == "eval(user_input)"
    assert ctx["context_after"] == "line4 = 4\nline5 = 5"

def test_scan_metadata_accuracy():
    """Verify ScanMetadata structure in analyze_python_code result."""
    code = "import eval\neval('1+1')"
    res = analyze_python_code(code, "test_file.py")
    assert res.scan is not None
    assert res.scan.filename == "test_file.py"
    assert res.scan.language == "python"
    assert "bandit" in res.scan.analyzers_requested
    assert "semgrep" in res.scan.analyzers_requested
    assert len(res.scan.analyzer_status) >= 2
    for status in res.scan.analyzer_status:
        assert status.status in ["completed", "failed"]

def test_correlated_analyzer_evidence():
    """Verify that multi-analyzer detections preserve individual engine evidence."""
    b_finding = Finding(
        id="bandit-1",
        analyzer="bandit",
        rule_id="B307",
        title="Eval injection",
        description="Bandit eval",
        severity="HIGH",
        confidence="HIGH",
        category="CODE_INJECTION",
        line_start=10,
        line_end=10,
        source_file="vulnerable.py",
        analyzer_evidence=[{"analyzer": "bandit", "rule_id": "B307", "confidence": "HIGH"}]
    )

    s_finding = Finding(
        id="semgrep-1",
        analyzer="semgrep",
        rule_id="unsafe-eval-exec",
        title="Semgrep eval",
        description="Semgrep eval",
        severity="HIGH",
        confidence="HIGH",
        category="CODE_INJECTION",
        line_start=10,
        line_end=10,
        source_file="vulnerable.py",
        analyzer_evidence=[{"analyzer": "semgrep", "rule_id": "unsafe-eval-exec", "confidence": "HIGH"}]
    )

    logical, raw = correlate_findings([b_finding, s_finding])
    assert len(logical) == 1
    log_item = logical[0]
    assert "bandit" in log_item.detected_by
    assert "semgrep" in log_item.detected_by
    assert len(log_item.analyzer_evidence) == 2
    tools = [ev["analyzer"] for ev in log_item.analyzer_evidence]
    assert "bandit" in tools
    assert "semgrep" in tools

def test_null_handling_unmapped_metadata():
    """Verify unmapped metadata returns None without raising errors."""
    cwe_val = map_rule_to_cwe("unknown_rule_999", "OTHER")
    owasp_val = map_category_to_owasp("OTHER")
    assert cwe_val is None
    assert owasp_val is None
