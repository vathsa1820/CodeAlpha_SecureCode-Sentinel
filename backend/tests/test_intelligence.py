import pytest
from app.models.findings import Finding
from app.scoring.scoring_engine import (
    calculate_security_score,
    determine_risk_level,
    generate_risk_breakdown,
    generate_score_explanation,
    SEVERITY_WEIGHTS,
)
from app.analyzers.correlator import correlate_findings
from app.remediation.remediation_service import get_remediation_for_finding
from app.remediation.remediation_kb import REMEDIATION_KB, DEFAULT_REMEDIATION

def make_finding(finding_id: str, severity: str, category: str = "OTHER", line: int = 1, analyzer: str = "bandit", cwe: str = None) -> Finding:
    return Finding(
        id=finding_id,
        analyzer=analyzer,
        rule_id=finding_id,
        title=f"Test Finding {finding_id}",
        description="Test finding description",
        severity=severity,
        category=category,
        cwe=cwe,
        line_start=line,
        line_end=line,
        source_file="test.py",
    )

def test_zero_findings_score_100():
    score = calculate_security_score([])
    risk_level = determine_risk_level(score, [])
    assert score == 100
    assert risk_level == "MINIMAL"

def test_low_finding_score_lower_than_100():
    low_f = [make_finding("f1", "LOW")]
    score = calculate_security_score(low_f)
    assert score < 100
    assert score >= 90

def test_high_finding_lower_than_low():
    low_f = [make_finding("f1", "LOW")]
    high_f = [make_finding("f2", "HIGH")]
    low_score = calculate_security_score(low_f)
    high_score = calculate_security_score(high_f)
    assert high_score < low_score

def test_critical_finding_significantly_lower_score():
    high_f = [make_finding("f1", "HIGH")]
    crit_f = [make_finding("f2", "CRITICAL")]
    high_score = calculate_security_score(high_f)
    crit_score = calculate_security_score(crit_f)
    assert crit_score < high_score
    assert crit_score <= 45

def test_score_bounded_between_0_and_100():
    # Massive amount of critical findings
    crit_list = [make_finding(f"f_{i}", "CRITICAL", line=i) for i in range(50)]
    score = calculate_security_score(crit_list)
    assert 0 <= score <= 100

def test_risk_level_thresholds():
    assert determine_risk_level(95, []) == "MINIMAL"
    assert determine_risk_level(80, [make_finding("f1", "LOW")]) == "LOW"
    assert determine_risk_level(65, [make_finding("f1", "MEDIUM")]) == "MEDIUM"
    assert determine_risk_level(40, [make_finding("f1", "HIGH")]) == "HIGH"
    assert determine_risk_level(20, [make_finding("f1", "CRITICAL")]) == "CRITICAL"

def test_finding_correlation():
    # Bandit and Semgrep detect same issue at line 10
    f_bandit = make_finding("B307", "HIGH", category="CODE_INJECTION", line=10, analyzer="bandit", cwe="CWE-95")
    f_semgrep = make_finding("unsafe-eval", "HIGH", category="CODE_INJECTION", line=10, analyzer="semgrep", cwe="CWE-95")

    logical, raw = correlate_findings([f_bandit, f_semgrep])

    assert len(logical) == 1, "Duplicate Bandit and Semgrep findings at line 10 should correlate into 1 logical finding"
    assert set(logical[0].detected_by) == {"bandit", "semgrep"}
    assert logical[0].category == "CODE_INJECTION"

def test_unrelated_findings_remain_separate():
    f1 = make_finding("B307", "HIGH", category="CODE_INJECTION", line=10, analyzer="bandit")
    f2 = make_finding("B602", "HIGH", category="COMMAND_INJECTION", line=25, analyzer="bandit")

    logical, raw = correlate_findings([f1, f2])

    assert len(logical) == 2, "Findings at different lines with different categories should remain separate"

def test_raw_vs_logical_counts():
    f1 = make_finding("B307", "HIGH", category="CODE_INJECTION", line=10, analyzer="bandit")
    f2 = make_finding("unsafe-eval", "HIGH", category="CODE_INJECTION", line=10, analyzer="semgrep")

    logical, raw = correlate_findings([f1, f2])

    assert len(raw) == 2
    assert len(logical) == 1

def test_remediation_guidance_mapping():
    f_eval = make_finding("B307", "HIGH", category="CODE_INJECTION", line=10)
    rem = get_remediation_for_finding(f_eval)
    assert rem.title == "Avoid Dynamic Code Execution"
    assert "ast.literal_eval" in rem.secure_example
    assert rem.cwe is not None

def test_fallback_remediation_for_unknown():
    f_unknown = make_finding("CUSTOM-99", "LOW", category="UNKNOWN_CUSTOM_CAT", line=1)
    rem = get_remediation_for_finding(f_unknown)
    assert rem.title == DEFAULT_REMEDIATION.title
    assert "Review" in rem.recommendation
