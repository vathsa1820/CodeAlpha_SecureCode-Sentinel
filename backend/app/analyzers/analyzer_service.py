import logging
from typing import Optional, List
from app.models.findings import AnalysisResult, Finding, SecurityAssessment, ScanMetadata, AnalyzerStatus
from app.analyzers.execution import get_analyzer_runner
from app.analyzers.normalizer import calculate_summary
from app.analyzers.correlator import correlate_findings
from app.remediation.remediation_service import get_remediation_for_finding
from app.scoring.scoring_engine import (
    calculate_security_score,
    determine_risk_level,
    generate_risk_breakdown,
    generate_score_explanation,
)

logger = logging.getLogger(__name__)

# Maximum allowed source code size (500 KB)
MAX_CODE_SIZE_BYTES = 500 * 1024

def analyze_python_code(
    code: str,
    filename: Optional[str] = "input.py",
    runner_mode: Optional[str] = None
) -> AnalysisResult:
    """
    Main orchestration service for static analysis of Python source code.

    SECURITY GUARANTEE:
    Source code is treated strictly as text. It is NEVER imported, executed,
    compiled, or dynamically evaluated.
    """
    if not code or not code.strip():
        raise ValueError("Source code cannot be empty.")

    if len(code.encode("utf-8")) > MAX_CODE_SIZE_BYTES:
        raise ValueError(f"Source code exceeds maximum allowed limit of {MAX_CODE_SIZE_BYTES // 1024} KB.")

    safe_filename = filename or "input.py"
    safe_filename = safe_filename.replace("\\", "/").split("/")[-1]
    if not safe_filename:
        safe_filename = "input.py"

    # Instantiate configured analyzer runner (Local host vs Isolated Docker container)
    runner = get_analyzer_runner(mode=runner_mode)
    exec_mode = runner.execution_mode

    raw_findings: List[Finding] = []
    analyzers_requested = ["bandit", "semgrep"]
    analyzers_completed: List[str] = []
    analyzer_status_list: List[AnalyzerStatus] = []

    # 1. Execute Bandit Static Analyzer via Runner
    bandit_findings, bandit_ok, bandit_err = runner.run_bandit(code, safe_filename)
    if bandit_ok:
        raw_findings.extend(bandit_findings)
        analyzers_completed.append("bandit")
        analyzer_status_list.append(AnalyzerStatus(name="bandit", status="completed", execution_mode=exec_mode, error=None))
    else:
        logger.error(f"Bandit analyzer execution failed ({exec_mode} mode): {bandit_err}")
        analyzer_status_list.append(AnalyzerStatus(name="bandit", status="failed", execution_mode=exec_mode, error=bandit_err))

    # 2. Execute Semgrep Static Analyzer via Runner
    semgrep_findings, semgrep_ok, semgrep_err = runner.run_semgrep(code, safe_filename)
    if semgrep_ok:
        raw_findings.extend(semgrep_findings)
        analyzers_completed.append("semgrep")
        analyzer_status_list.append(AnalyzerStatus(name="semgrep", status="completed", execution_mode=exec_mode, error=None))
    else:
        logger.error(f"Semgrep analyzer execution failed ({exec_mode} mode): {semgrep_err}")
        analyzer_status_list.append(AnalyzerStatus(name="semgrep", status="failed", execution_mode=exec_mode, error=semgrep_err))

    # 3. Correlate and deduplicate findings
    logical_findings, enhanced_raw_findings = correlate_findings(raw_findings)

    # 4. Attach remediation guidance to logical findings
    for finding in logical_findings:
        finding.remediation = get_remediation_for_finding(finding)

    # 5. Compute security assessment and risk metrics based on logical findings
    score = calculate_security_score(logical_findings)
    risk_level = determine_risk_level(score, logical_findings)
    risk_breakdown = generate_risk_breakdown(logical_findings)
    score_explanation = generate_score_explanation(logical_findings, len(raw_findings))

    highest_severity: Optional[str] = None
    if logical_findings:
        highest_severity = max(
            logical_findings,
            key=lambda x: (
                10 if (x.severity or "").upper() == "CRITICAL" else
                7 if (x.severity or "").upper() == "HIGH" else
                4 if (x.severity or "").upper() == "MEDIUM" else
                1 if (x.severity or "").upper() == "LOW" else 0
            )
        ).severity

    security_assessment = SecurityAssessment(
        score=score,
        risk_level=risk_level,
        logical_vulnerabilities=len(logical_findings),
        raw_detections=len(raw_findings),
        highest_severity=highest_severity,
        risk_breakdown=risk_breakdown,
        score_explanation=score_explanation,
    )

    # Summary counts based on logical findings
    summary = calculate_summary(logical_findings)

    scan_metadata = ScanMetadata(
        language="python",
        filename=safe_filename,
        analyzers_requested=analyzers_requested,
        analyzers_completed=analyzers_completed,
        finding_count=len(logical_findings),
        analyzer_status=analyzer_status_list,
    )

    return AnalysisResult(
        status="completed",
        language="python",
        findings=logical_findings,
        summary=summary,
        security=security_assessment,
        analyzers=analyzers_completed,
        scan=scan_metadata,
    )
