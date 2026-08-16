import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from app.models.findings import AnalysisResult, Finding, ScanMetadata
from app.models.report import (
    SecurityReport,
    ExecutiveSummary,
    SeverityPercentage,
    SeverityBreakdownReport,
    RemediationCategorySummary,
    RemediationSummaryReport,
)

_report_counter = 0

def generate_report_id() -> str:
    """
    Generate a stable, human-readable report identifier (e.g. SCR-2026-000001).
    """
    global _report_counter
    _report_counter += 1
    current_year = datetime.now(timezone.utc).year
    return f"SCR-{current_year}-{_report_counter:06d}"

def generate_security_report(
    analysis: Union[AnalysisResult, Dict[str, Any]],
    custom_report_id: Optional[str] = None
) -> SecurityReport:
    """
    Transforms an existing AnalysisResult object into a structured SecurityReport.

    STRICT GUARANTEES:
    - Consumes existing analysis findings, security score, and risk level directly.
    - Does NOT re-run static analysis engines or re-calculate scores.
    - Uses timezone-aware UTC timestamps.
    """
    if isinstance(analysis, dict):
        analysis_obj = AnalysisResult(**analysis)
    else:
        analysis_obj = analysis

    report_id = custom_report_id or generate_report_id()
    generated_at = datetime.now(timezone.utc).isoformat()

    findings = analysis_obj.findings
    total_findings = len(findings)

    # 1. Executive Summary Construction
    scan_meta = analysis_obj.scan or ScanMetadata(
        language=analysis_obj.language or "python",
        filename=(findings[0].source_file if findings else "input.py"),
        analyzers_requested=analysis_obj.analyzers,
        analyzers_completed=analysis_obj.analyzers,
        finding_count=total_findings,
    )

    primary_category = analysis_obj.security.score_explanation.get("primary_risk_category")
    if not primary_category and findings:
        primary_category = findings[0].category

    affected_files = list(set(f.source_file for f in findings if f.source_file))
    affected_files_count = len(affected_files) if affected_files else 1

    critical_count = sum(1 for f in findings if (f.severity or "").upper() == "CRITICAL")
    high_count = sum(1 for f in findings if (f.severity or "").upper() == "HIGH")

    exec_summary = ExecutiveSummary(
        target_file=scan_meta.filename,
        language=scan_meta.language,
        security_score=analysis_obj.security.score,
        risk_level=analysis_obj.security.risk_level,
        logical_vulnerabilities=analysis_obj.security.logical_vulnerabilities,
        raw_detections=analysis_obj.security.raw_detections,
        highest_severity=analysis_obj.security.highest_severity or ("MINIMAL" if total_findings == 0 else "INFO"),
        primary_risk_category=primary_category,
        critical_count=critical_count,
        high_count=high_count,
        affected_files_count=affected_files_count,
    )

    # 2. Severity Breakdown Percentage Calculation (Handling 0 findings safely)
    def calc_percentage(count: int) -> SeverityPercentage:
        pct = round((count / total_findings) * 100, 1) if total_findings > 0 else 0.0
        return SeverityPercentage(count=count, percentage=pct)

    summary_obj = analysis_obj.summary
    severity_breakdown = SeverityBreakdownReport(
        critical=calc_percentage(summary_obj.critical),
        high=calc_percentage(summary_obj.high),
        medium=calc_percentage(summary_obj.medium),
        low=calc_percentage(summary_obj.low),
        info=calc_percentage(summary_obj.info),
    )

    # 3. Remediation Summary Construction (Only DETECTED categories included)
    category_map: Dict[str, List[Finding]] = {}
    for f in findings:
        cat = f.category or "OTHER"
        if cat not in category_map:
            category_map[cat] = []
        category_map[cat].append(f)

    remediation_categories: List[RemediationCategorySummary] = []
    top_recommendations: List[str] = []
    seen_recommendations = set()

    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    for cat_name, cat_findings in category_map.items():
        highest_sev = max(cat_findings, key=lambda x: sev_rank.get((x.severity or "").upper(), 0)).severity
        primary_f = cat_findings[0]
        rec_text = (
            primary_f.remediation.recommendation
            if primary_f.remediation
            else "Review flagged code pattern and apply standard secure coding controls."
        )

        remediation_categories.append(
            RemediationCategorySummary(
                category=cat_name,
                priority=highest_sev,
                findings_count=len(cat_findings),
                recommendation=rec_text,
            )
        )

        if primary_f.remediation and primary_f.remediation.title:
            rec_title = primary_f.remediation.title
            if rec_title not in seen_recommendations:
                seen_recommendations.add(rec_title)
                top_recommendations.append(rec_title)

    # Sort remediation categories by priority rank
    remediation_categories.sort(key=lambda x: sev_rank.get(x.priority.upper(), 0), reverse=True)

    remediation_summary = RemediationSummaryReport(
        categories=remediation_categories,
        top_recommendations=top_recommendations,
    )

    return SecurityReport(
        report_id=report_id,
        generated_at=generated_at,
        scan_metadata=scan_meta,
        executive_summary=exec_summary,
        security_score=analysis_obj.security.score,
        risk_level=analysis_obj.security.risk_level,
        severity_breakdown=severity_breakdown,
        logical_vulnerabilities=analysis_obj.security.logical_vulnerabilities,
        raw_detections=analysis_obj.security.raw_detections,
        findings=findings,
        remediation_summary=remediation_summary,
        analyzers=analysis_obj.analyzers,
    )
