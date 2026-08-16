import re
from typing import Dict, Any, List, Optional
from app.models.findings import Finding, AnalysisSummary
from app.analyzers.categories import (
    map_finding_category,
    map_rule_to_cwe,
    map_category_to_owasp,
    normalize_confidence,
    generate_fingerprint,
    extract_source_context,
)

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
}

def parse_cwe_string(raw_cwe: Any) -> Optional[str]:
    """
    Extract standard CWE-XXX format or return None if unavailable.
    """
    if not raw_cwe:
        return None

    if isinstance(raw_cwe, dict):
        cwe_id = raw_cwe.get("id")
        if cwe_id:
            return f"CWE-{cwe_id}"
        return None

    if isinstance(raw_cwe, list) and len(raw_cwe) > 0:
        raw_cwe = raw_cwe[0]

    if isinstance(raw_cwe, str):
        match = re.search(r"CWE-\d+", raw_cwe, re.IGNORECASE)
        if match:
            return match.group(0).upper()

    return None

def normalize_bandit_finding(item: Dict[str, Any], filename: str, index: int, raw_source_code: str = "") -> Finding:
    """
    Convert raw Bandit JSON finding dict to normalized & enriched Finding model.
    """
    test_id = str(item.get("test_id", "UNKNOWN"))
    line_start = int(item.get("line_number", 1))
    line_range = item.get("line_range", [])
    line_end = int(line_range[-1]) if line_range else line_start

    raw_severity = str(item.get("issue_severity", "MEDIUM")).upper()
    severity = SEVERITY_MAP.get(raw_severity, "MEDIUM")

    raw_confidence = str(item.get("issue_confidence", "MEDIUM"))
    confidence = normalize_confidence(raw_confidence)

    parsed_cwe = parse_cwe_string(item.get("issue_cwe"))
    test_name = item.get("test_name", test_id)
    issue_text = item.get("issue_text", "Potential security vulnerability detected by Bandit.")

    category = map_finding_category(test_id, parsed_cwe, issue_text)
    cwe = map_rule_to_cwe(test_id, category, parsed_cwe)
    owasp = map_category_to_owasp(category)

    code_snippet = item.get("code")
    if code_snippet:
        code_snippet = str(code_snippet).strip()

    fingerprint = generate_fingerprint(category, cwe, filename, line_start, line_end, test_id)
    source_ctx = extract_source_context(raw_source_code, line_start, line_end)

    evidence = {
        "source": code_snippet or f"Line {line_start}",
        "line_start": line_start,
        "line_end": line_end,
        "matched_rule": test_id,
        "analyzers": ["bandit"],
    }

    analyzer_evidence = [
        {
            "analyzer": "bandit",
            "rule_id": test_id,
            "confidence": confidence,
            "severity": severity,
        }
    ]

    return Finding(
        id=f"bandit-{test_id}-{line_start}-{index}",
        fingerprint=fingerprint,
        analyzer="bandit",
        detected_by=["bandit"],
        rule_id=test_id,
        title=f"Bandit {test_id}: {test_name}",
        description=issue_text,
        severity=severity,
        confidence=confidence,
        category=category,
        cwe=cwe,
        owasp=owasp,
        line_start=line_start,
        line_end=line_end,
        code=code_snippet,
        source_file=filename,
        evidence=evidence,
        analyzer_evidence=analyzer_evidence,
        source_context=source_ctx,
    )

def normalize_semgrep_finding(item: Dict[str, Any], filename: str, index: int, raw_source_code: str = "") -> Finding:
    """
    Convert raw Semgrep JSON finding dict to normalized & enriched Finding model.
    """
    check_id = str(item.get("check_id", "semgrep-rule"))
    rule_id = check_id.split(".")[-1] if "." in check_id else check_id

    start_pos = item.get("start", {})
    end_pos = item.get("end", {})
    line_start = int(start_pos.get("line", 1))
    line_end = int(end_pos.get("line", line_start))

    extra = item.get("extra", {})
    message = extra.get("message", "Potential security vulnerability detected by Semgrep.")
    metadata = extra.get("metadata", {})

    raw_severity = str(extra.get("severity") or metadata.get("severity") or "WARNING").upper()
    severity = SEVERITY_MAP.get(raw_severity, "MEDIUM")

    raw_confidence = str(metadata.get("confidence", "MEDIUM"))
    confidence = normalize_confidence(raw_confidence)

    parsed_cwe = parse_cwe_string(metadata.get("cwe"))
    category = map_finding_category(rule_id, parsed_cwe, message)
    cwe = map_rule_to_cwe(rule_id, category, parsed_cwe)
    owasp = map_category_to_owasp(category)

    code_lines = extra.get("lines")
    if code_lines:
        code_lines = str(code_lines).strip()

    fingerprint = generate_fingerprint(category, cwe, filename, line_start, line_end, rule_id)
    source_ctx = extract_source_context(raw_source_code, line_start, line_end)

    evidence = {
        "source": code_lines or f"Line {line_start}",
        "line_start": line_start,
        "line_end": line_end,
        "matched_rule": rule_id,
        "analyzers": ["semgrep"],
    }

    analyzer_evidence = [
        {
            "analyzer": "semgrep",
            "rule_id": rule_id,
            "confidence": confidence,
            "severity": severity,
        }
    ]

    return Finding(
        id=f"semgrep-{rule_id}-{line_start}-{index}",
        fingerprint=fingerprint,
        analyzer="semgrep",
        detected_by=["semgrep"],
        rule_id=rule_id,
        title=f"Semgrep: {rule_id}",
        description=message,
        severity=severity,
        confidence=confidence,
        category=category,
        cwe=cwe,
        owasp=owasp,
        line_start=line_start,
        line_end=line_end,
        code=code_lines,
        source_file=filename,
        evidence=evidence,
        analyzer_evidence=analyzer_evidence,
        source_context=source_ctx,
    )

def calculate_summary(findings: List[Finding]) -> AnalysisSummary:
    """
    Calculate finding counts aggregated by normalized severity.
    """
    summary = AnalysisSummary(total=len(findings))
    for f in findings:
        sev = f.severity.upper()
        if sev == "CRITICAL":
            summary.critical += 1
        elif sev == "HIGH":
            summary.high += 1
        elif sev == "MEDIUM":
            summary.medium += 1
        elif sev == "LOW":
            summary.low += 1
        elif sev == "INFO":
            summary.info += 1
    return summary
