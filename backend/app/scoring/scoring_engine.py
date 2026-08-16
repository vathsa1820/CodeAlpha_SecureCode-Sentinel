from typing import List, Dict, Any, Optional
from app.models.findings import Finding

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

def calculate_weighted_risk(logical_findings: List[Finding]) -> int:
    """
    Calculate sum of deterministic severity weights across logical findings.
    """
    total_weight = 0
    for f in logical_findings:
        sev = (f.severity or "MEDIUM").upper()
        total_weight += SEVERITY_WEIGHTS.get(sev, 4)
    return total_weight

def calculate_security_score(logical_findings: List[Finding]) -> int:
    """
    Calculate deterministic security score bounded strictly between 0 and 100.

    Formula:
      Weighted Risk (W) = sum(SEVERITY_WEIGHTS[finding.severity])
      Score = max(0, min(100, round(100 / (1 + 0.08 * W))))

      Extra rule: If there is at least 1 CRITICAL finding, the maximum allowed score is 45.
    """
    if not logical_findings:
        return 100

    weighted_risk = calculate_weighted_risk(logical_findings)
    raw_score = 100.0 / (1.0 + 0.08 * weighted_risk)
    score = round(raw_score)

    has_critical = any((f.severity or "").upper() == "CRITICAL" for f in logical_findings)
    if has_critical:
        score = min(score, 45)

    return max(0, min(100, score))

def determine_risk_level(score: int, logical_findings: List[Finding]) -> str:
    """
    Determine categorical security risk level based on score and severity distribution.
    """
    has_critical = any((f.severity or "").upper() == "CRITICAL" for f in logical_findings)
    has_high = any((f.severity or "").upper() == "HIGH" for f in logical_findings)

    if score >= 90 and not has_critical and not has_high:
        return "MINIMAL"
    if score >= 75 and not has_critical:
        return "LOW"
    if score >= 55:
        return "MEDIUM"
    if score >= 30:
        return "HIGH"
    return "CRITICAL"

def generate_risk_breakdown(logical_findings: List[Finding]) -> Dict[str, Any]:
    """
    Generate count breakdown and total weighted risk metrics.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in logical_findings:
        sev = (f.severity or "MEDIUM").lower()
        if sev in counts:
            counts[sev] += 1

    weighted_risk = calculate_weighted_risk(logical_findings)
    return {
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "info": counts["info"],
        "weighted_risk": weighted_risk,
    }

def generate_score_explanation(
    logical_findings: List[Finding],
    raw_findings_count: int,
) -> Dict[str, Any]:
    """
    Generate deterministic score explanation details for UI clients.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_weights: Dict[str, int] = {}

    for f in logical_findings:
        sev = (f.severity or "MEDIUM").lower()
        if sev in counts:
            counts[sev] += 1
        cat = f.category or "OTHER"
        weight = SEVERITY_WEIGHTS.get((f.severity or "MEDIUM").upper(), 4)
        category_weights[cat] = category_weights.get(cat, 0) + weight

    primary_category: Optional[str] = None
    if category_weights:
        primary_category = max(category_weights.items(), key=lambda x: x[1])[0]

    deduplication_savings = max(0, raw_findings_count - len(logical_findings))

    return {
        "critical_findings": counts["critical"],
        "high_findings": counts["high"],
        "medium_findings": counts["medium"],
        "low_findings": counts["low"],
        "info_findings": counts["info"],
        "primary_risk_category": primary_category,
        "deduplication_savings": deduplication_savings,
    }
