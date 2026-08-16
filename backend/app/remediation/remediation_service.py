from app.models.findings import Finding
from app.remediation.remediation_kb import REMEDIATION_KB, DEFAULT_REMEDIATION, RemediationGuidance

def get_remediation_for_finding(finding: Finding) -> RemediationGuidance:
    """
    Map a logical or raw static finding to its corresponding deterministic remediation guidance.
    """
    category = (finding.category or "").upper()

    if category in REMEDIATION_KB:
        guidance = REMEDIATION_KB[category].model_copy()
        # Override CWE if specific CWE was extracted from analyzer finding
        if finding.cwe:
            guidance.cwe = finding.cwe
        return guidance

    # Fallback for unknown categories
    fallback = DEFAULT_REMEDIATION.model_copy()
    if finding.cwe:
        fallback.cwe = finding.cwe
    return fallback
