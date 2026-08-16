import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from app.config import MAX_SOURCE_SIZE_BYTES, MAX_FILENAME_LENGTH

class RemediationGuidance(BaseModel):
    """
    Actionable secure coding guidance and remediation example.
    """
    title: str = Field(..., description="Actionable title for remediation guidance")
    explanation: str = Field(..., description="Technical explanation of the security vulnerability")
    impact: str = Field(..., description="Potential security impact if left unaddressed")
    recommendation: str = Field(..., description="Specific step-by-step remediation recommendation")
    best_practice: str = Field(..., description="Industry standard secure coding best practice")
    secure_example: str = Field(..., description="Remediated code example demonstrating safe coding")
    cwe: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID")

class Finding(BaseModel):
    """
    Normalized security finding schema produced by static analyzers (Bandit, Semgrep, etc.)
    """
    id: str = Field(..., description="Unique finding identifier (e.g. bandit-B307-12)")
    finding_group_id: Optional[str] = Field(default=None, description="Correlated group ID for deduplicated findings")
    fingerprint: Optional[str] = Field(default=None, description="Deterministic SHA-256 fingerprint hash of finding")
    analyzer: str = Field(..., description="Primary static analyzer name ('bandit' | 'semgrep')")
    detected_by: List[str] = Field(default_factory=list, description="List of static analyzers that flagged this issue")
    rule_id: str = Field(..., description="Analyzer rule or test identifier (e.g. B307, unsafe-eval)")
    title: str = Field(..., description="Short summary title of the finding")
    description: str = Field(..., description="Detailed explanation of the security issue")
    severity: str = Field(..., description="Normalized severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    confidence: str = Field(default="MEDIUM", description="Normalized confidence level: HIGH, MEDIUM, LOW")
    category: str = Field(default="OTHER", description="Normalized vulnerability category")
    cwe: Optional[str] = Field(default=None, description="Standardized Common Weakness Enumeration ID (e.g. CWE-95)")
    owasp: Optional[str] = Field(default=None, description="OWASP Top 10:2021 classification (e.g. A03:2021-Injection)")
    line_start: int = Field(..., description="1-indexed starting line number of finding")
    line_end: int = Field(..., description="1-indexed ending line number of finding")
    code: Optional[str] = Field(default=None, description="Vulnerable source code snippet")
    source_file: Optional[str] = Field(default="input.py", description="Source code filename")
    evidence: Optional[Dict[str, Any]] = Field(default=None, description="Concise detection evidence object")
    analyzer_evidence: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="Preserved analyzer-specific evidence")
    source_context: Optional[Dict[str, Any]] = Field(default=None, description="Plain text source code context before/after line")
    remediation: Optional[RemediationGuidance] = Field(default=None, description="Deterministic remediation guidance")

class AnalysisSummary(BaseModel):
    """
    Aggregation summary of findings count grouped by normalized severity.
    """
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class SecurityAssessment(BaseModel):
    """
    Overall security risk rating, score, risk breakdown, and score explanation.
    """
    score: int = Field(..., description="Deterministic security score between 0 and 100")
    risk_level: str = Field(..., description="Risk rating level: CRITICAL, HIGH, MEDIUM, LOW, MINIMAL")
    logical_vulnerabilities: int = Field(..., description="Count of deduplicated/correlated logical security findings")
    raw_detections: int = Field(..., description="Total raw detections count across all static analyzers")
    highest_severity: Optional[str] = Field(default=None, description="Highest severity level detected in the scan")
    risk_breakdown: Dict[str, Any] = Field(default_factory=dict, description="Severity count breakdown & weighted risk")
    score_explanation: Dict[str, Any] = Field(default_factory=dict, description="Detailed score calculation explanation")

class AnalyzerStatus(BaseModel):
    """
    Operational status of an individual static analysis engine.
    """
    name: str = Field(..., description="Name of static analyzer ('bandit' | 'semgrep')")
    status: str = Field(..., description="Execution status: completed | failed")
    execution_mode: str = Field(default="local", description="Execution environment mode: local | docker")
    error: Optional[str] = Field(default=None, description="Sanitized error message if failed")

class ScanMetadata(BaseModel):
    """
    Comprehensive scan execution metadata.
    """
    language: str = Field(default="python", description="Target programming language")
    filename: str = Field(default="input.py", description="Target filename")
    analyzers_requested: List[str] = Field(default_factory=list, description="List of analyzers requested")
    analyzers_completed: List[str] = Field(default_factory=list, description="List of analyzers successfully completed")
    finding_count: int = Field(default=0, description="Count of logical findings detected")
    analyzer_status: List[AnalyzerStatus] = Field(default_factory=list, description="Status details per analyzer")

class AnalysisResult(BaseModel):
    """
    Unified analysis result returned by the static security analysis service.
    """
    status: str = Field(default="completed", description="Analysis status: completed | failed")
    language: str = Field(default="python", description="Source code programming language")
    findings: List[Finding] = Field(default_factory=list, description="List of normalized security findings")
    summary: AnalysisSummary = Field(default_factory=AnalysisSummary, description="Summary counts of findings")
    security: SecurityAssessment = Field(..., description="Security risk assessment and score details")
    analyzers: List[str] = Field(default_factory=list, description="List of active analyzers executed")
    scan: Optional[ScanMetadata] = Field(default=None, description="Detailed scan metadata and status")

class AnalysisRequest(BaseModel):
    """
    Incoming payload schema for source code static analysis request with strict validation.
    """
    code: str = Field(..., description="Raw Python source code text to analyze statically")
    filename: Optional[str] = Field(default="input.py", description="Optional filename for reference")

    @field_validator("code")

    def validate_code(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Source code cannot be empty.")

        code_bytes = v.encode("utf-8")
        if len(code_bytes) > MAX_SOURCE_SIZE_BYTES:
            raise ValueError(f"Source code size exceeds maximum allowed limit of {MAX_SOURCE_SIZE_BYTES // 1024} KB.")

        return v

    @field_validator("filename")

    def validate_filename(cls, v: Optional[str]) -> str:
        if not v:
            return "input.py"

        filename_str = str(v).strip()
        if len(filename_str) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename exceeds maximum length limit of {MAX_FILENAME_LENGTH} characters.")

        if "\x00" in filename_str:
            raise ValueError("Null bytes are prohibited in filenames.")

        if "/" in filename_str or "\\" in filename_str or ".." in filename_str:
            raise ValueError("Directory traversal characters and path separators are strictly prohibited.")

        if not filename_str.lower().endswith(".py"):
            raise ValueError("Only Python source code files with '.py' extension are supported.")

        if not re.match(r"^[a-zA-Z0-9_\-\.]+\.py$", filename_str, re.IGNORECASE):
            raise ValueError("Filename contains prohibited characters.")

        return filename_str
