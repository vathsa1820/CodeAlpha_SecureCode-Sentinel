from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from app.models.findings import Finding, ScanMetadata, AnalysisSummary, SecurityAssessment

class SeverityPercentage(BaseModel):
    """
    Count and calculated percentage of logical findings for a severity level.
    """
    count: int = Field(default=0, description="Count of logical findings")
    percentage: float = Field(default=0.0, description="Percentage of total logical findings")

class SeverityBreakdownReport(BaseModel):
    """
    Detailed severity count and percentage distribution.
    """
    critical: SeverityPercentage = Field(default_factory=SeverityPercentage)
    high: SeverityPercentage = Field(default_factory=SeverityPercentage)
    medium: SeverityPercentage = Field(default_factory=SeverityPercentage)
    low: SeverityPercentage = Field(default_factory=SeverityPercentage)
    info: SeverityPercentage = Field(default_factory=SeverityPercentage)

class ExecutiveSummary(BaseModel):
    """
    High-level executive overview of the security audit.
    """
    target_file: str = Field(default="input.py", description="Target source filename")
    language: str = Field(default="python", description="Source code language")
    security_score: int = Field(..., description="Deterministic security score (0-100)")
    risk_level: str = Field(..., description="Risk level rating: CRITICAL, HIGH, MEDIUM, LOW, MINIMAL")
    logical_vulnerabilities: int = Field(..., description="Count of deduplicated logical vulnerabilities")
    raw_detections: int = Field(..., description="Total raw detections across all engines")
    highest_severity: Optional[str] = Field(default=None, description="Highest severity level detected")
    primary_risk_category: Optional[str] = Field(default=None, description="Primary vulnerability category posing highest risk")
    critical_count: int = Field(default=0, description="Count of critical findings")
    high_count: int = Field(default=0, description="Count of high severity findings")
    affected_files_count: int = Field(default=1, description="Count of affected source files")

class RemediationCategorySummary(BaseModel):
    """
    Remediation priority item for a detected vulnerability category.
    """
    category: str = Field(..., description="Vulnerability category name")
    priority: str = Field(..., description="Severity priority rating (CRITICAL, HIGH, MEDIUM, LOW)")
    findings_count: int = Field(..., description="Number of logical findings in this category")
    recommendation: str = Field(..., description="Primary recommendation text")

class RemediationSummaryReport(BaseModel):
    """
    Aggregated remediation summary grouping priorities and top recommendations.
    """
    categories: List[RemediationCategorySummary] = Field(default_factory=list, description="Categorized remediation priorities")
    top_recommendations: List[str] = Field(default_factory=list, description="List of top actionable secure coding recommendations")

class SecurityReport(BaseModel):
    """
    Structured security review report produced from an AnalysisResult.
    """
    report_id: str = Field(..., description="Unique report identifier (e.g. SCR-2026-000001)")
    generated_at: str = Field(..., description="ISO 8601 UTC timestamp when report was generated")
    scan_metadata: ScanMetadata = Field(..., description="Scan execution details and analyzer statuses")
    executive_summary: ExecutiveSummary = Field(..., description="Executive summary overview")
    security_score: int = Field(..., description="Overall security score")
    risk_level: str = Field(..., description="Overall risk rating level")
    severity_breakdown: SeverityBreakdownReport = Field(..., description="Percentage severity breakdown")
    logical_vulnerabilities: int = Field(..., description="Logical vulnerabilities count")
    raw_detections: int = Field(..., description="Raw detections count")
    findings: List[Finding] = Field(default_factory=list, description="Deduplicated logical security findings")
    remediation_summary: RemediationSummaryReport = Field(..., description="Categorized remediation priorities and recommendations")
    analyzers: List[str] = Field(default_factory=list, description="List of active static analyzer engines")

class ReportGenerationRequest(BaseModel):
    """
    Incoming request schema for generating a security report.
    """
    analysis: Any = Field(..., description="AnalysisResult object or dictionary")
