from typing import List, Optional, Dict, Any, Union
from app.models.findings import AnalysisResult
from app.models.report import SecurityReport
from app.reports.report_generator import generate_security_report
from app.reports import history_service

def create_report_from_analysis(analysis: Union[AnalysisResult, Dict[str, Any]]) -> SecurityReport:
    """
    Generate a SecurityReport from an AnalysisResult and save it to in-memory history.
    """
    report = generate_security_report(analysis)
    history_service.store_report(report)
    return report

def get_all_reports() -> List[SecurityReport]:
    """
    Retrieve all security reports in history.
    """
    return history_service.list_reports()

def get_report(report_id: str) -> Optional[SecurityReport]:
    """
    Retrieve a specific security report by ID.
    """
    return history_service.get_report_by_id(report_id)

def remove_report(report_id: str) -> bool:
    """
    Delete a security report by ID.
    """
    return history_service.delete_report(report_id)
