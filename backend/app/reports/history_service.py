"""
In-Memory Scan History Service

NON-PERSISTENT STORAGE DISCLAIMER:
Reports are stored strictly in-memory within the active server process.
If the backend server process restarts, stored reports will be reset.
"""

from typing import List, Dict, Optional
from app.models.report import SecurityReport

_reports_store: Dict[str, SecurityReport] = {}

def store_report(report: SecurityReport) -> SecurityReport:
    """
    Store a generated SecurityReport in in-memory session history.
    """
    _reports_store[report.report_id] = report
    return report

def list_reports() -> List[SecurityReport]:
    """
    Return a list of all stored security reports, sorted by generation date (newest first).
    """
    reports = list(_reports_store.values())
    reports.sort(key=lambda r: r.generated_at, reverse=True)
    return reports

def get_report_by_id(report_id: str) -> Optional[SecurityReport]:
    """
    Retrieve a specific security report by its unique report_id.
    Returns None if report_id does not exist.
    """
    return _reports_store.get(report_id)

def delete_report(report_id: str) -> bool:
    """
    Delete a specific security report by report_id.
    Returns True if deleted, False if not found.
    """
    if report_id in _reports_store:
        del _reports_store[report_id]
        return True
    return False

def clear_reports() -> None:
    """
    Clear all in-memory reports (primarily used for test cleanup).
    """
    _reports_store.clear()
