from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, status
from pydantic import ValidationError
from app.models.findings import AnalysisResult
from app.models.report import SecurityReport
from app.reports import report_service

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.post("", status_code=status.HTTP_201_CREATED)
def create_report_endpoint(payload: Dict[str, Any]):
    """
    Generate a SecurityReport from an existing AnalysisResult payload with strict Pydantic model validation.
    Rejects malformed or tampered payload structures.
    """
    try:
        if "analysis" in payload:
            raw_analysis = payload["analysis"]
        else:
            raw_analysis = payload

        # Strict Pydantic Schema Validation of incoming AnalysisResult payload
        validated_analysis = AnalysisResult.model_validate(raw_analysis)

        report = report_service.create_report_from_analysis(validated_analysis)
        return {
            "report_id": report.report_id,
            "generated_at": report.generated_at,
            "report": report,
        }
    except ValidationError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Report generation rejected: invalid analysis schema structure."
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to generate report from provided analysis payload: {str(err)}"
        )

@router.get("", response_model=List[SecurityReport])
def list_reports_endpoint():
    """
    Retrieve all stored security review reports.
    """
    return report_service.get_all_reports()

@router.get("/{report_id}", response_model=SecurityReport)
def get_report_endpoint(report_id: str):
    """
    Retrieve a specific security review report by report_id.
    """
    safe_id = report_id.strip()
    report = report_service.get_report(safe_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security report '{safe_id}' not found."
        )
    return report

@router.delete("/{report_id}")
def delete_report_endpoint(report_id: str):
    """
    Delete a security review report from history.
    """
    safe_id = report_id.strip()
    deleted = report_service.remove_report(safe_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security report '{safe_id}' not found."
        )
    return {"status": "deleted", "report_id": safe_id}
