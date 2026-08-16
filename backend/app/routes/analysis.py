from fastapi import APIRouter, HTTPException, status
from app.models.findings import AnalysisRequest, AnalysisResult
from app.analyzers.analyzer_service import analyze_python_code

router = APIRouter(prefix="/api", tags=["Analysis"])

@router.post(
    "/analyze",
    response_model=AnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyze Python Source Code Statically",
    description="Analyzes user-submitted Python source code for security vulnerabilities using Bandit & Semgrep static analysis engines.",
)
async def analyze_code(request: AnalysisRequest) -> AnalysisResult:
    """
    POST /api/analyze

    SECURITY GUARANTEE:
    Submitted code is NEVER executed, imported, or dynamically evaluated.
    Static analysis is performed using isolated static analysis tools.
    """
    if not request.code or not request.code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source code cannot be empty."
        )

    try:
        result = analyze_python_code(request.code, request.filename)
        return result
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during static analysis execution."
        )
