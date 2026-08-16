from fastapi import APIRouter
from datetime import datetime, timezone
from app.config import ANALYZER_MODE

router = APIRouter(prefix="/api", tags=["Health"])

@router.get("/health")
async def health_check():
    """
    Health check endpoint for frontend connectivity and system status monitoring.
    """
    return {
        "status": "ok",
        "service": "SecureCode Sentinel API",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@router.get("/health/ready")
async def readiness_check():
    """
    Readiness check endpoint verifying application orchestration state.
    """
    return {
        "status": "ready",
        "service": "SecureCode Sentinel API",
        "version": "0.1.0",
        "analyzer_mode": ANALYZER_MODE,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
