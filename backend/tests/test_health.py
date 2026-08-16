import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    """
    Verify GET /api/health returns HTTP 200 and expected status.
    """
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "SecureCode Sentinel API"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data

def test_readiness_endpoint():
    """
    Verify GET /api/health/ready returns HTTP 200 and readiness status.
    """
    response = client.get("/api/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["service"] == "SecureCode Sentinel API"
    assert data["version"] == "0.1.0"
    assert "analyzer_mode" in data
    assert "timestamp" in data
