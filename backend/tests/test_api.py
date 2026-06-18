from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health_endpoint_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_analyze_endpoint_streams_events():
    pass

def test_audit_log_populated_after_analysis():
    pass

def test_cache_endpoint_returns_previous_result():
    pass
