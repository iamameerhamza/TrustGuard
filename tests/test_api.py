from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_scan_url():
    response = client.post("/scan", json={"url": "example.com/test?q=1"})
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "example.com"
    assert data["path"] == "/test"
    assert data["scheme"] == "http"
    assert data["query"] == "q=1"
    assert data["url"] == "http://example.com/test?q=1"
    assert "features" in data
    assert data["features"]["domain_length"] == 11
