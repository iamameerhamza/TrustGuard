import pytest
import os
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app


class _StubVTSignal:
    def __init__(self, score=0.0, state="scored"):
        self.state = state
        self.score = score


class _StubVTClient:
    async def scan_url(self, url):
        return _StubVTSignal(score=0.0)

    async def close(self):
        return None

@pytest.fixture(autouse=True)
def mock_external_calls():
    with patch("app.core.db.init_db") as mock_db, \
         patch("app.core.db.log_scan") as mock_log, \
         patch("app.core.predictor.predict") as mock_predict, \
         patch("app.core.threat_intel.check_blacklist") as mock_bl, \
         patch("app.modules.whois_checker.cached_whois") as mock_whois:

        mock_db.return_value = None
        mock_log.return_value = None
        # Our app's predict() returns a dict
        mock_predict.return_value = {"ml_score": 0.12, "ml_prediction": "safe"}
        mock_bl.return_value = False
        mock_whois.return_value = 450
        app.state.vt_client = _StubVTClient()

        yield {
            "db": mock_db,
            "log": mock_log,
            "predict": mock_predict,
            "blacklist": mock_bl,
            "whois": mock_whois,
            "vt_client": app.state.vt_client,
        }

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "2.1.0"}

def test_scan_url():
    # Because we mocked init_db globally via autouse=True, we don't need to call it here.
    
    # We clear cache internally to avoid cross-test contamination just in case
    # Cache clearing removed due to architecture change
    api_key = os.environ.get("TRUSTGUARD_API_KEY", "change_me_to_a_strong_random_secret")
    headers = {"X-API-Key": api_key}
    response = client.post("/scan", json={"url": "example.com/test?q=1"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "example.com"
    assert data["path"] == "/test"
    assert data["scheme"] == "http"
    assert data["query"] == "q=1"
    assert data["url"] == "http://example.com/test?q=1"
    assert "features" in data
    assert data["features"]["domain_length"] == 11
    assert "risk_score" in data
    assert "prediction" in data
    assert "ml_score" in data
    assert "ml_prediction" in data
    assert "blacklisted" in data
    assert "reasons" in data
    assert len(data["reasons"]) >= 1
    
    # Test caching (should return the exact same response quickly)
    response_cached = client.post("/scan", json={"url": "example.com/test?q=1"}, headers=headers)
    assert response_cached.status_code == 200
    assert response_cached.json() == data
