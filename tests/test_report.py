from fastapi.testclient import TestClient
from app.main import app
import sqlite3
import os

client = TestClient(app)

def test_submit_report():
    response = client.post("/report", json={
        "url": "http://example.com/test-report",
        "is_phishing": True,
        "comments": "Looks like a credential harvester"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"

def test_get_url_history():
    # First submit a report
    client.post("/report", json={
        "url": "http://example.com/test-history",
        "is_phishing": False,
        "comments": "Safe site"
    })
    
    # Now get history
    response = client.get("/report/history?url=http://example.com/test-history")
    assert response.status_code == 200
    data = response.json()
    assert "reports" in data
    assert "scans" in data
    assert len(data["reports"]) > 0
    assert data["reports"][0]["is_phishing"] == False
