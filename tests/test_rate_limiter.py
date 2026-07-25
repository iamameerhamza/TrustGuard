import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.core.rate_limiter import check_rate_limit, _requests
from fastapi import Depends

app = FastAPI()

@app.get("/test", dependencies=[Depends(check_rate_limit)])
def test_endpoint():
    return {"status": "ok"}

client = TestClient(app)

def test_rate_limiter():
    # Clear state
    _requests.clear()
    
    # Send 60 requests
    for _ in range(60):
        response = client.get("/test")
        assert response.status_code == 200
        
    # 61st request should be blocked
    response = client.get("/test")
    assert response.status_code == 429
    assert response.json() == {"detail": "Too Many Requests"}
