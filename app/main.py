from fastapi import FastAPI
from app.api.schemas import ScanRequest, ScanResponse
from app.core.normalizer import normalize_url
from app.core.extractor import extract_features

app = FastAPI(title="TrustGuard API")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/scan", response_model=ScanResponse)
def scan_url(request: ScanRequest):
    normalized = normalize_url(request.url)
    features = extract_features(normalized)
    return ScanResponse(**normalized, features=features)
