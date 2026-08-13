"""
REST API Surface - Thin adapter over QuickScanPipeline.
Replaces legacy app/api/routes/scan.py with modular pipeline.
"""
from __future__ import annotations
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.auth import require_api_key
from app.core.rate_limiter import check_rate_limit
from app.core.db import log_scan
from pipelines.quick_scan import QuickScanPipeline, quick_scan_sync
from core.schemas import Verdict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])

# Pipeline instance (singleton for connection pooling)
_pipeline: QuickScanPipeline | None = None


def get_pipeline() -> QuickScanPipeline:
    """Get or create pipeline instance."""
    global _pipeline
    if _pipeline is None:
        _pipeline = QuickScanPipeline()
    return _pipeline


# Request/Response models (compatible with existing API)
class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):
    """Backward-compatible response matching existing ScanResponse schema."""
    url: str
    domain: str
    tld: str
    path: str
    query: str
    scheme: str
    features: dict
    risk_score: int
    prediction: str
    ml_score: float | None = None
    ml_prediction: str | None = None
    vt_score: float | None = None
    blacklisted: bool = False
    reasons: list[str] = []
    whois: dict | None = None


def _verdict_to_response(verdict: Verdict, modality_input) -> ScanResponse:
    """Convert new Verdict to legacy ScanResponse format."""
    content = modality_input.content
    
    # Extract features for response
    features = {}
    if verdict.model_outputs.get("rf_url_onnx"):
        mo = verdict.model_outputs["rf_url_onnx"]
        features["ml_score"] = mo.get("score")
        features["ml_prediction"] = mo.get("prediction")
    
    # Build reasons from chain of thought
    reasons = [step for step in verdict.chain_of_thought if ":" in step]
    
    # WHOIS info (placeholder - would come from feature extractor)
    whois = None
    # TODO: Add WHOIS from feature vector if available
    
    return ScanResponse(
        url=content.get("url", verdict.url),
        domain=content.get("domain", ""),
        tld=content.get("domain", "").split(".")[-1] if "." in content.get("domain", "") else "",
        path=content.get("path", ""),
        query=content.get("query", ""),
        scheme=content.get("scheme", "https"),
        features=features,
        risk_score=verdict.risk_score,
        prediction=verdict.prediction,
        ml_score=features.get("ml_score"),
        ml_prediction=features.get("ml_prediction"),
        vt_score=None,  # Not in quick scan
        blacklisted=False,  # Not checked in quick scan
        reasons=reasons,
        whois=whois,
    )


@router.post("", response_model=ScanResponse, dependencies=[Depends(check_rate_limit), Depends(require_api_key)])
async def scan_url(request: ScanRequest, pipeline: QuickScanPipeline = Depends(get_pipeline)):
    """
    Scan a URL for phishing/threats using the quick scan pipeline.
    
    This is the new modular pipeline replacing the legacy scan endpoint.
    """
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    try:
        # Run pipeline
        verdict = await pipeline.run(url, source="api")
        
        # Convert to legacy response format
        modality_input = None
        # We need the modality input for response - get it from pipeline
        # For now, create a minimal one
        from modules.intake.url_intake.intake import URLIntake
        intake = URLIntake()
        modality_input = intake.accept(url, source="api")
        
        response = _verdict_to_response(verdict, modality_input)
        
        # Log to database (legacy format)
        log_scan(
            "trustguard.db", 
            url, 
            verdict.risk_score, 
            verdict.prediction,
            ml_score=verdict.model_outputs.get("rf_url_onnx", {}).get("score"),
            ml_prediction=verdict.model_outputs.get("rf_url_onnx", {}).get("prediction"),
            blacklisted=False,
            reasons=verdict.chain_of_thought,
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Scan failed for {url}: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/health")
async def health_check(pipeline: QuickScanPipeline = Depends(get_pipeline)):
    """Health check endpoint with pipeline component status."""
    health = pipeline.health_check()
    health["status"] = "ok" if health["model"] == "ok" else "degraded"
    return health


# Legacy sync endpoint for backward compatibility
@router.post("/sync", response_model=ScanResponse, dependencies=[Depends(check_rate_limit), Depends(require_api_key)])
def scan_url_sync(request: ScanRequest):
    """Synchronous scan endpoint (for simple clients)."""
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    try:
        verdict = quick_scan_sync(url, source="api")
        
        # Create modality input for response
        from modules.intake.url_intake.intake import URLIntake
        intake = URLIntake()
        modality_input = intake.accept(url, source="api")
        
        response = _verdict_to_response(verdict, modality_input)
        
        # Log to database
        log_scan(
            "trustguard.db", 
            url, 
            verdict.risk_score, 
            verdict.prediction,
            ml_score=verdict.model_outputs.get("rf_url_onnx", {}).get("score"),
            ml_prediction=verdict.model_outputs.get("rf_url_onnx", {}).get("prediction"),
            blacklisted=False,
            reasons=verdict.chain_of_thought,
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Sync scan failed for {url}: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


# Export router
__all__ = ["router"]