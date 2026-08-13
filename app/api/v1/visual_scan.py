from fastapi import APIRouter, HTTPException, Request
import asyncio
from app.api.schemas import VisualScanRequest, VisualScanResponse
from app.modules.phash_matcher import analyze_visual
from app.core.rate_limit import limiter
from app.core.telemetry import MODULE_REQUESTS, THREATS_DETECTED, track_latency

router = APIRouter(prefix="/scan/visual", tags=["visual"])

@router.post("/", response_model=VisualScanResponse)
@limiter.limit("20/minute")
@track_latency(module="visual", stage="fusion")
async def scan_visual(request: Request, payload: VisualScanRequest):
    try:
        # Offload heavy CV processing and Tesseract OCR to a thread
        result = await asyncio.wait_for(
            asyncio.to_thread(analyze_visual, payload.image_base64, payload.target_brand),
            timeout=5.0
        )
        
        MODULE_REQUESTS.labels(module="visual").inc()
        if result["is_spoof"]:
            THREATS_DETECTED.labels(threat_type="visual_impersonation", severity="critical").inc()
            
        return VisualScanResponse(**result)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Visual analysis timed out")
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse image: {e}")
