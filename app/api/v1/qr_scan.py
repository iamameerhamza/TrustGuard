from fastapi import APIRouter, HTTPException, Request
import asyncio
from app.api.schemas import QrScanRequest, QrScanResponse
from app.modules.qr_decoder import decode_qr_from_base64, analyze_qr_target
from app.core.rate_limit import limiter
from app.core.telemetry import MODULE_REQUESTS, THREATS_DETECTED, track_latency

router = APIRouter(prefix="/scan/qr", tags=["qr"])

@router.post("/", response_model=QrScanResponse)
@limiter.limit("30/minute")
@track_latency(module="qr", stage="fusion")
async def scan_qr(request: Request, payload: QrScanRequest):
    try:
        # Offload decoding to thread pool
        decoded = await asyncio.wait_for(
            asyncio.to_thread(decode_qr_from_base64, payload.image_base64),
            timeout=3.0
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="QR decoding timed out")
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to decode QR image: {exc}")

    if not decoded:
        raise HTTPException(status_code=422, detail="No QR code found in the provided image.")

    try:
        # Offload analysis (which does network requests or non-HTTP parsing)
        result = await asyncio.wait_for(
            asyncio.to_thread(analyze_qr_target, decoded),
            timeout=10.0
        )
        
        MODULE_REQUESTS.labels(module="qr").inc()
        if result.is_malicious:
            THREATS_DETECTED.labels(threat_type="malicious_qr", severity="high").inc()
            
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="QR payload analysis timed out")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"QR payload analysis failed: {exc}")
