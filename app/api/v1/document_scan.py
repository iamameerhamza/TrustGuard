from fastapi import APIRouter, HTTPException, Request
import asyncio
from app.api.schemas import DocumentScanRequest, DocumentScanResponse
from app.modules.doc_parser import inspect_document
from app.core.rate_limit import limiter
from app.core.telemetry import MODULE_REQUESTS, THREATS_DETECTED, track_latency

router = APIRouter(prefix="/scan/document", tags=["document"])

@router.post("/", response_model=DocumentScanResponse)
@limiter.limit("10/minute")
@track_latency(module="document", stage="fusion")
async def scan_document(request: Request, payload: DocumentScanRequest):
    try:
        # Offload heavy CPU parsing (PDFs, Macros) to thread pool and cap at 5 seconds
        result = await asyncio.wait_for(
            asyncio.to_thread(inspect_document, payload.filename, payload.content_base64, payload.mime_type),
            timeout=5.0
        )
        
        MODULE_REQUESTS.labels(module="document").inc()
        if result.prediction != "clean":
            THREATS_DETECTED.labels(threat_type="malicious_document", severity=result.prediction).inc()
            
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Document inspection timed out")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Document inspection failed: {exc}")
