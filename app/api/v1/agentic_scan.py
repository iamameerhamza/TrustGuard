from fastapi import APIRouter, HTTPException
from app.api.schemas import AgenticScanRequest, AgenticScanResponse
from app.modules.pii_scanner import scan_pii, sanitize_text
from app.modules.prompt_guard import detect_prompt_injection

router = APIRouter(prefix="/scan/agentic", tags=["agentic"])

@router.post("/", response_model=AgenticScanResponse)
def scan_agentic(request: AgenticScanRequest):
    text = request.text
    if not text:
        raise HTTPException(status_code=400, detail="Empty text payload.")
    
    pii_findings = []
    injection_detected = False
    injection_confidence = 0.0
    
    if request.scan_type in ("pii", "full"):
        pii_findings = scan_pii(text)
    
    if request.scan_type in ("prompt_injection", "full"):
        guard_result = detect_prompt_injection(text)
        injection_detected = guard_result["detected"]
        injection_confidence = guard_result["confidence"]
    
    risk = 0
    if pii_findings:
        risk += min(len(pii_findings) * 10, 50)
    if injection_detected:
        risk += int(injection_confidence * 50)
    risk = min(risk, 100)
    
    sanitized = None
    if pii_findings:
        sanitized = sanitize_text(text, pii_findings)
    
    return AgenticScanResponse(
        text_length=len(text),
        pii_findings=pii_findings,
        prompt_injection_detected=injection_detected,
        injection_confidence=injection_confidence,
        risk_score=risk,
        sanitized_text=sanitized
    )
