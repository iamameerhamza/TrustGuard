from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.prompt_predictor import predict_prompt
from app.core.telemetry import THREATS_DETECTED

router = APIRouter(prefix="/scan/prompt", tags=["GenAI Security"])
limiter = Limiter(key_func=get_remote_address)

class PromptScanRequest(BaseModel):
    # Enforce a strict pre-tokenization length bound (max 2000 chars) to prevent tokenization-level DoS
    prompt: str = Field(..., max_length=2000, description="The raw prompt text to evaluate for injections.")

@router.post("/")
@limiter.limit("250/minute") # Based on 52ms ONNX INT8 profiling
async def scan_prompt(request: Request, body: PromptScanRequest):
    """
    Evaluates a prompt sequence against a DistilBERT NLP model to detect jailbreaks, 
    system instruction overrides, and payload injections.
    
    Inference is offloaded to a background thread to prevent event loop blocking.
    """
    if not body.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt text cannot be empty.")
        
    result = await predict_prompt(body.prompt)
    
    if result.get("error"):
        raise HTTPException(status_code=500, detail=f"Model Inference Error: {result['error']}")
        
    if result["prediction"] == "injection":
        THREATS_DETECTED.labels(
            threat_type="prompt_injection", 
            severity="high", 
            model_version=result["model_version"]
        ).inc()
        
    return {
        "status": "success",
        "data": {
            "prompt_length": len(body.prompt),
            "ml_score": result["score"],
            "prediction": result["prediction"],
            "model_used": "distilbert_onnx_int8",
            "model_version": result["model_version"],
            "is_canary": result["is_canary"]
        }
    }
