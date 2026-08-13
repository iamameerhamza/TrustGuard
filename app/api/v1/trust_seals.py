from fastapi import APIRouter, HTTPException
from app.api.schemas import SealRequest, SealResponse
from app.modules.seal_renderer import generate_seal

router = APIRouter(prefix="/seals", tags=["seals"])

@router.post("/generate", response_model=SealResponse)
def create_seal(request: SealRequest):
    try:
        return generate_seal(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Seal generation failed: {exc}")
