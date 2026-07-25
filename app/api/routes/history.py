from fastapi import APIRouter
from app.api.schemas import ScanHistoryItem
from app.core.db import get_history
from typing import List

router = APIRouter()

@router.get("/history", response_model=List[ScanHistoryItem])
def read_history(limit: int = 50):
    """
    Retrieve the most recent URL scans from the database.
    """
    return get_history(limit=limit)
