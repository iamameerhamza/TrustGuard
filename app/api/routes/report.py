from fastapi import APIRouter
from app.api.schemas import ReportRequest, UrlHistoryResponse
from app.core.db import log_report, get_url_history
from app.core.normalizer import normalize_url

router = APIRouter()

@router.post("/report")
def submit_report(request: ReportRequest):
    """
    Submit a community report about a URL (benign or phishing).
    """
    normalized = normalize_url(request.url)
    url = normalized["url"]
    log_report("trustguard.db", url, request.is_phishing, request.comments)
    return {"status": "success", "message": "Report logged successfully"}

@router.get("/report/history")
def read_url_history(url: str) -> UrlHistoryResponse:
    """
    Retrieve past scans and community reports for a specific URL.
    """
    normalized = normalize_url(url)
    history = get_url_history("trustguard.db", normalized["url"])
    return history
