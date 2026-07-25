from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    url: str
    domain: str
    tld: str
    path: str
    query: str
    scheme: str
    features: Dict[str, Any]
    risk_score: int
    prediction: str
    ml_score: float | None = None
    ml_prediction: str | None = None
    vt_score: float | None = None
    blacklisted: bool = False
    reasons: list[str] = []
    whois: Dict[str, Any] | None = None

class ScanHistoryItem(BaseModel):
    id: int
    url: str
    risk_score: int
    prediction: str
    ml_score: float | None = None
    ml_prediction: str | None = None
    vt_score: float | None = None
    blacklisted: bool = False
    timestamp: datetime

class ReportRequest(BaseModel):
    url: str
    is_phishing: bool
    comments: str | None = None

class ReportItem(BaseModel):
    id: int
    is_phishing: bool
    comments: str | None = None
    timestamp: datetime

class UrlHistoryResponse(BaseModel):
    scans: list[Dict[str, Any]]
    reports: list[ReportItem]
