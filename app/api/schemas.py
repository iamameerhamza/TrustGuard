from pydantic import BaseModel, Field
from typing import Dict, Any
from datetime import datetime

# ── URL Scanner (Existing) ──
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

# ── QR Code Scanner ──
class QrScanRequest(BaseModel):
    image_base64: str = Field(..., description="Base64-encoded PNG/JPEG of the QR code")

class QrScanResponse(BaseModel):
    decoded_url: str | None
    is_malicious: bool
    risk_score: int
    redirect_chain: list[str] = []
    final_url: str | None = None
    safety_report: Dict[str, Any] | None = None

# ── Document Malware Inspector ──
class DocumentScanRequest(BaseModel):
    filename: str
    content_base64: str
    mime_type: str = Field(..., pattern=r"^(application/pdf|application/vnd\.openxmlformats|application/msword)")

class DocumentThreat(BaseModel):
    type: str  # macro, javascript, external_link, embedded_file
    description: str
    severity: str  # low, medium, high, critical

class DocumentScanResponse(BaseModel):
    filename: str
    mime_type: str
    threats_found: list[DocumentThreat] = []
    has_macros: bool = False
    has_javascript: bool = False
    external_links: list[str] = []
    risk_score: int
    prediction: str  # clean, suspicious, malicious

# ── Visual Impersonation / pHash ──
class VisualScanRequest(BaseModel):
    image_base64: str
    target_brand: str | None = Field(default=None, description="google, microsoft, paypal, apple")

class VisualScanResponse(BaseModel):
    phash_signature: str
    matched_brand: str | None
    similarity_score: float = Field(..., ge=0.0, le=1.0)
    is_spoof: bool
    risk_score: int

# ── Agentic PII Guard ──
class AgenticScanRequest(BaseModel):
    text: str
    scan_type: str = Field(default="full", pattern=r"^(pii|prompt_injection|full)$")

class PiiFinding(BaseModel):
    type: str  # credit_card, ssn, api_key, email, phone
    position: int
    snippet: str
    redacted: str

class AgenticScanResponse(BaseModel):
    text_length: int
    pii_findings: list[PiiFinding] = []
    prompt_injection_detected: bool = False
    injection_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: int
    sanitized_text: str | None = None

# ── Trust Seals ──
class SealRequest(BaseModel):
    domain: str
    seal_type: str = Field(..., pattern=r"^(certified|pci_dss|malware_free|real_time_guard)$")
    theme: str = Field(default="dark", pattern=r"^(dark|light|minimal)$")

class SealResponse(BaseModel):
    svg_markup: str
    html_embed: str
    expires_at: datetime
    verification_url: str
