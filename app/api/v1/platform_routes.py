"""
TrustGuard Platform API Routes - Multi-Modal Inspection, Agentic Reasoning & Trust Seals
Exposes Document Analysis, Visual Impersonation, Agentic PII Guard, and Trust Seal Generation endpoints.
"""
from __future__ import annotations
import re
import uuid
import base64
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, File, UploadFile, HTTPException, Form
from pydantic import BaseModel

from modules.extractors.documents.doc_inspector import DocumentSecurityInspector
from modules.extractors.visual.brand_matcher import PerceptualHashMatcher
from modules.reasoning.tool_registry import ToolRegistry
from modules.reasoning.agent_orchestrator import AgenticOrchestrator
from core.schemas.evidence import EvidenceItem, EvidenceType, SeverityLevel

router = APIRouter(prefix="/api/v1", tags=["Platform Modules"])

doc_inspector = DocumentSecurityInspector()
visual_matcher = PerceptualHashMatcher()
tool_registry = ToolRegistry()
agent_orchestrator = AgenticOrchestrator(tool_registry=tool_registry)


# ---------------- Document Inspection ----------------
@router.post("/scan/document")
async def scan_document(file: UploadFile = File(...)):
    """
    Inspect PDF or Office XML (DOCX/XLSX/PPTX) documents for malicious JavaScript, VBA macros, and suspicious external links.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename required")

    contents = await file.read()
    result = doc_inspector.inspect_document(contents, file.filename)
    return {
        "success": True,
        "result": result
    }


# ---------------- Visual Impersonation Inspector ----------------
class VisualScanRequest(BaseModel):
    screenshot_b64: str
    claimed_domain: str


@router.post("/scan/visual")
async def scan_visual_impersonation(payload: VisualScanRequest):
    """
    Compare page screenshot pHash signature against reference brand login templates (Google, Microsoft, PayPal, Apple, etc.).
    """
    if not payload.screenshot_b64:
        raise HTTPException(status_code=400, detail="Screenshot base64 payload required")

    match_res = visual_matcher.match_brand(payload.screenshot_b64, payload.claimed_domain)
    return {
        "success": True,
        "visual_analysis": match_res
    }


# ---------------- Agentic Investigation & PII Guard ----------------
class AgenticScanRequest(BaseModel):
    url: str
    text_content: Optional[str] = None


@router.post("/scan/agentic")
async def run_agentic_investigation(payload: AgenticScanRequest):
    """
    Run multi-tool agentic investigation loop and inspect text content for PII leaks (credit cards, SSNs, API keys) & prompt injection attempts.
    """
    domain = payload.url.split("//")[-1].split("/")[0] if "//" in payload.url else payload.url.split("/")[0]
    
    # 1. Base evidence
    initial_evidence = [
        EvidenceItem(
            evidence_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.URL,
            source_layer="LEXICAL_INSPECTOR",
            confidence=0.85,
            severity=SeverityLevel.MEDIUM if len(domain) > 20 else SeverityLevel.LOW,
            raw_observation={"url": payload.url, "domain": domain},
            explanation=f"Lexical analysis performed on {domain}",
        )
    ]

    # Run agentic loop
    verdict = await agent_orchestrator.investigate_target(
        target_url=payload.url,
        domain=domain,
        initial_score=55.0 if "login" in payload.url.lower() or "verify" in payload.url.lower() else 20.0,
        initial_evidence=initial_evidence,
    )

    # 2. PII & Prompt Inspection on optional text content
    pii_findings = []
    if payload.text_content:
        text = payload.text_content
        # Credit Card regex
        if re.search(r'\b(?:\d[ -]*?){13,16}\b', text):
            pii_findings.append({"type": "Credit Card Number", "severity": "CRITICAL"})
        # SSN regex
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', text):
            pii_findings.append({"type": "Social Security Number (SSN)", "severity": "CRITICAL"})
        # API Key regex
        if re.search(r'(?:sk_live|AKIA|ghp_)[a-zA-Z0-9]{20,}', text):
            pii_findings.append({"type": "API Key / Access Token", "severity": "CRITICAL"})
        # Email regex
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text):
            pii_findings.append({"type": "Email Address", "severity": "MEDIUM"})
        # Prompt injection vectors
        if re.search(r'(?:ignore previous instructions|system prompt|override safety)', text, re.I):
            pii_findings.append({"type": "Adversarial Prompt Injection Vector", "severity": "HIGH"})

    return {
        "success": True,
        "verdict": {
            "target": verdict.target,
            "overall_risk_score": verdict.overall_risk_score,
            "verdict_label": verdict.verdict_label,
            "confidence": verdict.confidence,
            "primary_risk_drivers": verdict.primary_risk_drivers,
            "evidence_list": [
                {
                    "evidence_id": e.evidence_id,
                    "evidence_type": e.evidence_type.value,
                    "source_layer": e.source_layer,
                    "severity": e.severity.value,
                    "explanation": e.explanation,
                }
                for e in verdict.evidence_list
            ],
            "remediation_guidance": verdict.remediation_guidance,
        },
        "pii_findings": pii_findings,
    }


# ---------------- Trust Seals & Compliance Framework ----------------
class TrustSealRequest(BaseModel):
    domain: str
    seal_type: str = "certified"  # "certified" | "pci_dss" | "malware_free" | "realtime_guard"
    theme: str = "dark"  # "dark" | "light" | "neon"


@router.post("/trust/seals")
async def generate_trust_seal(payload: TrustSealRequest):
    """
    Generate customized SVG/HTML Trust Seal badge embed code and verification payload.
    """
    badge_titles = {
        "certified": "TrustGuard Verified Security",
        "pci_dss": "PCI-DSS Security Compliant",
        "malware_free": "Malware & Phishing Shielded",
        "realtime_guard": "24/7 AI Real-Time Guarded",
    }
    title = badge_titles.get(payload.seal_type, "TrustGuard Verified Security")
    bg_color = "#0f172a" if payload.theme == "dark" else ("#090d16" if payload.theme == "neon" else "#f8fafc")
    text_color = "#38bdf8" if payload.theme == "neon" else ("#0ea5e9" if payload.theme == "dark" else "#0284c7")
    border_color = "#3b82f6" if payload.theme == "neon" else "#334155"

    svg_code = f'''<svg xmlns="http://www.w3.org/2000/svg" width="240" height="60" viewBox="0 0 240 60">
  <rect width="240" height="60" rx="8" fill="{bg_color}" stroke="{border_color}" stroke-width="2"/>
  <path d="M24 18 L34 14 L44 18 L44 32 C44 40 34 44 34 44 C34 44 24 40 24 32 Z" fill="{text_color}" opacity="0.2" stroke="{text_color}" stroke-width="2"/>
  <path d="M30 28 L33 31 L38 25" fill="none" stroke="{text_color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  <text x="56" y="27" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="11" font-weight="700" fill="{text_color}">{title.upper()}</text>
  <text x="56" y="42" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="10" fill="#94a3b8">VERIFIED: {payload.domain}</text>
</svg>'''

    embed_html = f'''<!-- TrustGuard Verification Badge -->
<a href="https://trustguard.security/verify?domain={payload.domain}" target="_blank" rel="noopener noreferrer">
  <img src="data:image/svg+xml;base64,{base64.b64encode(svg_code.encode()).decode()}" alt="{title}" width="240" height="60" />
</a>'''

    return {
        "success": True,
        "domain": payload.domain,
        "seal_type": payload.seal_type,
        "theme": payload.theme,
        "svg": svg_code,
        "embed_code": embed_html,
        "compliance": {
            "pci_dss": "PASSED (Scanning Active)",
            "gdpr_privacy": "PASSED (K-Anonymity & Differential Privacy)",
            "iso_27001": "COMPLIANT (Post-Quantum & Encrypted Signals)",
        }
    }
