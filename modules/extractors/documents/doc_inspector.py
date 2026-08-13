"""
TrustGuard Document Inspection - Unified Document Security Inspector
Parses PDF, DOCX, XLSX, and PPTX documents for embedded malware indicators, macros, and links.
"""
from __future__ import annotations
import zipfile
import re
import logging
from io import BytesIO
from typing import Dict, Any
from modules.extractors.documents.pdf_parser import PDFDocumentParser

logger = logging.getLogger(__name__)


class DocumentSecurityInspector:
    """Unified static document security analysis engine."""

    def __init__(self):
        self.pdf_parser = PDFDocumentParser()

    def inspect_document(self, file_bytes: bytes, filename: str) -> dict:
        """
        Inspect document bytes based on file extension / signature.
        """
        filename_lower = filename.lower()

        if filename_lower.endswith(".pdf") or file_bytes.startswith(b"%PDF"):
            return self._inspect_pdf(file_bytes, filename)
        
        if filename_lower.endswith((".docx", ".xlsx", ".pptx", ".zip")) or file_bytes.startswith(b"PK\x03\x04"):
            return self._inspect_office_xml(file_bytes, filename)

        return {
            "filename": filename,
            "error": "Unsupported document format for static security inspection",
            "document_risk_score": 0.0,
            "links": [],
        }

    def _inspect_pdf(self, file_bytes: bytes, filename: str) -> dict:
        parsed = self.pdf_parser.parse_pdf_bytes(file_bytes)
        
        risk_score = 0.0
        risk_factors = []

        if parsed.get("has_javascript"):
            risk_score += 45.0
            risk_factors.append("PDF contains embedded JavaScript code execution blocks (/JS)")

        if parsed.get("has_open_action"):
            risk_score += 35.0
            risk_factors.append("PDF contains auto-executing launch action (/OpenAction)")

        if parsed.get("link_count", 0) > 10:
            risk_score += 15.0
            risk_factors.append(f"High volume of embedded hyperlinks ({parsed['link_count']})")

        return {
            "filename": filename,
            "format": "PDF",
            "link_count": parsed.get("link_count", 0),
            "links": parsed.get("links", []),
            "has_javascript": parsed.get("has_javascript", False),
            "has_open_action": parsed.get("has_open_action", False),
            "document_risk_score": min(100.0, risk_score),
            "risk_factors": risk_factors,
            "verdict": "malicious" if risk_score >= 65 else ("suspicious" if risk_score >= 30 else "safe"),
        }

    def _inspect_office_xml(self, file_bytes: bytes, filename: str) -> dict:
        """Inspect OpenXML ZIP structures for macros and external hyperlinked targets."""
        links = []
        has_vba_macro = False
        external_rels = []

        try:
            with zipfile.ZipFile(BytesIO(file_bytes)) as z:
                names = z.namelist()

                # Check for VBA binary macros
                if any("vbaProject.bin" in name for name in names):
                    has_vba_macro = True

                # Inspect relationship XML files for external links
                for name in names:
                    if name.endswith(".rels"):
                        rels_content = z.read(name).decode("utf-8", errors="ignore")
                        targets = re.findall(r'Target="(https?://[^"]+)"', rels_content)
                        external_rels.extend(targets)

            links = list(dict.fromkeys(external_rels))
        except Exception as e:
            logger.warning(f"Error reading Office XML structure: {e}")

        risk_score = 0.0
        risk_factors = []

        if has_vba_macro:
            risk_score += 65.0
            risk_factors.append("Office document contains executable VBA macros (vbaProject.bin)")

        if len(links) > 5:
            risk_score += 15.0
            risk_factors.append(f"Contains multiple external relationship hyperlinks ({len(links)})")

        return {
            "filename": filename,
            "format": "Office XML",
            "link_count": len(links),
            "links": links,
            "has_vba_macro": has_vba_macro,
            "document_risk_score": min(100.0, risk_score),
            "risk_factors": risk_factors,
            "verdict": "malicious" if risk_score >= 65 else ("suspicious" if risk_score >= 30 else "safe"),
        }
