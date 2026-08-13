"""
TrustGuard Document Inspection - PDF Hyperlink & Object Tree Parser
Extracts embedded URIs, JavaScript actions, and OpenAction triggers from PDF byte streams.
"""
from __future__ import annotations
import re
import logging
from io import BytesIO
from typing import Dict, Any

logger = logging.getLogger(__name__)


class PDFDocumentParser:
    """Parses PDF objects to extract hyperlinks and active executable elements."""

    def parse_pdf_bytes(self, pdf_bytes: bytes) -> dict:
        """
        Extract embedded links and suspicious PDF objects from byte buffer.
        """
        if not pdf_bytes or len(pdf_bytes) < 4:
            return {"error": "Empty or invalid PDF buffer", "links": [], "has_js": False}

        links = []
        has_js = False
        has_open_action = False

        # Attempt 1: PyPDF / pypdf library if available
        try:
            from pypdf import PdfReader
            reader = PdfReader(BytesIO(pdf_bytes))
            for page in reader.pages:
                if "/Annots" in page:
                    for annot in page["/Annots"]:
                        obj = annot.get_object()
                        if obj.get("/Subtype") == "/Link" and "/A" in obj:
                            action = obj["/A"]
                            if action.get("/S") == "/URI" and "/URI" in action:
                                links.append(str(action["/URI"]))

                # Check text content for raw URLs
                text = page.extract_text() or ""
                raw_urls = re.findall(r'https?://[^\s<>"]+', text)
                links.extend(raw_urls)
        except Exception:
            pass

        # Fallback raw byte pattern matching (robust against obfuscation)
        raw_text = pdf_bytes.decode("utf-8", errors="ignore")

        # 1. Regex URI extraction
        if not links:
            uri_matches = re.findall(r'/URI\s*\((https?://[^)]+)\)', raw_text)
            direct_urls = re.findall(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s()<>]*', raw_text)
            links.extend(uri_matches)
            links.extend(direct_urls)

        # 2. Check JavaScript / OpenAction objects
        if "/JavaScript" in raw_text or "/JS" in raw_text:
            has_js = True
        if "/OpenAction" in raw_text or "/AA" in raw_text:
            has_open_action = True

        # Deduplicate extracted links
        unique_links = list(dict.fromkeys(links))

        return {
            "link_count": len(unique_links),
            "links": unique_links,
            "has_javascript": has_js,
            "has_open_action": has_open_action,
            "is_encrypted": "/Encrypt" in raw_text,
        }
