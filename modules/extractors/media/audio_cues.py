"""
TrustGuard Media Inspection - Synthetic Audio & Vishing Cue Extractor
Extracts speech transcripts, identifies urgent financial/credential coercion keywords, and extracts embedded URLs/phones.
"""
from __future__ import annotations
import re
import logging
from typing import Dict, Any, Set

logger = logging.getLogger(__name__)


class AudioVishingCueExtractor:
    """Analyzes audio samples for vishing (voice phishing) and urgency indicators."""

    URGENT_COERCION_KEYWORDS: Set[str] = frozenset({
        "bank", "account", "social security", "tax", "irs", "fraud", "police",
        "warrant", "arrest", "suspend", "wire transfer", "gift card", "crypto",
        "bitcoin", "verify", "password", "security code", "otp", "2fa",
        "immediate action", "urgent", "legal action", "compromised", "support"
    })

    def analyze_audio_transcript(self, transcript_text: str) -> dict:
        """
        Analyze speech-to-text transcript for coercion cues and extracted targets.
        """
        if not transcript_text:
            return {
                "transcript": "",
                "vishing_risk_score": 0.0,
                "urgency_keywords_found": [],
                "extracted_urls": [],
                "extracted_phone_numbers": [],
                "risk_factors": [],
            }

        text_lower = transcript_text.lower()

        # 1. Coercion keyword matching
        found_keywords = [kw for kw in self.URGENT_COERCION_KEYWORDS if kw in text_lower]

        # 2. Extract phone numbers and embedded URLs from audio transcript
        phone_pattern = r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
        url_pattern = r'https?://[^\s<>"]+'

        phone_numbers = list(dict.fromkeys(re.findall(phone_pattern, transcript_text)))
        urls = list(dict.fromkeys(re.findall(url_pattern, transcript_text)))

        # 3. Calculate Vishing risk score
        risk_score = 0.0
        risk_factors = []

        if len(found_keywords) >= 3:
            risk_score += 50.0
            risk_factors.append(f"Multiple high-coercion vishing keywords detected: {', '.join(found_keywords[:4])}")
        elif len(found_keywords) > 0:
            risk_score += 25.0

        if any(term in text_lower for term in ["gift card", "wire transfer", "bitcoin", "crypto"]):
            risk_score += 35.0
            risk_factors.append("Demands untraceable payment method (gift card / wire / crypto)")

        if any(term in text_lower for term in ["otp", "2fa", "security code", "password"]):
            risk_score += 30.0
            risk_factors.append("Requests one-time security code (OTP) or password over audio call")

        return {
            "transcript": transcript_text,
            "vishing_risk_score": min(100.0, risk_score),
            "urgency_keywords_found": found_keywords,
            "extracted_urls": urls,
            "extracted_phone_numbers": phone_numbers,
            "risk_factors": risk_factors,
            "verdict": "vishing_phishing" if risk_score >= 65 else ("suspicious" if risk_score >= 30 else "safe"),
        }
