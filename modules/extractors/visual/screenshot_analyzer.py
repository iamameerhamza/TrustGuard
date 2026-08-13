"""
TrustGuard Visual Inspection - Screenshot & Brand Impersonation Analyzer
Unified extractor combining DOM rendering, login form detection, and pHash brand matching.
"""
from __future__ import annotations
import logging
from typing import Dict, Any
from modules.extractors.visual.screenshot_service import ScreenshotService
from modules.extractors.visual.brand_matcher import PerceptualHashMatcher

logger = logging.getLogger(__name__)


class VisualImpersonationAnalyzer:
    """Unified analyzer producing structured visual threat signals."""

    def __init__(self):
        self.screenshot_service = ScreenshotService()
        self.brand_matcher = PerceptualHashMatcher()

    async def analyze_url(self, url: str, domain: str) -> dict:
        """
        Extract visual threat features for a given URL and domain.
        """
        capture_result = await self.screenshot_service.capture_url(url)
        screenshot_b64 = capture_result.get("screenshot_b64", "")
        has_login_form = capture_result.get("has_login_form", False)

        visual_match = self.brand_matcher.match_brand(screenshot_b64, domain)

        # Risk scoring logic for visual inspection
        visual_risk_score = 0.0
        risk_factors = []

        if visual_match["is_spoofing_attempt"]:
            visual_risk_score += 60.0
            risk_factors.append(f"Visual page template matches {visual_match['matched_brand']} but domain is untrusted ({domain})")

        if has_login_form and visual_match["similarity_score"] >= 0.65:
            visual_risk_score += 25.0
            risk_factors.append("Credential login form detected on spoofed brand template")

        return {
            "url": url,
            "domain": domain,
            "visual_captured": capture_result["captured"],
            "has_login_form": has_login_form,
            "phash": visual_match["phash"],
            "matched_brand": visual_match["matched_brand"],
            "similarity_score": visual_match["similarity_score"],
            "is_spoofing_attempt": visual_match["is_spoofing_attempt"],
            "visual_risk_score": min(100.0, visual_risk_score),
            "risk_factors": risk_factors,
        }
