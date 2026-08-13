"""
TrustGuard Reasoning - Fact-Grounded Explanation Generator
Transforms technical signal vectors and evidence items into human-readable, grounded security explanations.
"""
from __future__ import annotations
import logging
from typing import List, Dict, Any
from core.schemas.evidence import EvidenceItem, VerdictSummary, SeverityLevel

logger = logging.getLogger(__name__)


class FactGroundedExplainer:
    """Generates plain-language, evidence-backed security explanations."""

    TECHNICAL_SIGNAL_MAP: Dict[str, str] = {
        "url_length": "URL is unusually long and complex",
        "entropy": "URL contains random/encoded character sequences (high entropy)",
        "subdomain_count": "Excessive subdomain levels indicating domain spoofing",
        "punycode_detected": "Domain uses internationalized punycode (homograph attack risk)",
        "brand_impersonation_score": "Domain impersonates a known brand identity",
        "is_ip_address": "Direct IP address used instead of legitimate domain name",
        "tld_risk_score": "Top-level domain (TLD) has a high historical scam frequency",
        "suspicious_keyword_count": "URL contains sensitive credential/login keywords",
    }

    def generate_explanation(self, verdict: VerdictSummary) -> Dict[str, Any]:
        """
        Produce top 3 risk drivers and plain-language summary.
        """
        evidence_items = verdict.evidence_list

        # Rank evidence items by severity and confidence
        severity_order = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1,
        }

        sorted_evidence = sorted(
            evidence_items,
            key=lambda e: (severity_order.get(e.severity, 0), e.confidence),
            reverse=True
        )

        top_drivers = [e.explanation for e in sorted_evidence[:3]]
        if not top_drivers:
            top_drivers = ["No significant threat indicators detected in baseline scan"]

        # Plain language summary headline
        if verdict.verdict_label == "phishing":
            headline = f"HIGH RISK: This link appears to be a phishing page targeting credentials."
        elif verdict.verdict_label == "suspicious":
            headline = f"WARNING: Potential security risk detected. Verify URL identity carefully."
        else:
            headline = f"SAFE: No major phishing or malware indicators found."

        return {
            "target": verdict.target,
            "headline": headline,
            "overall_risk_score": verdict.overall_risk_score,
            "verdict_label": verdict.verdict_label,
            "top_3_risk_drivers": top_drivers,
            "remediation_guidance": verdict.remediation_guidance,
            "detailed_explanations": [e.explanation for e in sorted_evidence],
        }
