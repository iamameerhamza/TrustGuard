"""
TrustGuard Reasoning - Multi-Tool Agentic Orchestrator
Executes adaptive investigation loops for ambiguous risk targets.
"""
from __future__ import annotations
import uuid
import logging
from typing import List, Dict, Any
from datetime import datetime
from core.schemas.evidence import EvidenceItem, EvidenceType, SeverityLevel, VerdictSummary
from modules.reasoning.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class AgenticOrchestrator:
    """Dynamic orchestrator triggering targeted tools based on initial threat ambiguity."""

    def __init__(self, tool_registry: ToolRegistry, max_iterations: int = 3):
        self.tool_registry = tool_registry
        self.max_iterations = max_iterations

    async def investigate_target(self, target_url: str, domain: str, initial_score: float, initial_evidence: List[EvidenceItem]) -> VerdictSummary:
        """
        Run agentic loop if initial score is ambiguous (40.0 <= initial_score <= 70.0).
        """
        evidence_chain = list(initial_evidence)
        current_score = initial_score
        iterations = 0

        # Check if adaptive tool triggering is needed
        if 40.0 <= current_score <= 70.0:
            logger.info(f"Initial score {initial_score} is ambiguous for {target_url}. Triggering agentic tool suite...")

            # Iteration 1: WHOIS Lookup
            if iterations < self.max_iterations:
                whois_tool = self.tool_registry.get_tool("WHOIS_LOOKUP")
                if whois_tool:
                    whois_res = await whois_tool.execute(domain=domain)
                    iterations += 1

                    if whois_res.get("is_new_domain"):
                        current_score += 15.0
                        evidence_chain.append(
                            EvidenceItem(
                                evidence_id=str(uuid.uuid4()),
                                evidence_type=EvidenceType.AGENTIC_TOOL,
                                source_layer="WHOIS_LOOKUP",
                                confidence=0.9,
                                severity=SeverityLevel.HIGH,
                                raw_observation=whois_res,
                                explanation=f"Domain registered recently ({whois_res.get('domain_age_days')} days old)",
                            )
                        )

            # Iteration 2: Threat Feed Search
            if iterations < self.max_iterations and current_score < 80.0:
                feed_tool = self.tool_registry.get_tool("THREAT_FEED_SEARCH")
                if feed_tool:
                    feed_res = await feed_tool.execute(target=target_url)
                    iterations += 1

                    if feed_res.get("in_openphish"):
                        current_score += 25.0
                        evidence_chain.append(
                            EvidenceItem(
                                evidence_id=str(uuid.uuid4()),
                                evidence_type=EvidenceType.THREAT_FEED,
                                source_layer="THREAT_FEED_SEARCH",
                                confidence=0.95,
                                severity=SeverityLevel.CRITICAL,
                                raw_observation=feed_res,
                                explanation="Target URL found active in OpenPhish threat intelligence feed",
                            )
                        )

        # Finalize verdict label
        final_score = min(100.0, max(0.0, current_score))
        verdict_label = "phishing" if final_score >= 65.0 else ("suspicious" if final_score >= 30.0 else "safe")

        # Rank primary risk drivers
        primary_drivers = [e.explanation for e in evidence_chain if e.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)]
        if not primary_drivers:
            primary_drivers = [e.explanation for e in evidence_chain[:3]]

        return VerdictSummary(
            target=target_url,
            overall_risk_score=round(final_score, 1),
            verdict_label=verdict_label,
            confidence=0.90 if len(evidence_chain) >= 2 else 0.75,
            primary_risk_drivers=primary_drivers,
            evidence_list=evidence_chain,
            remediation_guidance=self._generate_guidance(verdict_label),
        )

    def _generate_guidance(self, verdict_label: str) -> str:
        if verdict_label == "phishing":
            return "DO NOT enter any credentials, passwords, or personal financial details. Block site immediately."
        elif verdict_label == "suspicious":
            return "Proceed with extreme caution. Verify domain authenticity before submitting data."
        return "Site appears safe based on extracted security signals."
