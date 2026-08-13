"""
Unit tests for Phase C Micro-Modules (MM-3.1, MM-3.2, MM-3.3, MM-3.4)
"""
import unittest
import asyncio
from datetime import datetime
from core.schemas.evidence import EvidenceItem, EvidenceType, SeverityLevel, VerdictSummary
from modules.reasoning.tool_registry import ToolRegistry
from modules.reasoning.agent_orchestrator import AgenticOrchestrator
from core.policy.containment_rules import ContainmentRulesEngine
from core.policy.actions import ContainmentActionDispatcher
from modules.reasoning.explainability import FactGroundedExplainer


class TestPhaseCModules(unittest.TestCase):
    def test_evidence_schema_creation(self):
        item = EvidenceItem(
            evidence_id="ev-123",
            evidence_type=EvidenceType.LEXICAL,
            source_layer="url_extractor",
            confidence=0.85,
            severity=SeverityLevel.HIGH,
            raw_observation={"keyword": "login"},
            explanation="Contains credential update keyword in domain",
        )
        self.assertEqual(item.confidence, 0.85)
        self.assertEqual(item.severity, SeverityLevel.HIGH)

    def test_agent_orchestrator_loop(self):
        registry = ToolRegistry()
        orchestrator = AgenticOrchestrator(registry, max_iterations=2)

        initial_evidence = [
            EvidenceItem(
                evidence_id="ev-1",
                evidence_type=EvidenceType.LEXICAL,
                source_layer="url_extractor",
                confidence=0.7,
                severity=SeverityLevel.MEDIUM,
                raw_observation={"entropy": 4.2},
                explanation="High entropy subdomains detected",
            )
        ]

        async def run_test():
            verdict = await orchestrator.investigate_target(
                target_url="https://secure-login.update-verify.xyz",
                domain="update-verify.xyz",
                initial_score=55.0,  # Ambiguous score -> triggers tools
                initial_evidence=initial_evidence
            )
            self.assertGreaterEqual(verdict.overall_risk_score, 65.0)
            self.assertEqual(verdict.verdict_label, "phishing")

        asyncio.run(run_test())

    def test_containment_policy_engine(self):
        dispatcher = ContainmentActionDispatcher()

        verdict = VerdictSummary(
            target="https://bad-site.com",
            overall_risk_score=85.0,
            verdict_label="phishing",
            confidence=0.9,
            primary_risk_drivers=["Verified threat feed hit"],
            evidence_list=[],
            remediation_guidance="Block navigation immediately",
        )

        res = dispatcher.dispatch_containment(verdict)
        self.assertEqual(res["directive_action"], "BLOCK_NAVIGATION")
        self.assertTrue(res["should_block"])

    def test_fact_grounded_explainer(self):
        explainer = FactGroundedExplainer()

        verdict = VerdictSummary(
            target="https://paypal-update.xyz",
            overall_risk_score=75.0,
            verdict_label="phishing",
            confidence=0.9,
            primary_risk_drivers=["Brand impersonation targeted at Paypal"],
            evidence_list=[
                EvidenceItem(
                    evidence_id="ev-99",
                    evidence_type=EvidenceType.VISUAL_SPOOF,
                    source_layer="visual_matcher",
                    confidence=0.95,
                    severity=SeverityLevel.CRITICAL,
                    raw_observation={"brand": "paypal"},
                    explanation="Visual template matches PayPal login but domain is untrusted",
                )
            ],
            remediation_guidance="Do not enter credentials.",
        )

        res = explainer.generate_explanation(verdict)
        self.assertIn("HIGH RISK", res["headline"])
        self.assertEqual(len(res["top_3_risk_drivers"]), 1)


if __name__ == "__main__":
    unittest.main()
