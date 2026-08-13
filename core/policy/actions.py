"""
TrustGuard Core Policy - Containment Actions Executor
Dispatches policy directives (BLOCK, WARN, QUARANTINE) and records audit trail events.
"""
from __future__ import annotations
import logging
from typing import Dict, Any
from core.schemas.evidence import VerdictSummary
from core.policy.containment_rules import ContainmentRulesEngine

logger = logging.getLogger(__name__)


class ContainmentActionDispatcher:
    """Dispatches policy enforcement actions and maintains containment audit trails."""

    def __init__(self):
        self.rules_engine = ContainmentRulesEngine()

    def dispatch_containment(self, verdict: VerdictSummary) -> Dict[str, Any]:
        """
        Evaluate policy and generate actionable client enforcement directives.
        """
        policy_result = self.rules_engine.evaluate_policy(verdict)
        
        audit_event = {
            "target": verdict.target,
            "overall_risk_score": verdict.overall_risk_score,
            "verdict_label": verdict.verdict_label,
            "directive_action": policy_result["action"],
            "triggered_rules": policy_result["triggered_rules"],
            "should_block": policy_result["should_block"],
            "should_warn": policy_result["should_warn"],
        }

        logger.info(f"[PolicyEngine] Dispatched action '{policy_result['action']}' for {verdict.target}")
        return audit_event
