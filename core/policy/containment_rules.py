"""
TrustGuard Core Policy - Containment Rules Engine
Evaluates configurable security policies against verdict summaries and evidence items.
"""
from __future__ import annotations
from typing import List, Dict, Any
from core.schemas.evidence import VerdictSummary, SeverityLevel


class PolicyRule:
    """Security policy rule definition."""
    def __init__(self, rule_id: str, name: str, action: str, condition_fn):
        self.rule_id = rule_id
        self.name = name
        self.action = action
        self.condition_fn = condition_fn

    def evaluate(self, verdict: VerdictSummary) -> bool:
        return self.condition_fn(verdict)


class ContainmentRulesEngine:
    """Evaluates security rules and outputs containment directives."""

    def __init__(self):
        self.rules: List[PolicyRule] = []
        self._register_default_rules()

    def _register_default_rules(self):
        # Rule 1: High risk or phishing score -> BLOCK
        self.rules.append(
            PolicyRule(
                rule_id="POL-001",
                name="Block High Risk Phishing Target",
                action="BLOCK_NAVIGATION",
                condition_fn=lambda v: v.overall_risk_score >= 65.0 or v.verdict_label == "phishing"
            )
        )

        # Rule 2: Active threat feed match -> BLOCK
        self.rules.append(
            PolicyRule(
                rule_id="POL-002",
                name="Block Verified Threat Feed Match",
                action="BLOCK_NAVIGATION",
                condition_fn=lambda v: any(e.severity == SeverityLevel.CRITICAL for e in v.evidence_list)
            )
        )

        # Rule 3: Suspicious domain score -> WARN
        self.rules.append(
            PolicyRule(
                rule_id="POL-003",
                name="Warn User for Suspicious Domain",
                action="WARN_USER",
                condition_fn=lambda v: 30.0 <= v.overall_risk_score < 65.0
            )
        )

    def evaluate_policy(self, verdict: VerdictSummary) -> Dict[str, Any]:
        """
        Evaluate all active policy rules against verdict summary.
        """
        triggered_rules = []
        chosen_action = "ALLOW"

        for rule in self.rules:
            if rule.evaluate(verdict):
                triggered_rules.append({"rule_id": rule.rule_id, "name": rule.name, "action": rule.action})
                if rule.action == "BLOCK_NAVIGATION":
                    chosen_action = "BLOCK_NAVIGATION"
                elif rule.action == "QUARANTINE_FILE" and chosen_action != "BLOCK_NAVIGATION":
                    chosen_action = "QUARANTINE_FILE"
                elif rule.action == "WARN_USER" and chosen_action not in ("BLOCK_NAVIGATION", "QUARANTINE_FILE"):
                    chosen_action = "WARN_USER"

        return {
            "target": verdict.target,
            "action": chosen_action,
            "triggered_rules": triggered_rules,
            "should_block": chosen_action == "BLOCK_NAVIGATION",
            "should_warn": chosen_action in ("WARN_USER", "BLOCK_NAVIGATION"),
        }
