"""
tests/test_whois_scoring.py
TrustGuard — WHOIS risk scoring tests.
"""

from app.modules.whois_checker import score_domain_age

class TestScoreDomainAge:
    def test_none_age_returns_unknown_moderate_risk(self):
        result = score_domain_age(None)
        assert result["label"] == "Unknown"
        assert result["score"] == 0.50
        assert result["age_days"] is None
        assert result["source"] == "whois"

    def test_3_day_domain_is_critical(self):
        result = score_domain_age(3)
        assert result["label"] == "Critical"
        assert result["score"] >= 0.90
        assert "3" in result["reason"]

    def test_15_day_domain_is_high(self):
        result = score_domain_age(15)
        assert result["label"] == "High"
        assert result["score"] >= 0.70

    def test_60_day_domain_is_elevated(self):
        result = score_domain_age(60)
        assert result["label"] == "Elevated"
        assert result["score"] >= 0.50

    def test_120_day_domain_is_moderate(self):
        result = score_domain_age(120)
        assert result["label"] == "Moderate"
        assert 0.25 <= result["score"] <= 0.60

    def test_270_day_domain_is_low(self):
        result = score_domain_age(270)
        assert result["label"] == "Low"
        assert result["score"] < 0.35

    def test_500_day_domain_is_safe(self):
        result = score_domain_age(500)
        assert result["label"] == "Safe"
        assert result["score"] <= 0.10

    def test_score_always_within_bounds(self):
        for age in [None, 0, 1, 7, 30, 90, 180, 365, 1000, 5000]:
            result = score_domain_age(age)
            assert 0.0 <= result["score"] <= 1.0, f"score out of range for age={age}"

    def test_source_always_whois(self):
        for age in [None, 5, 400]:
            assert score_domain_age(age)["source"] == "whois"

    def test_reason_contains_age_when_known(self):
        result = score_domain_age(42)
        assert "42" in result["reason"]

    def test_score_monotonically_decreases_with_age(self):
        ages = [1, 7, 30, 90, 180, 365, 730]
        scores = [score_domain_age(a)["score"] for a in ages]
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1]
