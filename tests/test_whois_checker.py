"""
tests/test_whois_checker.py
TrustGuard — WHOIS module test suite.

All tests mock the underlying whois.whois() call so the suite:
  - runs offline (no real DNS/WHOIS queries)
  - completes in milliseconds
  - never flakes due to network issues or rate limits

Run with:
    pytest tests/test_whois_checker.py -v
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from typing import Optional

from app.modules.whois_checker import (
    get_domain_age_days,
    cached_whois,
    score_domain_age,
    check_domain,
    invalidate_cache,
    _normalise_domain,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_whois(creation_date):
    """Build a minimal whois result object with a given creation_date."""
    mock = MagicMock()
    mock.creation_date = creation_date
    return mock


def _days_ago(n: int) -> datetime:
    """Return a timezone-aware UTC datetime n days in the past."""
    return datetime.now(timezone.utc) - timedelta(days=n)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_lru_cache():
    """Always start each test with a cold WHOIS cache."""
    invalidate_cache()
    yield
    invalidate_cache()


# ── get_domain_age_days ───────────────────────────────────────────────────────

class TestGetDomainAgeDays:

    @patch("app.modules.whois_checker.whois.whois")
    def test_normal_domain_returns_correct_age(self, mock_whois):
        mock_whois.return_value = _make_whois(_days_ago(365))
        age = get_domain_age_days("example.com")
        assert age == 365

    @patch("app.modules.whois_checker.whois.whois")
    def test_creation_date_as_list_takes_first_element(self, mock_whois):
        dates = [_days_ago(200), _days_ago(100)]
        mock_whois.return_value = _make_whois(dates)
        age = get_domain_age_days("example.com")
        assert age == 200

    @patch("app.modules.whois_checker.whois.whois")
    def test_empty_list_returns_none(self, mock_whois):
        mock_whois.return_value = _make_whois([])
        age = get_domain_age_days("example.com")
        assert age is None

    @patch("app.modules.whois_checker.whois.whois")
    def test_none_creation_date_returns_none(self, mock_whois):
        mock_whois.return_value = _make_whois(None)
        age = get_domain_age_days("example.com")
        assert age is None

    @patch("app.modules.whois_checker.whois.whois")
    def test_naive_datetime_treated_as_utc(self, mock_whois):
        """Naive datetimes (no tzinfo) must not raise — treated as UTC."""
        naive = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=50)
        assert naive.tzinfo is None
        mock_whois.return_value = _make_whois(naive)
        age = get_domain_age_days("example.com")
        assert age == 50

    @patch("app.modules.whois_checker.whois.whois")
    def test_lookup_exception_returns_none(self, mock_whois):
        mock_whois.side_effect = Exception("connection timeout")
        age = get_domain_age_days("unreachable.tld")
        assert age is None

    @patch("app.modules.whois_checker.whois.whois")
    def test_very_new_domain_returns_zero_not_negative(self, mock_whois):
        """Clock skew could produce a creation_date in the future — clamp to 0."""
        future = datetime.now(timezone.utc) + timedelta(days=1)
        mock_whois.return_value = _make_whois(future)
        age = get_domain_age_days("brand-new.com")
        assert age == 0

    @patch("app.modules.whois_checker.whois.whois")
    def test_brand_new_domain_age_zero(self, mock_whois):
        mock_whois.return_value = _make_whois(_days_ago(0))
        age = get_domain_age_days("new.com")
        assert age == 0


# ── _normalise_domain ─────────────────────────────────────────────────────────

class TestNormaliseDomain:

    def test_ascii_domain_unchanged(self):
        assert _normalise_domain("example.com") == "example.com"

    def test_idn_domain_converted_to_punycode(self):
        result = _normalise_domain("münchen.de")
        assert result.startswith("xn--")

    def test_already_punycode_unchanged(self):
        result = _normalise_domain("xn--mnchen-3ya.de")
        assert result == "xn--mnchen-3ya.de"


# ── score_domain_age ──────────────────────────────────────────────────────────

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
        """Older domains must never score higher risk than younger ones."""
        ages = [1, 7, 30, 90, 180, 365, 730]
        scores = [score_domain_age(a)["score"] for a in ages]
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1], (
                f"Score increased from age {ages[i]} to {ages[i+1]}: "
                f"{scores[i]} → {scores[i+1]}"
            )


# ── cached_whois ──────────────────────────────────────────────────────────────

class TestCachedWhois:

    @patch("app.modules.whois_checker.whois.whois")
    def test_second_call_does_not_hit_network(self, mock_whois):
        mock_whois.return_value = _make_whois(_days_ago(100))
        cached_whois("cached-domain.com")
        cached_whois("cached-domain.com")
        # whois.whois() must only be called once despite two cached_whois calls
        mock_whois.assert_called_once()

    @patch("app.modules.whois_checker.whois.whois")
    def test_different_domains_are_cached_separately(self, mock_whois):
        mock_whois.return_value = _make_whois(_days_ago(50))
        cached_whois("domain-a.com")
        cached_whois("domain-b.com")
        assert mock_whois.call_count == 2

    @patch("app.modules.whois_checker.whois.whois")
    def test_invalidate_cache_clears_entries(self, mock_whois):
        mock_whois.return_value = _make_whois(_days_ago(200))
        cached_whois("example.com")
        invalidate_cache()
        cached_whois("example.com")
        assert mock_whois.call_count == 2  # called again after cache clear


# ── check_domain (integration) ────────────────────────────────────────────────

class TestCheckDomain:

    @patch("app.modules.whois_checker.whois.whois")
    def test_fresh_phishing_domain_full_pipeline(self, mock_whois):
        """End-to-end: 2-day-old domain should come back as Critical."""
        mock_whois.return_value = _make_whois(_days_ago(2))
        result = check_domain("paypal-login-secure.xyz")
        assert result["label"] == "Critical"
        assert result["score"] >= 0.90
        assert result["age_days"] == 2
        assert result["source"] == "whois"

    @patch("app.modules.whois_checker.whois.whois")
    def test_established_domain_full_pipeline(self, mock_whois):
        """End-to-end: 10-year-old domain should come back as Safe."""
        mock_whois.return_value = _make_whois(_days_ago(3650))
        result = check_domain("google.com")
        assert result["label"] == "Safe"
        assert result["score"] <= 0.10

    @patch("app.modules.whois_checker.whois.whois")
    def test_private_registration_pipeline(self, mock_whois):
        """End-to-end: private registration (None date) should be Unknown/moderate."""
        mock_whois.return_value = _make_whois(None)
        result = check_domain("private-registration.com")
        assert result["label"] == "Unknown"
        assert result["score"] == 0.50

    @patch("app.modules.whois_checker.whois.whois")
    def test_network_failure_pipeline(self, mock_whois):
        """End-to-end: network failure should degrade gracefully to Unknown."""
        mock_whois.side_effect = Exception("WHOIS server unavailable")
        result = check_domain("unreachable.tld")
        assert result["label"] == "Unknown"
        assert result["score"] == 0.50
        # Must not raise — graceful degradation
