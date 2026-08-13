"""
tests/test_whois_pipeline.py
TrustGuard — WHOIS end-to-end integration tests.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from app.modules.whois_checker import check_domain

def _make_whois(creation_date):
    mock = MagicMock()
    mock.creation_date = creation_date
    return mock

def _days_ago(n: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=n)

class TestCheckDomain:
    @pytest.mark.asyncio
    @patch("app.modules.whois_checker.whois.whois")
    async def test_fresh_phishing_domain_full_pipeline(self, mock_whois):
        mock_whois.return_value = _make_whois(_days_ago(2))
        result = await check_domain("paypal-login-secure.xyz")
        assert result["label"] == "Critical"
        assert result["score"] >= 0.90
        assert result["age_days"] == 2
        assert result["source"] == "whois"

    @pytest.mark.asyncio
    @patch("app.modules.whois_checker.whois.whois")
    async def test_established_domain_full_pipeline(self, mock_whois):
        mock_whois.return_value = _make_whois(_days_ago(3650))
        result = await check_domain("google.com")
        assert result["label"] == "Safe"
        assert result["score"] <= 0.10

    @pytest.mark.asyncio
    @patch("app.modules.whois_checker.whois.whois")
    async def test_private_registration_pipeline(self, mock_whois):
        mock_whois.return_value = _make_whois(None)
        result = await check_domain("private-registration.com")
        assert result["label"] == "Unknown"
        assert result["score"] == 0.50

    @pytest.mark.asyncio
    @patch("app.modules.whois_checker.whois.whois")
    async def test_network_failure_pipeline(self, mock_whois):
        mock_whois.side_effect = Exception("WHOIS server unavailable")
        result = await check_domain("unreachable.tld")
        assert result["label"] == "Unknown"
        assert result["score"] == 0.50
