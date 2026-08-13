"""
tests/test_whois_age.py
TrustGuard — WHOIS age calculation tests.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from app.modules.whois_checker import get_domain_age_days

def _make_whois(creation_date):
    """Build a minimal whois result object with a given creation_date."""
    mock = MagicMock()
    mock.creation_date = creation_date
    return mock

def _days_ago(n: int) -> datetime:
    """Return a timezone-aware UTC datetime n days in the past."""
    return datetime.now(timezone.utc) - timedelta(days=n)

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
        naive = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=50)
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
        future = datetime.now(timezone.utc) + timedelta(days=1)
        mock_whois.return_value = _make_whois(future)
        age = get_domain_age_days("brand-new.com")
        assert age == 0

    @patch("app.modules.whois_checker.whois.whois")
    def test_brand_new_domain_age_zero(self, mock_whois):
        mock_whois.return_value = _make_whois(_days_ago(0))
        age = get_domain_age_days("new.com")
        assert age == 0
