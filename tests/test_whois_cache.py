"""
tests/test_whois_cache.py
TrustGuard — WHOIS caching tests.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from app.modules.whois_checker import cached_whois, invalidate_cache

def _make_whois(creation_date):
    mock = MagicMock()
    mock.creation_date = creation_date
    return mock

def _days_ago(n: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=n)

@pytest.fixture(autouse=True)
def clear_lru_cache():
    invalidate_cache()
    yield
    invalidate_cache()

class TestCachedWhois:
    @patch("app.modules.whois_checker.whois.whois")
    def test_second_call_does_not_hit_network(self, mock_whois):
        mock_whois.return_value = _make_whois(_days_ago(100))
        cached_whois("cached-domain.com")
        cached_whois("cached-domain.com")
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
        assert mock_whois.call_count == 2
