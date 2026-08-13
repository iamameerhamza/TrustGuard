"""
tests/test_whois_normalization.py
TrustGuard — WHOIS domain normalization tests.
"""

from app.modules.whois_checker import _normalise_domain

class TestNormaliseDomain:
    def test_ascii_domain_unchanged(self):
        assert _normalise_domain("example.com") == "example.com"

    def test_idn_domain_converted_to_punycode(self):
        result = _normalise_domain("münchen.de")
        assert result.startswith("xn--")

    def test_already_punycode_unchanged(self):
        result = _normalise_domain("xn--mnchen-3ya.de")
        assert result == "xn--mnchen-3ya.de"
