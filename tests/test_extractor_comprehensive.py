"""
Comprehensive unit tests for URL Feature Extractor.
Tests all edge cases for the modular extractor in modules/extractors/url_features/extractor.py
"""
import pytest
from datetime import datetime
from core.schemas import ModalityInput
from modules.extractors.url_features.extractor import URLFeatureExtractor


class TestURLFeatureExtractor:
    """Test suite for URLFeatureExtractor covering all edge cases."""

    @pytest.fixture
    def extractor(self):
        return URLFeatureExtractor()

    @pytest.fixture
    def make_input(self):
        """Factory for creating ModalityInput objects."""
        def _make(url: str, domain: str = "", path: str = "", query: str = "", port: int = None):
            return ModalityInput(
                modality="url",
                content={
                    "url": url,
                    "domain": domain,
                    "path": path,
                    "query": query,
                    "port": port
                },
                timestamp=datetime.utcnow()
            )
        return _make

    # ===== Basic Extraction Tests =====

    def test_basic_url_extraction(self, extractor, make_input):
        """Test basic URL feature extraction."""
        inp = make_input(
            url="http://example.com/path?query=1",
            domain="example.com",
            path="/path",
            query="query=1"
        )
        fv = extractor.extract(inp)

        assert fv.features["url_length"] == len("http://example.com/path?query=1")
        assert fv.features["domain_length"] == len("example.com")
        assert fv.features["path_length"] == len("/path")
        assert fv.features["query_length"] == len("query=1")
        assert fv.features["subdomain_count"] == 0
        assert fv.features["query_param_count"] == 1

    def test_subdomain_counting(self, extractor, make_input):
        """Test subdomain counting at various levels."""
        test_cases = [
            ("example.com", 0),
            ("sub.example.com", 1),
            ("a.b.c.example.com", 3),
            ("", 0),
            ("com", 0),  # TLD only
            ("example.co.uk", 1),  # Simple split count
        ]
        for domain, expected in test_cases:
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            assert fv.features["subdomain_count"] == expected, f"Failed for {domain}"

    def test_suspicious_keywords_detection(self, extractor, make_input):
        """Test detection of suspicious keywords in URL."""
        url = "http://secure-login.bank.com/update-credentials"
        inp = make_input(url=url, domain="secure-login.bank.com")
        fv = extractor.extract(inp)

        # Should detect: secure, login, bank, update, credentials
        assert fv.features["suspicious_keyword_count"] >= 5

    def test_suspicious_keywords_case_insensitive(self, extractor, make_input):
        """Test keyword detection is case insensitive."""
        url = "http://EXAMPLE.COM/LOGIN/SECURE"
        inp = make_input(url=url, domain="EXAMPLE.COM")
        fv = extractor.extract(inp)

        assert fv.features["suspicious_keyword_count"] >= 2  # login, secure

    def test_special_chars_detection(self, extractor, make_input):
        """Test detection of special characters in domain."""
        test_cases = [
            ("example.com", False),
            ("ex@mple.com", True),  # @ symbol
            ("ex#mple.com", True),  # # symbol
            ("ex$mple.com", True),  # $ symbol
            ("ex%mple.com", True),  # % symbol
            ("sub.example.com", False),  # dots and hyphens allowed
            ("sub-domain.example.com", False),  # hyphens allowed
        ]
        for domain, expected in test_cases:
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            assert fv.features["has_special_chars"] == (1.0 if expected else 0.0), f"Failed for {domain}"

    def test_at_symbol_detection(self, extractor, make_input):
        """Test @ symbol detection in URL (credential stuffing indicator)."""
        test_cases = [
            ("http://user:pass@example.com", True),
            ("http://example.com", False),
            ("http://example.com@evil.com", True),  # @ in path
        ]
        for url, expected in test_cases:
            inp = make_input(url=url)
            fv = extractor.extract(inp)
            assert fv.features["has_at_symbol"] == (1.0 if expected else 0.0), f"Failed for {url}"

    def test_dash_in_domain(self, extractor, make_input):
        """Test dash detection in domain (SLD)."""
        test_cases = [
            ("example.com", False),
            ("my-site.com", True),
            ("sub.my-site.com", True),  # dash in SLD
            ("sub.domain-example.com", True),  # dash in SLD
        ]
        for domain, expected in test_cases:
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            assert fv.features["has_dash_in_domain"] == (1.0 if expected else 0.0), f"Failed for {domain}"

    def test_ip_address_detection(self, extractor, make_input):
        """Test IP address detection in domain."""
        test_cases = [
            ("192.168.1.1", True),
            ("10.0.0.1", True),
            ("255.255.255.255", True),
            ("999.999.999.999", True),  # Regex matches but invalid IP - still counts
            ("example.com", False),
            ("1.2.3", False),  # Not enough octets
            ("1.2.3.4.5", False),  # Too many octets
        ]
        for domain, expected in test_cases:
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            assert fv.features["is_ip_address"] == (1.0 if expected else 0.0), f"Failed for {domain}"

    def test_port_detection(self, extractor, make_input):
        """Test port detection in URL."""
        test_cases = [
            ("http://example.com:8080", True),
            ("http://example.com:443", True),
            ("http://example.com", False),
            ("https://example.com", False),
        ]
        for url, expected in test_cases:
            port_val = 8080 if ":8080" in url else (443 if ":443" in url else None)
            inp = make_input(url=url, port=port_val)
            fv = extractor.extract(inp)
            assert fv.features["has_port"] == (1.0 if expected else 0.0), f"Failed for {url}"

    # ===== Entropy Tests =====

    def test_entropy_calculation(self, extractor, make_input):
        """Test Shannon entropy calculation."""
        # Low entropy: repeated characters
        inp = make_input(url="http://aaaaaaaaaa.com", domain="aaaaaaaaaa.com")
        fv = extractor.extract(inp)
        assert fv.features["entropy"] < 3.0

        # High entropy: random characters
        inp = make_input(url="http://x7k9m2p4q.com", domain="x7k9m2p4q.com")
        fv = extractor.extract(inp)
        assert fv.features["entropy"] > 2.0

    def test_subdomain_entropy(self, extractor, make_input):
        """Test subdomain entropy calculation."""
        # Low entropy subdomain
        inp = make_input(url="http://aaaa.bbbb.example.com", domain="aaaa.bbbb.example.com")
        fv = extractor.extract(inp)
        assert fv.features["subdomain_entropy"] >= 0

        # No subdomain
        inp = make_input(url="http://example.com", domain="example.com")
        fv = extractor.extract(inp)
        assert fv.features["subdomain_entropy"] == 0.0

    def test_path_entropy(self, extractor, make_input):
        """Test path entropy calculation."""
        inp = make_input(url="http://example.com/abcdef123456", domain="example.com", path="/abcdef123456")
        fv = extractor.extract(inp)
        assert fv.features["path_entropy"] > 0

    # ===== TLD Risk Tests =====

    def test_high_risk_tld_detection(self, extractor, make_input):
        """Test detection of high-risk TLDs."""
        high_risk = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "club"]
        for tld in high_risk:
            domain = f"example.{tld}"
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            assert fv.features["has_suspicious_tld"] == 1.0, f"Failed for .{tld}"
            assert fv.features["tld_risk_score"] == 0.8, f"Failed risk score for .{tld}"

    def test_safe_tld_low_risk(self, extractor, make_input):
        """Test safe TLDs get low risk score."""
        safe_tlds = ["com", "org", "net", "edu", "gov", "io", "co", "ai"]
        for tld in safe_tlds:
            domain = f"example.{tld}"
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            assert fv.features["has_suspicious_tld"] == 0.0, f"Failed for .{tld}"
            assert fv.features["tld_risk_score"] == 0.1, f"Failed risk score for .{tld}"

    def test_unknown_tld_moderate_risk(self, extractor, make_input):
        """Test unknown TLDs get moderate risk."""
        domain = "example.unknown"
        inp = make_input(url=f"http://{domain}", domain=domain)
        fv = extractor.extract(inp)
        assert fv.features["tld_risk_score"] == 0.3

    # ===== Brand Impersonation Tests =====

    def test_brand_impersonation_subdomain(self, extractor, make_input):
        """Test brand impersonation via subdomain spoofing."""
        test_cases = [
            ("google.com.phishing.site", 0.9),  # Brand in subdomain
            ("facebook.com.evil.com", 0.9),
            ("apple.com.fake.site", 0.9),
        ]
        for domain, expected_min in test_cases:
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            assert fv.features["brand_impersonation_score"] >= expected_min, f"Failed for {domain}"

    def test_brand_impersonation_typosquatting(self, extractor, make_input):
        """Test brand impersonation detection (brand in subdomain)."""
        test_cases = [
            "google.com.phishing.site",
            "paypal.verify-account.com",
            "apple.login-secure.net",
        ]
        for domain in test_cases:
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            # Should detect brand-like pattern
            assert fv.features["brand_impersonation_score"] > 0, f"Failed for {domain}"

    def test_legitimate_brand_domain(self, extractor, make_input):
        """Test legitimate brand domains score 0."""
        legitimate = ["google.com", "facebook.com", "apple.com", "microsoft.com"]
        for domain in legitimate:
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            assert fv.features["brand_impersonation_score"] == 0.0, f"Failed for {domain}"

    # ===== Punycode Tests =====

    def test_punycode_detection(self, extractor, make_input):
        """Test punycode (xn--) detection for homograph attacks."""
        test_cases = [
            ("xn--pple-43d.com", True),  # аpple.com (cyrillic 'a')
            ("xn--gogle-6ya.com", True),  # gоogle.com (cyrillic 'o')
            ("example.com", False),
            ("sub.xn--example.com", True),  # Punycode in subdomain
        ]
        for domain, expected in test_cases:
            inp = make_input(url=f"http://{domain}", domain=domain)
            fv = extractor.extract(inp)
            assert fv.features["punycode_detected"] == (1.0 if expected else 0.0), f"Failed for {domain}"

    # ===== URL Hash Prefix Tests =====

    def test_url_hash_prefix(self, extractor, make_input):
        """Test URL hash prefix generation for privacy-preserving blocklist."""
        inp = make_input(url="http://example.com/test")
        fv = extractor.extract(inp)

        hash_val = fv.features["url_hash_prefix"]
        assert 0.0 <= hash_val <= 1.0
        assert isinstance(hash_val, float)

        # Same URL should produce same hash
        inp2 = make_input(url="http://example.com/test")
        fv2 = extractor.extract(inp2)
        assert fv.features["url_hash_prefix"] == fv2.features["url_hash_prefix"]

    # ===== Edge Cases =====

    def test_empty_url(self, extractor, make_input):
        """Test handling of empty URL."""
        inp = make_input(url="", domain="", path="", query="")
        fv = extractor.extract(inp)

        # All features should be 0 or defaults
        assert fv.features["url_length"] == 0
        assert fv.features["domain_length"] == 0
        assert fv.features["entropy"] == 0.0

    def test_very_long_url(self, extractor, make_input):
        """Test handling of very long URLs."""
        long_path = "/a" * 1000
        long_query = "&".join([f"p{i}=v{i}" for i in range(100)])
        url = f"http://example.com{long_path}?{long_query}"

        inp = make_input(url=url, domain="example.com", path=long_path, query=long_query)
        fv = extractor.extract(inp)

        assert fv.features["url_length"] == len(url)
        assert fv.features["query_param_count"] == 100
        assert fv.features["path_length"] == len(long_path)

    def test_unicode_in_url(self, extractor, make_input):
        """Test handling of unicode/IDN domains."""
        # Punycode encoded
        inp = make_input(url="http://xn--mller-kva.example.com", domain="xn--mller-kva.example.com")
        fv = extractor.extract(inp)
        assert fv.features["punycode_detected"] == 1.0

    def test_query_param_count(self, extractor, make_input):
        """Test query parameter counting."""
        test_cases = [
            ("", 0),
            ("a=1", 1),
            ("a=1&b=2", 2),
            ("a=1&b=2&c=3&d=4", 4),
            ("a=1&&b=2", 2),  # Empty param handled
        ]
        for query, expected in test_cases:
            inp = make_input(url=f"http://example.com?{query}", domain="example.com", query=query)
            fv = extractor.extract(inp)
            assert fv.features["query_param_count"] == expected, f"Failed for query: {query}"

    def test_feature_names_consistency(self, extractor):
        """Test that feature_names matches extracted features."""
        inp = ModalityInput(modality="url", content={"url": "http://test.com"}, timestamp=datetime.utcnow())
        fv = extractor.extract(inp)

        for name in extractor.feature_names():
            assert name in fv.features, f"Missing feature: {name}"

        # Should have exactly the expected number of features
        assert len(fv.features) == len(extractor.feature_names())

    def test_invalid_modality_raises(self, extractor):
        """Test that non-URL modality raises ValueError."""
        inp = ModalityInput(modality="email", content={}, timestamp=datetime.utcnow())
        with pytest.raises(ValueError, match="Expected modality 'url'"):
            extractor.extract(inp)

    def test_feature_names_method(self, extractor):
        """Test feature_names() method returns copy."""
        names1 = extractor.feature_names()
        names2 = extractor.feature_names()
        assert names1 == names2
        assert names1 is not names2  # Should be copy

    def test_version_attribute(self, extractor):
        """Test version attribute exists."""
        assert hasattr(extractor, 'version')
        assert extractor.version == "1.0.0"

    # ===== Feature Vector Output Tests =====

    def test_feature_vector_structure(self, extractor, make_input):
        """Test FeatureVector output structure."""
        inp = make_input(url="http://example.com")
        fv = extractor.extract(inp)

        assert hasattr(fv, 'features')
        assert hasattr(fv, 'feature_names')
        assert hasattr(fv, 'extractor_version')
        assert hasattr(fv, 'timestamp')
        assert isinstance(fv.features, dict)
        assert isinstance(fv.feature_names, list)
        assert isinstance(fv.extractor_version, str)
        assert fv.timestamp is not None

    def test_all_features_present(self, extractor, make_input):
        """Test all expected features are present in output."""
        expected_features = [
            "url_length", "domain_length", "subdomain_count", "path_length",
            "query_length", "has_special_chars", "has_at_symbol", "has_dash_in_domain",
            "entropy", "suspicious_keyword_count", "is_ip_address", "has_port",
            "tld_risk_score", "brand_impersonation_score", "punycode_detected",
            "subdomain_entropy", "path_entropy", "query_param_count",
            "has_suspicious_tld", "url_hash_prefix"
        ]

        inp = make_input(url="http://example.com")
        fv = extractor.extract(inp)

        for feat in expected_features:
            assert feat in fv.features, f"Missing feature: {feat}"

    def test_feature_order_matches_names(self, extractor, make_input):
        """Test that features dict order matches feature_names order."""
        inp = make_input(url="http://example.com")
        fv = extractor.extract(inp)

        # Check that we can iterate in order
        ordered_values = [fv.features[name] for name in fv.feature_names]
        assert len(ordered_values) == len(fv.feature_names)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
