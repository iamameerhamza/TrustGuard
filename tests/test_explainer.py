import pytest
from app.core.explainer import explain

def test_explain_blacklisted():
    reasons = explain({}, is_blacklisted=True)
    assert len(reasons) == 1
    assert "known threat intelligence" in reasons[0]

def test_explain_safe():
    reasons = explain({"url_length": 10}, is_blacklisted=False, ml_score=0.1)
    assert len(reasons) == 1
    assert "10.0%" in reasons[0]

def test_explain_suspicious():
    features = {
        "suspicious_keywords": 2,
        "entropy": 4.6,
        "url_length": 80,
        "domain_length": 30,
        "subdomain_count": 3,
        "has_special_chars": True
    }
    reasons = explain(features, is_blacklisted=False, ml_score=0.95)
    assert len(reasons) == 7
    assert "2 suspicious keyword(s)" in reasons[0]
    assert "High character entropy (4.60)" in reasons[1]
    assert "unusually long (80" in reasons[2]
    assert "unusually long (30" in reasons[3]
    assert "high number of subdomains (3)" in reasons[4]
    assert "suspicious special characters" in reasons[5]
    assert "95.0%" in reasons[6]
