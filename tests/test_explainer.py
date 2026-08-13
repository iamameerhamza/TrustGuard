import pytest
from app.core.explainer import explain

def test_explain_blacklisted():
    reasons, _ = explain({}, is_blacklisted=True)
    assert len(reasons) == 1
    assert "known threat intelligence" in reasons[0]

def test_explain_safe():
    reasons, _ = explain({"url_length": 10}, is_blacklisted=False, ml_score=0.1)
    assert len(reasons) == 1
    assert "No suspicious traits" in reasons[0]

def test_explain_suspicious():
    features = {
        "suspicious_keywords": 2,
        "entropy": 4.6,
        "url_length": 80,
        "domain_length": 30,
        "subdomain_count": 3,
        "has_special_chars": True
    }
    reasons, _ = explain(features, is_blacklisted=False, ml_score=0.95)
    assert len(reasons) > 0
    assert any("95.0%" in r for r in reasons)
