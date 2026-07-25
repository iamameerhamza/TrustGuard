import pytest
from app.core.rules import calculate_risk

def test_calculate_risk_safe():
    features = {
        "url_length": 20,
        "domain_length": 10,
        "subdomain_count": 0,
        "has_special_chars": False,
        "entropy": 3.0,
        "suspicious_keywords": 0
    }
    result = calculate_risk(features)
    assert result["risk_score"] == 0
    assert result["prediction"] == "safe"

def test_calculate_risk_suspicious():
    features = {
        "url_length": 80, # +10
        "domain_length": 15,
        "subdomain_count": 1,
        "has_special_chars": False,
        "entropy": 3.0,
        "suspicious_keywords": 2 # +30
    }
    result = calculate_risk(features)
    assert result["risk_score"] == 40
    assert result["prediction"] == "suspicious"

def test_calculate_risk_phishing():
    features = {
        "url_length": 80, # +10
        "domain_length": 30, # +15
        "subdomain_count": 3, # +20
        "has_special_chars": True, # +10
        "entropy": 3.0, # 0
        "suspicious_keywords": 2 # +30
    }
    result = calculate_risk(features)
    assert result["risk_score"] == 85
    assert result["prediction"] == "phishing"

def test_calculate_risk_cap():
    features = {
        "url_length": 100, # +10
        "domain_length": 30, # +10
        "subdomain_count": 5, # +20
        "has_special_chars": True, # +10
        "entropy": 5.0, # +20
        "suspicious_keywords": 10 # +150
    }
    result = calculate_risk(features)
    assert result["risk_score"] == 100
    assert result["prediction"] == "phishing"
