from app.core.extractor import extract_features

def test_extract_features():
    normalized = {
        "url": "http://secure-login.example.com/update",
        "domain": "secure-login.example.com"
    }
    features = extract_features(normalized)
    
    assert features["url_length"] == 38
    assert features["domain_length"] == 24
    assert features["subdomain_count"] == 1
    assert features["has_special_chars"] is True
    assert features["suspicious_keywords"] == 3  # secure, login, update
    assert features["entropy"] > 0
