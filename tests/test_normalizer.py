import pytest
from app.core.normalizer import normalize_url

def test_normalize_valid_url():
    res = normalize_url("https://www.example.com/path?query=1")
    assert res["domain"] == "www.example.com"
    assert res["tld"] == "com"
    assert res["path"] == "/path"
    assert res["query"] == "query=1"
    assert res["scheme"] == "https"

def test_normalize_missing_schema():
    res = normalize_url("example.org")
    assert res["domain"] == "example.org"
    assert res["scheme"] == "http"
    assert res["url"].startswith("http://")

def test_normalize_whitespace_and_case():
    res = normalize_url("  HTTPS://Example.COM/Path  ")
    assert res["domain"] == "example.com"
    # Note: path isn't typically lowercased as it can be case-sensitive, but domain is
    assert res["scheme"] == "https"

def test_normalize_empty():
    with pytest.raises(ValueError):
        normalize_url("")
