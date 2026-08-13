import asyncio
import pytest
from app.modules.whois_checker import check_domain, invalidate_cache

@pytest.fixture(autouse=True)
def clear_whois_cache():
    """Ensure tests don't pollute each other's cache."""
    invalidate_cache()
    yield
    invalidate_cache()

from unittest.mock import patch

@pytest.mark.asyncio
@patch("app.modules.whois_checker.whois.whois")
async def test_check_domain_known_good(mock_whois):
    from datetime import datetime, timedelta, timezone
    class DummyWhois:
        pass
    d = DummyWhois()
    d.creation_date = datetime.now(timezone.utc) - timedelta(days=4000)
    mock_whois.return_value = d

    """Test a known domain resolves correctly and gets cached."""
    result = await check_domain("google.com")
    
    assert result["score"] <= 0.18  # Safe/Low risk for ancient domain
    assert result["age_days"] is not None
    assert result["age_days"] > 3650
    assert result["label"] == "Safe"

@pytest.mark.asyncio
async def test_check_domain_cache_warming(monkeypatch):
    """Test that a second request to the same domain is near-instantaneous."""
    import time
    
    # Mock the slow network call
    def mock_whois(domain):
        time.sleep(0.5)  # Simulate a half-second network lookup
        class DummyWhois:
            pass
        d = DummyWhois()
        from datetime import datetime
        d.creation_date = datetime(2000, 1, 1)
        return d
        
    import whois
    monkeypatch.setattr(whois, "whois", mock_whois)
    
    # First request
    start = time.time()
    res1 = await check_domain("fake-domain.com")
    duration1 = time.time() - start
    
    # Second request
    start = time.time()
    res2 = await check_domain("fake-domain.com")
    duration2 = time.time() - start
    
    assert res1["age_days"] == res2["age_days"]
    assert res1["age_days"] is not None
    assert duration1 >= 0.5
    assert duration2 < 0.05  # Cache hit should be instant

@pytest.mark.asyncio
async def test_check_domain_graceful_timeout(monkeypatch):
    """Test that the timeout forcefully interrupts a hanging WHOIS lookup."""
    async def mock_to_thread(*args, **kwargs):
        # Simulate a network hang that exceeds the 5.0s timeout
        await asyncio.sleep(10.0)
        return 50
        
    monkeypatch.setattr(asyncio, "to_thread", mock_to_thread)
    
    result = await check_domain("hang.example.com")
    
    assert result["age_days"] is None
    assert result["score"] == 0.50
    assert result["label"] == "Unknown"
