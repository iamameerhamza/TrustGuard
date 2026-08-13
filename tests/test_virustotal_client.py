import asyncio
import json
import time

import pytest

from modules.intake.virustotal_client import VTSignal, VirusTotalClient


class MockRedis:
    def __init__(self):
        self.cache = {}

    def get(self, key):
        return self.cache.get(key)

    def setex(self, key, ttl, value):
        self.cache[key] = value
        self.cache[f"{key}:ttl"] = ttl


class MockResponse:
    def __init__(self, status, payload=None, text_body=""):
        self.status = status
        self._payload = payload or {}
        self._text_body = text_body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None

    async def json(self):
        return self._payload

    async def text(self):
        return self._text_body


class MockSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError("Unexpected VirusTotal request")
        return MockResponseContext(self.responses.pop(0))

    async def close(self):
        self.closed = True


class MockResponseContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None


def _run(coro):
    return asyncio.run(coro)


def _make_client(redis_client=None, responses=None, **kwargs):
    redis_client = redis_client or MockRedis()
    session = MockSession(responses or [])
    client = VirusTotalClient("test_api_key", redis_client, session=session, **kwargs)
    return client, session, redis_client


def _make_vt_payload(malicious=0, suspicious=0, harmless=0, undetected=0, timeout=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": timeout,
                }
            }
        }
    }


def test_canonical_url_normalization_preserves_www_and_strips_default_port():
    client, _, _ = _make_client()

    canonical_one = client._canonicalize_url("https://www.example.com:443/path/")
    canonical_two = client._canonicalize_url("https://www.example.com/path")
    canonical_three = client._canonicalize_url("https://example.com/path")

    assert canonical_one == "https://www.example.com/path"
    assert canonical_one == canonical_two
    assert canonical_one != canonical_three


def test_cache_key_is_stable_for_equivalent_urls():
    client, _, _ = _make_client()

    key_one = client._cache_key(client._canonicalize_url("http://example.com/"))
    key_two = client._cache_key(client._canonicalize_url("http://example.com"))

    assert key_one == key_two


def test_vtsignal_parsing_round_trips_new_fields():
    sample = {
        "url": "https://example.com",
        "state": "scored",
        "score": 42.5,
        "malicious": 2,
        "suspicious": 1,
        "engines_total": 10,
        "engines_scored": 7,
        "engines": {"kaspersky": True},
        "cache_key": "abc123",
        "fetched_at": 123.4,
        "raw_stats": {"malicious": 2, "suspicious": 1},
    }

    signal = VTSignal.from_dict(sample)

    assert signal.url == "https://example.com"
    assert signal.state == "scored"
    assert signal.score == 42.5
    assert signal.malicious == 2
    assert signal.engines == {"kaspersky": True}
    assert signal.to_dict()["cache_key"] == "abc123"


def test_cache_hit_returns_cached_signal_without_network():
    client, session, redis_client = _make_client()
    cached_signal = VTSignal(
        url="https://example.com/",
        state="scored",
        score=12.5,
        malicious=1,
        suspicious=0,
        harmless=17,
        undetected=0,
        timeout=0,
        engines_total=18,
        engines_scored=18,
        cache_key=client._cache_key(client._canonicalize_url("https://example.com")),
        fetched_at=time.time(),
        raw_stats={"malicious": 1, "harmless": 17, "undetected": 0, "timeout": 0},
    )
    redis_client.setex(
        cached_signal.cache_key,
        21600,
        json.dumps({"signal": cached_signal.to_dict(), "cached_at": cached_signal.fetched_at}),
    )

    result = _run(client.scan_url("https://example.com/"))

    assert result.state == "scored"
    assert result.score == 12.5
    assert session.calls == []


def test_cache_miss_fetches_and_populates_cache():
    payload = _make_vt_payload(malicious=2, suspicious=1, harmless=15)
    client, session, redis_client = _make_client(responses=[MockResponse(200, payload)])

    result = _run(client.scan_url("https://example.com/path/"))

    assert result.state == "scored"
    assert result.score == 13.89
    cache_key = client._cache_key(client._canonicalize_url("https://example.com/path/"))
    assert cache_key in redis_client.cache
    assert session.calls[0][0].startswith("https://www.virustotal.com/api/v3/urls/")


def test_not_yet_scanned_for_404():
    client, _, _ = _make_client(responses=[MockResponse(404, text_body="not found")])

    result = _run(client.scan_url("https://example.com"))

    assert result.state == "not_yet_scanned"
    assert result.score == 0.0


def test_error_for_malformed_response():
    client, _, _ = _make_client(
        responses=[MockResponse(200, {"data": {"attributes": {"last_analysis_stats": "bad"}}})]
    )

    result = _run(client.scan_url("https://example.com"))

    assert result.state == "error"
    assert result.score == 0.0


def test_zero_engines_maps_to_not_yet_scanned():
    client, _, _ = _make_client(responses=[MockResponse(200, _make_vt_payload())])

    result = _run(client.scan_url("https://example.com"))

    assert result.state == "not_yet_scanned"
    assert result.score == 0.0


def test_all_undetected_maps_to_not_yet_scanned():
    client, _, _ = _make_client(responses=[MockResponse(200, _make_vt_payload(undetected=24))])

    result = _run(client.scan_url("https://example.com"))

    assert result.state == "not_yet_scanned"
    assert result.score == 0.0


def test_insufficient_coverage_below_floor():
    client, _, _ = _make_client(
        responses=[MockResponse(200, _make_vt_payload(malicious=1, harmless=16))],
        engine_floor=18,
    )

    result = _run(client.scan_url("https://example.com"))

    assert result.state == "insufficient_coverage"
    assert result.engines_total == 17


def test_threshold_boundary_hits_scored_at_floor():
    client, _, _ = _make_client(
        responses=[MockResponse(200, _make_vt_payload(malicious=1, harmless=17))],
        engine_floor=18,
    )

    result = _run(client.scan_url("https://example.com"))

    assert result.state == "scored"
    assert result.engines_total == 18


def test_single_outlier_engine_keeps_linear_score_low():
    client, _, _ = _make_client(responses=[MockResponse(200, _make_vt_payload(malicious=1, harmless=59))])

    result = _run(client.scan_url("https://example.com"))

    assert result.state == "scored"
    assert result.score == 1.67


def test_retry_logic_on_429_uses_backoff_and_eventual_success(monkeypatch):
    client, session, _ = _make_client(
        responses=[
            MockResponse(429, text_body="rate limited"),
            MockResponse(429, text_body="rate limited"),
            MockResponse(200, _make_vt_payload(malicious=1, harmless=17)),
        ],
        max_retries=4,
    )

    async def fake_sleep(delay):
        return None

    monkeypatch.setattr("modules.intake.virustotal_client.asyncio.sleep", fake_sleep)

    result = _run(client.scan_url("https://example.com"))

    assert len(session.calls) == 3
    assert result.state == "scored"


def test_cache_key_keeps_www_distinct_by_choice():
    client, _, _ = _make_client()

    apex_key = client._cache_key(client._canonicalize_url("https://example.com"))
    www_key = client._cache_key(client._canonicalize_url("https://www.example.com"))

    assert apex_key != www_key