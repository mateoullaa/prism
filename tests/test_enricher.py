"""
tests/test_enricher.py — Pytest suite for tools/enricher.py.

All tests are deterministic; no network or server dependencies.
External HTTP calls are replaced by injected mock sessions/clients.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

# Ensure the repo root is on the path so tools.* is importable.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.enricher import (  # noqa: E402
    AbuseIPDBClient,
    RateLimiter,
    TTLCache,
    VirusTotalClient,
    enrich,
)
from tools.parser import parse_alert  # noqa: E402

FIXTURES_DIR = REPO_ROOT / "data" / "sample_alerts"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_fixture(name: str) -> dict:
    """Load a JSON fixture by filename from the sample_alerts directory."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    """Build a mock requests.Response with given JSON body and status."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    return resp


def _vt_client(
    session: MagicMock | None = None,
    api_key: str = "test-vt-key",
    rate_limiter: RateLimiter | None = None,
    cache: TTLCache | None = None,
) -> VirusTotalClient:
    """Build a VirusTotalClient with injectable test defaults."""
    return VirusTotalClient(
        session=session or MagicMock(),
        api_key=api_key,
        rate_limiter=rate_limiter or RateLimiter(capacity=100, refill_window=60.0),
        cache=cache or TTLCache(ttl=3600.0),
    )


def _abuse_client(
    session: MagicMock | None = None,
    api_key: str = "test-abuse-key",
    rate_limiter: RateLimiter | None = None,
    cache: TTLCache | None = None,
) -> AbuseIPDBClient:
    """Build an AbuseIPDBClient with injectable test defaults."""
    return AbuseIPDBClient(
        session=session or MagicMock(),
        api_key=api_key,
        rate_limiter=rate_limiter or RateLimiter(capacity=100, refill_window=60.0),
        cache=cache or TTLCache(ttl=3600.0),
    )


# ---------------------------------------------------------------------------
# Canonical API response bodies
# ---------------------------------------------------------------------------

VT_JSON = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 3,
                "suspicious": 1,
                "harmless": 50,
                "undetected": 10,
            },
            "reputation": -12,
        }
    }
}

ABUSE_JSON = {
    "data": {
        "abuseConfidenceScore": 100,
        "totalReports": 42,
        "countryCode": "DE",
        "isWhitelisted": False,
    }
}


# ---------------------------------------------------------------------------
# 1. VirusTotal success parsing
# ---------------------------------------------------------------------------


def test_vt_success_normalises_fields():
    """VirusTotalClient.query() returns correctly normalised malicious/suspicious/reputation."""
    session = MagicMock()
    session.get.return_value = _mock_response(VT_JSON)
    client = _vt_client(session=session)

    result = client.query("5.5.5.5")

    assert result["status"] == "ok"
    assert result["malicious"] == 3
    assert result["suspicious"] == 1
    assert result["reputation"] == -12


# ---------------------------------------------------------------------------
# 2. AbuseIPDB success parsing
# ---------------------------------------------------------------------------


def test_abuseipdb_success_normalises_fields():
    """AbuseIPDBClient.query() returns correctly normalised abuse/report/country fields."""
    session = MagicMock()
    session.get.return_value = _mock_response(ABUSE_JSON)
    client = _abuse_client(session=session)

    result = client.query("5.5.5.5")

    assert result["status"] == "ok"
    assert result["abuse_confidence_score"] == 100
    assert result["total_reports"] == 42
    assert result["country_code"] == "DE"
    assert result["is_whitelisted"] is False


# ---------------------------------------------------------------------------
# 3. enrich() on real parser output — SSH fixture
# ---------------------------------------------------------------------------


def test_enrich_ssh_fixture_queries_both_providers():
    """enrich() queries both VT and AbuseIPDB for the external IP in the SSH fixture."""
    parsed = parse_alert(load_fixture("ssh_attack.json"))
    assert parsed["has_external_iocs"] is True

    vt_sess = MagicMock()
    vt_sess.get.return_value = _mock_response(VT_JSON)
    abuse_sess = MagicMock()
    abuse_sess.get.return_value = _mock_response(ABUSE_JSON)

    result = enrich(parsed, clients=(_vt_client(session=vt_sess), _abuse_client(session=abuse_sess)))

    assert "enrichment" in result
    assert "5.5.5.5" in result["enrichment"]
    entry = result["enrichment"]["5.5.5.5"]
    assert entry["virustotal"]["status"] == "ok"
    assert entry["abuseipdb"]["status"] == "ok"
    assert entry["virustotal"]["malicious"] == 3
    assert entry["abuseipdb"]["abuse_confidence_score"] == 100


# ---------------------------------------------------------------------------
# 4. No external IOC → enrichment == {}, query() must NOT be called
# ---------------------------------------------------------------------------


def test_enrich_windows_fixture_skips_all_queries():
    """Windows fixture has no external IPs; no client.query() call must occur."""
    parsed = parse_alert(load_fixture("windows_logon.json"))
    assert parsed["has_external_iocs"] is False

    vt_mock = MagicMock()
    abuse_mock = MagicMock()

    result = enrich(parsed, clients=(vt_mock, abuse_mock))

    assert result["enrichment"] == {}
    vt_mock.query.assert_not_called()
    abuse_mock.query.assert_not_called()


def test_enrich_vulnerability_fixture_skips_all_queries():
    """Vulnerability fixture (CVE only) has no external IPs; no query() call must occur."""
    parsed = parse_alert(load_fixture("vulnerability.json"))
    assert parsed["has_external_iocs"] is False

    vt_mock = MagicMock()
    abuse_mock = MagicMock()

    result = enrich(parsed, clients=(vt_mock, abuse_mock))

    assert result["enrichment"] == {}
    vt_mock.query.assert_not_called()
    abuse_mock.query.assert_not_called()


# ---------------------------------------------------------------------------
# 5. Rate-limit fail-fast — no HTTP call when bucket is empty
# ---------------------------------------------------------------------------


def test_vt_rate_limit_returns_rate_limited_no_http_call():
    """When the VT rate limiter refuses, query returns rate_limited without HTTP."""
    rl = MagicMock()
    rl.try_acquire.return_value = False
    session = MagicMock()

    client = _vt_client(session=session, rate_limiter=rl)
    result = client.query("5.5.5.5")

    assert result["status"] == "rate_limited"
    session.get.assert_not_called()


def test_abuseipdb_rate_limit_returns_rate_limited_no_http_call():
    """When the AbuseIPDB rate limiter refuses, query returns rate_limited without HTTP."""
    rl = MagicMock()
    rl.try_acquire.return_value = False
    session = MagicMock()

    client = _abuse_client(session=session, rate_limiter=rl)
    result = client.query("5.5.5.5")

    assert result["status"] == "rate_limited"
    session.get.assert_not_called()


# ---------------------------------------------------------------------------
# 6. Cache hit — session.get called exactly once across two queries
# ---------------------------------------------------------------------------


def test_vt_cache_hit_session_called_once():
    """Second VT query for the same IP returns cached status; HTTP only called once."""
    session = MagicMock()
    session.get.return_value = _mock_response(VT_JSON)
    cache = TTLCache(ttl=3600.0)

    client = _vt_client(session=session, cache=cache)

    r1 = client.query("5.5.5.5")
    r2 = client.query("5.5.5.5")

    assert r1["status"] == "ok"
    assert r2["status"] == "cached"
    # Cached result still carries the normalised fields
    assert r2["malicious"] == 3
    session.get.assert_called_once()


def test_abuseipdb_cache_hit_session_called_once():
    """Second AbuseIPDB query for the same IP returns cached status; HTTP only called once."""
    session = MagicMock()
    session.get.return_value = _mock_response(ABUSE_JSON)
    cache = TTLCache(ttl=3600.0)

    client = _abuse_client(session=session, cache=cache)

    r1 = client.query("5.5.5.5")
    r2 = client.query("5.5.5.5")

    assert r1["status"] == "ok"
    assert r2["status"] == "cached"
    assert r2["abuse_confidence_score"] == 100
    session.get.assert_called_once()


# ---------------------------------------------------------------------------
# 7. API error — non-200 or exception → status="error", no exception propagates
# ---------------------------------------------------------------------------


def test_vt_non_200_returns_error():
    """VT non-200 response → status='error' with HTTP code in message, no exception."""
    session = MagicMock()
    session.get.return_value = _mock_response({}, status_code=403)

    result = _vt_client(session=session).query("5.5.5.5")

    assert result["status"] == "error"
    assert "403" in result["message"]


def test_vt_timeout_returns_error():
    """VT network timeout → status='error', no exception propagates."""
    session = MagicMock()
    session.get.side_effect = requests.exceptions.Timeout("timed out")

    result = _vt_client(session=session).query("5.5.5.5")

    assert result["status"] == "error"


def test_abuseipdb_non_200_returns_error():
    """AbuseIPDB non-200 response → status='error' with HTTP code in message, no exception."""
    session = MagicMock()
    session.get.return_value = _mock_response({}, status_code=429)

    result = _abuse_client(session=session).query("5.5.5.5")

    assert result["status"] == "error"
    assert "429" in result["message"]


def test_abuseipdb_connection_error_returns_error():
    """AbuseIPDB connection failure → status='error', no exception propagates."""
    session = MagicMock()
    session.get.side_effect = ConnectionError("connection refused")

    result = _abuse_client(session=session).query("5.5.5.5")

    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# 8. Parallel enrichment of multiple IPs
# ---------------------------------------------------------------------------


def test_enrich_two_distinct_ips_both_present():
    """enrich() with two distinct external IPs produces a result entry for each."""
    parsed = {
        "alert_type": "network",
        "rule_id": None,
        "rule_level": None,
        "rule_description": None,
        "agent_name": None,
        "iocs": [
            {"value": "1.1.1.1", "type": "ip", "external": True},
            {"value": "2.2.2.2", "type": "ip", "external": True},
        ],
        "has_external_iocs": True,
        "context": {},
        "is_known_fp_candidate": False,
    }

    vt_sess = MagicMock()
    vt_sess.get.return_value = _mock_response(VT_JSON)
    abuse_sess = MagicMock()
    abuse_sess.get.return_value = _mock_response(ABUSE_JSON)

    result = enrich(
        parsed,
        clients=(_vt_client(session=vt_sess), _abuse_client(session=abuse_sess)),
    )

    assert "1.1.1.1" in result["enrichment"]
    assert "2.2.2.2" in result["enrichment"]
    for ip in ("1.1.1.1", "2.2.2.2"):
        assert result["enrichment"][ip]["virustotal"]["status"] == "ok"
        assert result["enrichment"][ip]["abuseipdb"]["status"] == "ok"

    # One HTTP call per IP per provider → 2 calls each
    assert vt_sess.get.call_count == 2
    assert abuse_sess.get.call_count == 2


# ---------------------------------------------------------------------------
# 9. Missing API key → status="skipped", no HTTP call, no crash
# ---------------------------------------------------------------------------


def test_vt_missing_api_key_returns_skipped():
    """VirusTotalClient with empty api_key returns status='skipped' without any HTTP call."""
    session = MagicMock()
    result = _vt_client(session=session, api_key="").query("5.5.5.5")

    assert result["status"] == "skipped"
    session.get.assert_not_called()


def test_abuseipdb_missing_api_key_returns_skipped():
    """AbuseIPDBClient with empty api_key returns status='skipped' without any HTTP call."""
    session = MagicMock()
    result = _abuse_client(session=session, api_key="").query("5.5.5.5")

    assert result["status"] == "skipped"
    session.get.assert_not_called()


# ---------------------------------------------------------------------------
# Bonus: RateLimiter unit tests
# ---------------------------------------------------------------------------


def test_rate_limiter_allows_up_to_capacity():
    """Token bucket allows exactly ``capacity`` acquisitions before refusing."""
    rl = RateLimiter(capacity=3, refill_window=3600.0)
    assert rl.try_acquire() is True
    assert rl.try_acquire() is True
    assert rl.try_acquire() is True
    assert rl.try_acquire() is False  # bucket exhausted


def test_rate_limiter_refills_after_window(monkeypatch):
    """Token bucket refills to capacity after the refill window elapses."""
    base = 1000.0
    clock = [base]
    monkeypatch.setattr("tools.enricher.time.monotonic", lambda: clock[0])

    rl = RateLimiter(capacity=2, refill_window=60.0)
    rl.try_acquire()
    rl.try_acquire()
    assert rl.try_acquire() is False  # exhausted

    clock[0] = base + 61.0  # advance past the window
    assert rl.try_acquire() is True  # refilled


# ---------------------------------------------------------------------------
# Bonus: TTLCache unit tests
# ---------------------------------------------------------------------------


def test_ttl_cache_get_set():
    """TTLCache stores and retrieves a value within TTL."""
    cache = TTLCache(ttl=3600.0)
    cache.set("k", "v")
    assert cache.get("k") == "v"


def test_ttl_cache_miss_returns_none():
    """TTLCache returns None for absent keys."""
    assert TTLCache().get("missing") is None


def test_ttl_cache_expires(monkeypatch):
    """TTLCache evicts entries after TTL expires."""
    base = 1000.0
    clock = [base]
    monkeypatch.setattr("tools.enricher.time.monotonic", lambda: clock[0])

    cache = TTLCache(ttl=10.0)
    cache.set("k", "v")
    assert cache.get("k") == "v"

    clock[0] = base + 11.0  # past TTL
    assert cache.get("k") is None
