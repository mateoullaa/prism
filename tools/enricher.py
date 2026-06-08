"""
enricher.py — IOC enrichment for the AI triage pipeline.

Queries VirusTotal and AbuseIPDB for external IPs extracted by the parser.
Thread-safe rate limiting (fail-fast token bucket) and in-memory TTL cache
prevent quota exhaustion and redundant API calls. All HTTP calls run in
parallel via a ThreadPoolExecutor.
"""

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RateLimiter — fail-fast token bucket
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe fail-fast token bucket rate limiter.

    ``try_acquire()`` returns ``True`` if a token is available and consumes it,
    or ``False`` immediately if the bucket is empty. Never blocks.
    Tokens are refilled in bulk once ``refill_window`` seconds have elapsed.
    """

    def __init__(self, capacity: int, refill_window: float) -> None:
        """
        Args:
            capacity: Max tokens in the bucket (also the full-refill amount).
            refill_window: Seconds after which the bucket is fully refilled.
        """
        self._capacity = capacity
        self._refill_window = refill_window
        self._tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        """Attempt to consume one token.

        Returns:
            ``True`` if a token was consumed, ``False`` if the bucket is empty.
        """
        with self._lock:
            now = time.monotonic()
            if now - self._last_refill >= self._refill_window:
                self._tokens = self._capacity
                self._last_refill = now
            if self._tokens > 0:
                self._tokens -= 1
                return True
            return False


# ---------------------------------------------------------------------------
# TTLCache — thread-safe in-memory cache
# ---------------------------------------------------------------------------


class TTLCache:
    """Thread-safe in-memory key→value cache with per-entry TTL.

    Expired entries are evicted lazily on ``get()``. Only successful results
    should be stored (callers are responsible for this convention).
    """

    def __init__(self, ttl: float = 3600.0) -> None:
        """
        Args:
            ttl: Time-to-live in seconds for each entry. Default 3600 s.
        """
        self._ttl = ttl
        self._store: dict[Any, tuple[Any, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any:
        """Return the cached value or ``None`` if absent or expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: Any, value: Any) -> None:
        """Store ``value`` under ``key`` with a TTL expiry."""
        with self._lock:
            self._store[key] = (value, time.monotonic() + self._ttl)


# ---------------------------------------------------------------------------
# VirusTotalClient
# ---------------------------------------------------------------------------


class VirusTotalClient:
    """Queries the VirusTotal v3 IP-addresses endpoint.

    All dependencies are injectable to enable deterministic unit tests.
    """

    _BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    def __init__(
        self,
        session: requests.Session,
        api_key: str,
        rate_limiter: RateLimiter,
        cache: TTLCache,
        timeout: float = 8.0,
    ) -> None:
        self._session = session
        self._api_key = api_key
        self._rate_limiter = rate_limiter
        self._cache = cache
        self._timeout = timeout

    def query(self, ip: str) -> dict:
        """Query VirusTotal for threat data about an IP address.

        Query order: cache → missing key → rate limit → HTTP GET.

        Args:
            ip: Public IP address to look up.

        Returns:
            Dict with ``status`` (ok|cached|rate_limited|skipped|error) and
            normalised fields on success: ``malicious``, ``suspicious``,
            ``reputation``.  Never raises.
        """
        # 1. Cache hit
        cached = self._cache.get(("virustotal", ip))
        if cached is not None:
            return {**cached, "status": "cached"}

        # 2. Missing API key
        if not self._api_key:
            return {"status": "skipped", "message": "VIRUSTOTAL_API_KEY not configured"}

        # 3. Rate limit (fail-fast)
        if not self._rate_limiter.try_acquire():
            return {"status": "rate_limited", "message": "VirusTotal rate limit reached"}

        # 4. HTTP request
        url = self._BASE_URL.format(ip=ip)
        try:
            resp = self._session.get(
                url,
                headers={"x-apikey": self._api_key},
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                return {"status": "error", "message": f"HTTP {resp.status_code}"}

            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result: dict = {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "reputation": attrs.get("reputation", 0),
            }
            self._cache.set(("virustotal", ip), result)
            return result

        except Exception as exc:
            logger.warning("VirusTotal query failed for %s: %s", ip, exc)
            return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# AbuseIPDBClient
# ---------------------------------------------------------------------------


class AbuseIPDBClient:
    """Queries the AbuseIPDB v2 check endpoint.

    All dependencies are injectable to enable deterministic unit tests.
    """

    _BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        session: requests.Session,
        api_key: str,
        rate_limiter: RateLimiter,
        cache: TTLCache,
        timeout: float = 8.0,
    ) -> None:
        self._session = session
        self._api_key = api_key
        self._rate_limiter = rate_limiter
        self._cache = cache
        self._timeout = timeout

    def query(self, ip: str) -> dict:
        """Query AbuseIPDB for abuse data about an IP address.

        Query order: cache → missing key → rate limit → HTTP GET.

        Args:
            ip: Public IP address to look up.

        Returns:
            Dict with ``status`` (ok|cached|rate_limited|skipped|error) and
            normalised fields on success: ``abuse_confidence_score``,
            ``total_reports``, ``country_code``, ``is_whitelisted``.
            Never raises.
        """
        # 1. Cache hit
        cached = self._cache.get(("abuseipdb", ip))
        if cached is not None:
            return {**cached, "status": "cached"}

        # 2. Missing API key
        if not self._api_key:
            return {"status": "skipped", "message": "ABUSEIPDB_API_KEY not configured"}

        # 3. Rate limit (fail-fast)
        if not self._rate_limiter.try_acquire():
            return {"status": "rate_limited", "message": "AbuseIPDB rate limit reached"}

        # 4. HTTP request
        try:
            resp = self._session.get(
                self._BASE_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                return {"status": "error", "message": f"HTTP {resp.status_code}"}

            data = resp.json().get("data", {})
            result: dict = {
                "status": "ok",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "is_whitelisted": data.get("isWhitelisted", False),
            }
            self._cache.set(("abuseipdb", ip), result)
            return result

        except Exception as exc:
            logger.warning("AbuseIPDB query failed for %s: %s", ip, exc)
            return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Default client factory
# ---------------------------------------------------------------------------


def _build_default_clients() -> tuple:
    """Build production clients from environment variables.

    VT bucket: 4 tokens / 60 s (free-tier limit).
    AbuseIPDB bucket: 60 tokens / 60 s (well within free-tier ~1000/day).
    Both clients share a single TTLCache (keys are namespaced by provider).
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")

    session = requests.Session()
    shared_cache = TTLCache(ttl=3600.0)

    vt_client = VirusTotalClient(
        session=session,
        api_key=vt_key,
        rate_limiter=RateLimiter(capacity=4, refill_window=60.0),
        cache=shared_cache,
    )
    abuse_client = AbuseIPDBClient(
        session=session,
        api_key=abuse_key,
        rate_limiter=RateLimiter(capacity=60, refill_window=60.0),
        cache=shared_cache,
    )
    return vt_client, abuse_client


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def enrich(parsed: dict, *, clients: tuple | None = None) -> dict:
    """Enrich external IPs in a parsed alert with VirusTotal and AbuseIPDB data.

    Collects unique external IPs from ``parsed["iocs"]`` (type="ip",
    external=True) and queries both providers in parallel. Results are stored
    under ``parsed["enrichment"]``.  If there are no external IPs the key is
    set to ``{}`` and no HTTP calls are made.

    Args:
        parsed: Output of ``parse_alert()``.  Must contain an ``"iocs"`` list.
        clients: Optional ``(vt_client, abuse_client)`` tuple for test
                 injection.  When ``None``, clients are built from env vars.

    Returns:
        The same ``parsed`` dict with ``"enrichment"`` added in-place.

    Example enrichment shape::

        parsed["enrichment"] = {
            "5.5.5.5": {
                "virustotal": {"status": "ok", "malicious": 3, ...},
                "abuseipdb":  {"status": "ok", "abuse_confidence_score": 100, ...},
            }
        }
    """
    iocs: list[dict] = parsed.get("iocs", [])
    external_ips: list[str] = list({
        ioc["value"]
        for ioc in iocs
        if ioc.get("type") == "ip" and ioc.get("external") is True
    })

    if not external_ips:
        parsed["enrichment"] = {}
        return parsed

    vt_client, abuse_client = clients if clients is not None else _build_default_clients()

    enrichment: dict[str, dict] = {ip: {} for ip in external_ips}

    with ThreadPoolExecutor(max_workers=4) as executor:
        future_map: dict = {}
        for ip in external_ips:
            future_map[executor.submit(vt_client.query, ip)] = (ip, "virustotal")
            future_map[executor.submit(abuse_client.query, ip)] = (ip, "abuseipdb")

        for future in as_completed(future_map):
            ip, provider = future_map[future]
            try:
                enrichment[ip][provider] = future.result()
            except Exception as exc:
                logger.error(
                    "Unexpected error enriching %s via %s: %s", ip, provider, exc
                )
                enrichment[ip][provider] = {"status": "error", "message": str(exc)}

    parsed["enrichment"] = enrichment
    return parsed
