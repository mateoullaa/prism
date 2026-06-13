# enricher.md — External IOC Intelligence Enrichment

**Objective:** Enrich external IPs (from parser output) with VirusTotal and AbuseIPDB reputation intel. Replaces Cortex. v1 enriches IPs only; hashes and CVEs are marked external=False and not enriched.

**Input:** Parser output dict; reads `parsed["iocs"]` for entries with `type=="ip"` and `external==True`.

**Output contract:**
```json
{
  "enrichment": {
    "ip_1": {
      "virustotal": {"status": "ok|cached|rate_limited|skipped|error", "malicious": int, "suspicious": int, "reputation": int},
      "abuseipdb": {"status": "ok|cached|rate_limited|skipped|error", "abuse_confidence_score": int, "total_reports": int, "country_code": str, "is_whitelisted": bool}
    },
    "ip_2": {...}
  }
}
```

If no external IOCs exist → `enrichment == {}` with **zero** external API calls.

---

## Design highlights

**Rate limiting (fail-fast token bucket):**
- VirusTotal: 4 req/min (capacity 4 tokens, refilled every 60s; ~1 token every 15s average).
- AbuseIPDB: 60 req/min (capacity 60 tokens, refilled every 60s; ~1 token every 1s average).
- `try_acquire()` returns `False` immediately if bucket empty; never blocks.
- Status "rate_limited" assigned if token unavailable.

**Caching (TTLCache, in-memory):**
- Default TTL: 3600s (1 hour).
- Only "ok" results cached; cached hits get status="cached".
- No cache persistence; reset per process.
- **CRITICAL for production:** cache + rate limiter only apply WITHIN one alert. `main.py` MUST hold module-level singletons (vt_client, abuse_client) and pass via `clients=` param, else VT 4 req/min limit is not enforced across alerts.

**Concurrency:**
- ThreadPoolExecutor (max_workers=4) queries both APIs in parallel.
- Fail-safe: per-source error handling; no exception propagates. All errors logged, contained.

**Secrets (via .env):**
- `VIRUSTOTAL_API_KEY` (required for VirusTotal).
- `ABUSEIPDB_API_KEY` (required for AbuseIPDB).
- Missing key → status="skipped" for that source; no HTTP call.

---

## API details

**VirusTotal (GET v3/ip_addresses/{ip}):**
- Header: `x-apikey: <key>`.
- Response → extract `data.attributes.last_analysis_stats`: malicious, suspicious, undetected.
- Response → extract `data.attributes.reputation`: direct integer reputation score (not calculated locally).

**AbuseIPDB (GET v2/check):**
- Params: `ipAddress={ip}`, `maxAgeInDays=90`.
- Headers: `Key: <key>`, `Accept: application/json`.
- Response → extract abuse_confidence_score, total_reports, usage_type, country_code, is_whitelisted.

---

## Running tests

```bash
"C:/Users/usuario/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m pytest tests/test_enricher.py -v
```

**Coverage:** 21 tests (mocked HTTP, rate limiting, caching, parallel execution, error handling).

---

## Implementation notes

- No external API calls if no external IOCs detected (efficiency).
- Thread-safe RateLimiter + TTLCache (both use locks).
- Errors (network, JSON parse, missing key) are caught and logged; status set to "error" or "skipped".
- Output always valid JSON; ready for reasoner.
- Requests library + python-dotenv (in requirements.txt).
