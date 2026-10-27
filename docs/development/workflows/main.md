# main.py — FastAPI Orchestration and Pipeline Entry Point

**Objective:** FastAPI webhook service that receives Wazuh alerts, orchestrates the full analysis pipeline (parse → enrich → reason → route → log), and returns the complete verdict to the caller. The sole entry point; all downstream tools are called here synchronously.

**Input contract:** `POST /analyze`
- Accepts an arbitrary Wazuh alert JSON object via `Body(...)`.
- Field contract guaranteed by Wazuh (direct from webhook, no transformation by Shuffle).
- Expected keys: `rule.id`, `rule.description`, `decoder.name`, `data.srcip`, `data.dstip`, (optional) `GeoLocation`, and alert metadata.

**Output contract:** 
HTTP 200 with complete parsed dict:
```json
{
  "parsed_alert": {...},
  "iocs": [...],
  "enrichment": {...},
  "nature_category": "public_attack | internal_movement | informational | unknown",
  "verdict": {...},
  "reasoner_meta": {...},
  "routing": {...}
}
```
- `parsed_alert`: alert_type, rule_id, rule_description, is_known_fp_candidate.
- `iocs`: extracted IOCs (filtered for public IPs).
- `enrichment`: enriched IOC data from VirusTotal / AbuseIPDB (ok or cached values only).
- `verdict`: verdict (TRUE_POSITIVE/FALSE_POSITIVE/NEEDS_REVIEW), confidence, risk_score, mitre, next_action.
- `reasoner_meta`: model, latency_ms, status (ok|fallback), fallback_reason (if fallback).
- `routing`: action (create_case|discard), send_to_shuffle (bool), reason (audit trail for logger).

**Public endpoints:**
```python
POST /analyze(payload: dict = Body(...)) -> dict
GET /health() -> dict
```

---

## Design highlights

**Synchronous pipeline in a threadpool:**
FastAPI runs all endpoint code in a threadpool (via `Starlette.run_in_threadpool` for sync defs), so blocking calls to VirusTotal, AbuseIPDB, and Ollama do not stall the event loop. Module-level singletons (enricher clients with RateLimiter/TTLCache and Ollama client) are thread-safe and shared across requests, preserving VirusTotal's ~4 req/min rate-limit token bucket and response cache across alerts (critical for high-volume v1 deployment).

**Dependency injection via FastAPI:**
- `get_pipeline()` dependency builds or injects enricher_clients and ollama_client.
- Tests override `app.dependency_overrides[get_pipeline]` to inject mocks.
- Module-level singletons `_ENRICHER_CLIENTS` and `_OLLAMA_CLIENT` built at import, reused across all requests.

**Never-lose-an-alert resilience:**
- Main orchestration wrapped in `try/except Exception`.
- Any unexpected error (parser crash, OOM, Ollama timeout, etc.) is caught and returns HTTP 200 with a conservative `create_case` escalation body (never 500).
- Best-effort defensive-escalation CSV audit row written (wrapped, never re-raises).
- Honors the mandatory "every alert logged" invariant even on catastrophic pipeline failure.

**Defensive escalation path:**
If the pipeline fails unexpectedly, Prism returns:
```json
{
  "routing": {
    "action": "create_case",
    "send_to_shuffle": true,
    "reason": "Automatic escalation due to pipeline failure"
  }
}
```
(A minimal parsed dict to prevent null-ref downstream in Shuffle; the full alert is best-effort logged to CSV with the escalation reason.)

**Configuration:**
- `load_dotenv()` at module import (reads `.env`).
- `logging.basicConfig(INFO)` for structured logging.
- `SERVICE_HOST` and `SERVICE_PORT` from env (defaults: 0.0.0.0:8000).
- `OLLAMA_TIMEOUT`, `LOG_PATH`, API keys from env.

**Main entry:**
```python
if __name__ == "__main__":
    uvicorn.run(app, host=SERVICE_HOST, port=SERVICE_PORT)
```

---

## Running tests

```bash
"C:/Users/usuario/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m pytest tests/test_main.py -q
```

**Coverage:** 9 tests (fully deterministic, all external calls mocked via dependency injection).
- POST /analyze with valid parsed fixture (1 test).
- GET /health (1 test).
- Sync endpoint behavior (runs in threadpool, no blocking I/O on event loop) (1 test).
- Dependency injection: enricher_clients and ollama_client mocked (1 test).
- Full-pipeline orchestration: parse → enrich → reason → route → log (1 test).
- Output contract validation (all required keys present) (1 test).
- Defensive escalation on pipeline exception (1 test).
- Audit row written on escalation (1 test).
- HTTP 200 even on failure (1 test).

**Total test suite:** 180 tests passing (parser 25 + enricher 21 + reasoner 46 + router 29 + logger 23 + pipeline 2 + main 9).

---

## Edge cases handled

1. **Empty/null payload** → parser handles, router/logger defensive fallback.
2. **Parser crash** → caught in main try/except, returns escalation 200 with create_case.
3. **Enricher timeout / API error** → enricher continues (failure non-blocking), returns cached/"ok" fields only.
4. **Ollama timeout / connection refused** → reasoner fallback to NEEDS_REVIEW/LOW, does not crash.
5. **CSV write fails (disk full, permission denied)** → logger catches, logs to stderr, does not raise (pipeline continues).
6. **Concurrent requests** → enricher RateLimiter + TTLCache, logger lock, reasoner session all thread-safe.
7. **Module-level singleton initialization fails** → FastAPI init fails hard (by design; don't mask config errors).
8. **Health check during pipeline crash** → /health returns 200 (independent; never blocked by request handlers).

---

## Implementation notes

- **Singletons built at import:** `_ENRICHER_CLIENTS = _enricher_module._build_default_clients()`, `_OLLAMA_CLIENT = _reasoner_module._build_default_client()` at module level, passed to `get_pipeline()` dependency.
- **Thread safety:** Enricher (RateLimiter, TTLCache, requests.Session) and Ollama client (httpx.Client session reuse) are thread-safe. Logger uses `threading.Lock`. All safe under FastAPI's threadpool model.
- **No new runtime deps:** fastapi/uvicorn already in requirements.txt. Added `httpx>=0.27` for TestClient/Starlette (a clean clone would otherwise ImportError).
- **Defensive last-resort:** minimal escalation dict is *always* built so downstream (Shuffle, logger) never sees None.

---

## Scope (v1)

`main.py` ONLY:
- Accepts webhook POST from Wazuh (direct, no transformation).
- Orchestrates tools in strict order: parse → enrich → reason → route → log.
- Returns the full parsed dict (confirmed user decision).
- Never sends HTTP to Shuffle (item 7; Shuffle integration is separate).
- Logs all alerts to CSV (logger.py responsibility).

Does NOT:
- Transform or validate Wazuh field structure (that's parser's job).
- Create TheHive cases (v2).
- Aggregate metrics (v2).
