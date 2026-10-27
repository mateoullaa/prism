# logger.md — Metrics CSV + Audit Trail

**Objective:** Append every alert (including discarded FALSE_POSITIVEs) to a CSV file with a complete audit trail. Logger never breaks the pipeline; I/O errors are caught and logged, and the record is still returned. The reason field from the router is persisted — no discarded alert disappears without a trace.

**Input contract:** Parsed dict with keys:
- `parsed["parsed_alert"]` (from parser): alert_type, rule_id, rule_description
- `parsed["routing"]` (from router): action, send_to_shuffle, reason
- `parsed["verdict"]` (from reasoner): verdict, confidence, risk_score, mitre
- `parsed["reasoner_meta"]` (from reasoner): model, latency_ms
- `parsed["nature_category"]` (from parser): categorization axis value

**Output contract:**
Appends ONE CSV row and returns a dict with all 16 column values (mirrors the CSV row):
```python
{
  "timestamp": str,
  "alert_type": str,
  "nature_category": str,
  "rule_id": str,
  "rule_description": str,
  "verdict": str,
  "confidence": str,
  "risk_score": str,
  "mitre_id": str,
  "action": str,
  "send_to_shuffle": str (True/False),
  "status": str,
  "latency_ms": str,
  "model": str,
  "is_known_fp_candidate": str (True/False),
  "reason": str (audit trail from router)
}
```

**Public function:**
```python
log_alert(parsed: dict, *, log_path: str | None = None, timestamp: str | None = None) -> dict
```
- `log_path`: injectable (overrides LOG_PATH env var). Defaults to `./metrics/triage_log.csv`.
- `timestamp`: injectable (for deterministic tests). Defaults to current UTC ISO-8601.
- Never raises. I/O errors are caught, logged to stderr, and the record is still returned.
- Thread-safe: module-level `threading.Lock` for FastAPI concurrency.

---

## CSV schema

**Fixed column order** (single `_COLUMNS` constant, 16 fields):
1. `timestamp` — UTC ISO-8601 from input or auto-generated
2. `alert_type` — from parser (FAILED_LOGIN, WINDOWS_SPP_ERROR, etc.)
3. `nature_category` — public_attack / internal_movement / informational / unknown
4. `rule_id` — rule ID or "" (never "None")
5. `rule_description` — rule description or ""
6. `verdict` — TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW
7. `confidence` — HIGH / MEDIUM / LOW / UNKNOWN
8. `risk_score` — int 1–10 coerced to string
9. `mitre_id` — from verdict.mitre["id"] if dict, else "" (missing-id → "")
10. `action` — create_case / discard
11. `send_to_shuffle` — "True" / "False" (boolean as string)
12. `status` — "complete" or "" (reserved for future edge cases; currently always complete)
13. `latency_ms` — from reasoner_meta or ""
14. `model` — Ollama model name or ""
15. `is_known_fp_candidate` — "True" / "False" (from parser hint, if present)
16. `reason` — audit trail from router (why the decision was made)

**Header behavior:**
- Header is written ONLY when the CSV file is new or empty (stat check inside lock, no TOCTOU).
- Under concurrency, the first caller to write wins; subsequent callers skip the header.

---

## Design highlights

**Mandatory audit trail for ALL alerts:**
Every alert is logged, including discarded FALSE_POSITIVEs. The `reason` field persists the router's decision context — verdict, confidence, fallback/downgrade notes. This ensures:
- Transparency: SOC can audit why any alert was discarded.
- Learning: patterns in discarded FPs (e.g., all from Rule 60602) are visible.
- Accountability: no silent alert disappearance.

**Defensive extraction:**
- `isinstance` checks for all fields (dict, bool, int, str).
- `.get()` with fallback defaults (not crash on missing keys).
- `_safe()` helper coalesces None to "" (rule_id=None → "", not "None").
- Booleans serialized as "True"/"False" strings (CSV-compatible, human-readable).

**Thread safety:**
Module-level `threading.Lock` serializes file writes. FastAPI's concurrent requests are queued; CSV remains consistent.

**Pipeline resilience:**
All I/O errors (OSError, IOError, permission denied, disk full) are caught in a try/except, logged to stderr, and the record dict is returned anyway. Reasoner/router never see a logger failure.

---

## Running tests

```bash
"C:/Users/usuario/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m pytest tests/test_logger.py -q
```

**Coverage:** 23 tests (fully deterministic, no network or server).
- Basic logging: minimal parsed dict, all fields populated (2 tests).
- CSV header: creation on new file, skip on second call (2 tests).
- Defensive extraction: missing rule_id → "", missing mitre dict → "" (4 tests).
- Boolean serialization: is_known_fp_candidate / send_to_shuffle as "True"/"False" (2 tests).
- Timestamp injection: override with custom timestamp (2 tests).
- log_path injection: override with temp path (2 tests).
- I/O error handling: simulated OSError, record still returned, no raise (3 tests).
- False Positive audit trail: windows_spp_error.json parsed → FALSE_POSITIVE verdict → row with reason + action=discard + send_to_shuffle="False", persisted (2 tests).
- Concurrency: ThreadPoolExecutor with 10 concurrent calls, all rows appended, no header duplication or data loss (2 tests).

**Total test suite:** 171 tests passing (parser 25 + enricher 21 + reasoner 46 + router 29 + logger 23 + pipeline 2).

---

## Edge cases handled

1. **Empty parsed dict** → all fields coalesce to ""; row still written with defaults.
2. **Missing routing key** → reason="", action="", send_to_shuffle="".
3. **Missing verdict dict** → verdict="", confidence="", risk_score="", mitre_id="".
4. **verdict.mitre not a dict** (e.g., None) → mitre_id="" (not crash).
5. **verdict.mitre["id"] missing** → mitre_id="" (not crash).
6. **rule_id=None** → "" (not the string "None").
7. **Booleans in parsed** (send_to_shuffle, is_known_fp_candidate) → serialized as "True"/"False" strings.
8. **OSError / permission denied / disk full** → caught, logged to stderr; record dict returned; pipeline continues.
9. **CSV file deleted between reads** → row still appended (file auto-created); no crash.
10. **Concurrent writes** → lock serializes; header written once; all rows appended in order.

---

## Implementation notes

- `load_dotenv()` called once at module import; `LOG_PATH` env var read lazily in `log_alert()`.
- Timestamp defaults to `datetime.utcnow().isoformat()` if not injected.
- `_safe(value)` → `value if value is not None else ""` (None-coalescer for any type).
- `_bool_str(value)` → `"True" if value else "False"` (defensive boolean serializer).
- CSV row built as a dict (mirrors the return value), then serialized to `csv.DictWriter`.
- No external I/O except file write. No network, no database.

---

## Scope (v1)

Logger ONLY appends CSV rows. It does NOT:
- Aggregate metrics (that's post-v1).
- Push to external systems (TheHive, SIEM dashboard).
- Filter or modify alerts (router decided already).

Responsible for: persisting audit trail, resilience, and thread safety.
