# reasoner.md — LLM Verdict via Ollama

**Objective:** Run parsed and enriched alert through a local LLM (Ollama) to produce a SOC analyst verdict (TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW) with MITRE ATT&CK tags, risk score, and reasoning.

**Input:** Parser + enricher output dict with alert_type, IOCs, enrichment data, is_known_fp_candidate flag.

**Output contract:**
```json
{
  "verdict": {
    "classification": "TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW",
    "confidence": "HIGH|MEDIUM|LOW",
    "risk_score": 1-10,
    "mitre_tags": ["T1234", ...] or null,
    "reasoning": "string"
  },
  "reasoner_meta": {
    "status": "ok|timeout|error",
    "fallback_reason": "string or null",
    "model": "string",
    "latency_ms": int,
    "downgrade_note": "string or null"
  }
}
```

---

## Design highlights

**OllamaClient (injectable HTTP client):**
- Constructor: `OllamaClient(session, host, model, timeout)` — takes requests.Session for DI.
- `generate(prompt)` — POSTs to `{host}/api/generate` with `stream=false`, `format="json"`, `temperature=0`.
- Returns dict: `{status: "ok"|"timeout"|"error", response: str | null, latency_ms: int}`. Never raises; all errors caught.

**Prompt engineering:**
- Built from parsed output: alert_type, nature_category, rule fields, IOCs, enrichment summary (only "ok"/"cached" entries).
- Per-type context: full_log truncated to 500 chars to avoid token explosion.
- Includes is_known_fp_candidate hint (rule 60602 signal).
- Embedded JSON schema with literal enum values (strict, not prose).
- Conservative bias rules: alerts with external IPs + signatures → HIGH confidence TP; unknown/noise → LOW/MEDIUM.
- **Risk_score calibration rule:** FALSE_POSITIVE alerts must return risk_score 1–2; critical TRUE_POSITIVE attacks 8–10. Enforced in _PROMPT_PREFIX conservative-bias section.
- One few-shot example showing format.

**JSON validation & normalization:**
- `_parse_llm_json()`: defensive extraction (first `{` to last `}`); handles incomplete/malformed output.
- `_validate_verdict()`: uppercase enums, risk_score coerced to int and clamped 1–10, malformed mitre→null, contract validation.
- Temperature 0 + `format: "json"` force strict output from qwen2.5:3b, but validation is redundant/defensive anyway.

**Code-level FP guardrail:**
- `FALSE_POSITIVE` with confidence != HIGH → forced downgrade to NEEDS_REVIEW + downgrade_note set.
- Conservative bias: never discard an alert without HIGH confidence (prevents silent misclassification).

**Fallback (never crash):**
- `fallback_verdict(reason)` → returns NEEDS_REVIEW/LOW + fallback_reason.
- All failure paths (timeout 30s, connection error, HTTP!=200, invalid JSON, contract violation) → fallback.
- Reasoner never crashes; always adds parsed["verdict"] and parsed["reasoner_meta"] in-place.

---

## Running tests

```bash
"C:/Users/usuario/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m pytest tests/test_reasoner.py -v
```

**Coverage:** 46 tests (fully mocked OllamaClient, no network). Fixtures: timeout, invalid JSON, contract violations, FP guardrail, fallback paths, latency tracking.
Total: 115 tests passing (parser 25 + enricher 21 + reasoner 46), zero regressions.

**Manual runner (dev only, requires VPN + Ollama server):**
```bash
python tools/reasoner.py data/sample_alerts/<fixture>.json
```

**Live validation (1/6 fixtures tested, 2026-06):**
windows_spp_error.json vs. real Ollama/qwen2.5:3b: verdict FALSE_POSITIVE, confidence HIGH, risk_score 1 (calibration rule honored), latency 9873 ms (cold start ~9s within 30s timeout). JSON contract valid. Ready for production after remaining 5 fixtures validated and edge cases refined.

---

## Ollama server setup (deployment note)

- **Model:** qwen2.5:3b (CPU-only, ~500ms warm, ~8-9s cold start).
- **Timeout:** OLLAMA_TIMEOUT=30s (covers cold start + margin).
- **Host:** OLLAMA_HOST from `.env` (default: http://localhost:11434).
- **Format:** `format: "json"` in POST body ensures valid JSON from 3b model (strict, no fallback parsing).
- **Temperature:** 0 (deterministic, no hallucination).

---

## Implementation notes

- Ollama client is injectable (requests.Session parameter) for full DI and testability (mocks in test suite).
- Prompt is built once, cached in OllamaClient (efficiency).
- Output always valid JSON and matches ARCHITECTURE.md contract; ready for router.
- No external APIs (Ollama is local); fully offline after setup.
- All error paths fallback gracefully; logger will record the downgrade_note for audit.
