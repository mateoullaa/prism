# PROGRESS.md — Build Status

Build progress tracker. **Read** at the start of each session (after `init.sh` and `memory.md`).
**Written** when a component is completed/advanced or the plan changes. **Written by:** `scribe`.
States: `[ ]` pending · `[~]` in progress · `[x]` done and tested.

---

## MVP v1 — Build sequence (strict order, do not skip)

- [x] Harness: structure, `.claude/` (agents, commands, hooks), `init.sh`, docs, fixtures
- [x] **1. `tools/parser.py`** — classify type + extract IOCs _(no server, no Ollama)_
  - [x] Handle wrapped `_source` format and direct format
  - [x] Classifier for the 5 alert types
  - [x] IOC extraction per type (with private IP filter)
  - [x] `tests/test_parser.py` against all 7 fixtures (windows_spp_grouped.json added)
  - [x] `workflows/parser.md`
  - [x] Categorization axis by nature: `nature_category` field (public_attack / internal_movement / informational / unknown); loaded from `config/known_patterns.json` (with code `_DEFAULTS` fallback); evaluation order: public_attack → internal_movement → informational → unknown; 13 new tests (180 → 187 total)
  - [x] Public attack detection: decoder + groups + external srcip. Configurable lists now in `config/known_patterns.json`
  - [x] Known FP candidates: rule 60602 + rule 61061 (aggregation of 60602); both flagged in config
  - [x] Apache extension: alert_type="apache" via decoder.name="apache-errorlog"; _extract_apache() extracts data.srcip IOC; fixture apache_attack.json; 6 new tests (282 total)
- [x] **2. `tools/enricher.py`** — VirusTotal + AbuseIPDB _(public APIs, no server)_
  - [x] VirusTotal client with rate limiting (~4 req/min free tier)
  - [x] AbuseIPDB client
  - [x] Parallel (ThreadPoolExecutor) + failure handling without breaking the pipeline
  - [x] Tests with mocked external calls (21 tests passing; 46/46 total with parser, no regressions)
  - [x] `workflows/enricher.md`
- [x] **3. `tools/reasoner.py`** — LLM via Ollama _(REQUIRES server running)_
  - [x] OllamaClient (injectable session) with `generate(prompt)` → `{status, response, latency_ms}`
  - [x] Analysis prompt builder: alert_type + nature_category + rule + IOCs + enrichment summary (ok/cached only) + is_known_fp_candidate hint + JSON schema with literal enums
  - [x] Defensive JSON validation (`_parse_llm_json`, `_validate_verdict`) + enum normalization + risk_score coerce/clamp 1–10
  - [x] Code-level FP guardrail: FALSE_POSITIVE + confidence != HIGH → NEEDS_REVIEW downgrade (conservative bias)
  - [x] Fallback verdict (NEEDS_REVIEW/LOW, never crash) for all failure paths (timeout, connection, HTTP!=200, invalid JSON, contract violation)
  - [x] Few-shot example replaced with domain-neutral text (mitre=null) — eliminates SSH hallucination
  - [x] _evaluate_enrichment(): thresholds evaluated in Python (named constants _ABUSEIPDB_SCORE_THRESHOLD=80, etc.), model receives pre-evaluated conclusions (HIGH/LOW RISK labels); numeric comparisons removed from prompt
  - [x] Prompt ENRICHMENT INTERPRETATION RULES simplified to 4 lines (logic now in code, not prose rules)
  - [x] test_reason_idempotent_payload: 5× same dict, payload bit-for-bit identical — confirms build_prompt() is pure
  - [x] TestEvaluateEnrichment: 16 unit tests for _evaluate_enrichment() (threshold boundaries, status filtering, None coercion)
  - [x] `tests/test_reasoner.py` — 65 tests (mocked OllamaClient, no network); 206 total tests passing (zero regressions)
  - [x] `workflows/reasoner.md`
- [x] **4. `tools/router.py`** — action decision (Prism decides create-or-not-case; only alerts that warrant a case are sent to Shuffle)
  - [x] route() contract: reads parsed["verdict"] + parsed["reasoner_meta"], writes parsed["routing"], in-place mutation
  - [x] Decision rules: FALSE_POSITIVE → discard; TRUE_POSITIVE|NEEDS_REVIEW → create_case; missing/malformed → defensive escalation (create_case)
  - [x] Audit trail: reason field includes verdict, confidence, fallback context (if any), downgrade_note (if present)
  - [x] tests/test_router.py: 29 tests (TRUE_POSITIVE/FALSE_POSITIVE/NEEDS_REVIEW paths, fallback/downgrade handling, defensive edge cases, in-place mutation contract, end-to-end fixtures)
  - [x] Total test suite: 148 passing (zero regressions)
  - [x] Reviewer APPROVED (no blockers)
  - [x] workflows/router.md
- [x] **5. `tools/logger.py`** — metrics in CSV + audit trail (timestamp, type, verdict, time; MUST log ALL discarded alerts with reason)
  - [x] CSV schema: 16 fixed columns (timestamp, alert_type, nature_category, rule_id, rule_description, verdict, confidence, risk_score, mitre_id, action, send_to_shuffle, status, latency_ms, model, is_known_fp_candidate, reason)
  - [x] Public API: `log_alert(parsed: dict, *, log_path: str | None = None, timestamp: str | None = None) -> dict` (never raises; I/O errors caught and logged)
  - [x] Mandatory audit trail: ALL alerts logged including FALSE_POSITIVE discarded ones; reason field persists router audit trail
  - [x] Defensive extraction: `isinstance` + `.get()` + `_safe()` None-coalescer; rule_id=None → "" (not "None"); booleans as "True"/"False" strings
  - [x] Header written only on new/empty file (stat check inside lock, no TOCTOU under concurrency)
  - [x] Thread safety: module-level threading.Lock for FastAPI concurrency
  - [x] tests/test_logger.py: 23 tests (CSV schema, header behavior, defensive extraction, boolean serialization, timestamp/log_path injection, I/O error resilience, FP audit trail end-to-end, concurrency)
  - [x] Reviewer APPROVED (no blockers)
  - [x] workflows/logger.md
- [x] **6. `main.py`** — FastAPI, endpoint `POST /analyze`, orchestration
  - [x] `POST /analyze` + `GET /health` endpoints
  - [x] Full pipeline orchestration: parse → enrich → reason → route → log, returns complete parsed dict
  - [x] Module-level singletons (enricher clients, Ollama) via FastAPI dependency injection (get_pipeline)
  - [x] Sync endpoint in threadpool (blocks don't stall event loop); thread-safe client/session reuse across requests
  - [x] Never-500 defensive escalation: catch all exceptions, return HTTP 200 + create_case escalation body; best-effort CSV audit row even on catastrophic failure (honors "every alert logged" invariant)
  - [x] 9 tests (mocked external calls via dependency injection; full pipeline, escalation path, contract, audit behavior)
  - [x] Reviewer APPROVED (no blockers)
  - [x] `workflows/main.md`
  - [x] `requirements.txt` updated: `httpx>=0.27` (TestClient/Starlette clean-clone dependency)
  - [x] 189 total tests passing (zero regressions)
- [x] **7. Shuffle integration** — end-to-end pipeline validated (TRUE_POSITIVE/NEEDS_REVIEW create cases; FALSE_POSITIVE discards to CSV audit log only)

## Blocked / waiting

_None (Shuffle integration complete; pipeline validated end-to-end)_

## Next immediate step

v2.2 is complete and live in shadow mode. The only pending action is growing the corpus to ≥200 alerts, then running validate_threshold.py and flipping RAG_SHADOW_MODE=false to activate auto-classification. Corpus grows with each new alert ingested; monitor shadow logs in metrics/triage_log.csv for precision metrics before flipping. No code changes required.

## Technical debt / pending (post-sanitization)

**RESOLVED:**

1. [x] Warning #1: OllamaClient now exposes a public `model` property; `reason()` reads `client.model` (no more `getattr`).
2. [x] Warning #2: `build_prompt` failure path now records real `latency_ms` (computed from `t_start`), not `0`.

**RESOLVED:** 3. [x] End-to-end pipeline test added (`tests/test_pipeline.py`): chained `parse_alert → enrich → reason`, external-IP and no-IOC paths, all mocked. 4. [x] `parser.py` non-list `rule.groups` guard now covered (`tests/test_parser.py` §13: scalar treated as single element; no substring false-match).

**RESOLVED:** 5. [x] Risk_score contract-validation fallback fixed: _validate_verdict() now defaults risk_score=5 for NEEDS_REVIEW with absent score; TRUE_POSITIVE/FALSE_POSITIVE still fatal. Both failing fixtures confirmed ok live (2026-06-21). 189 tests passing.

6. [x] Few-shot example SSH hallucination: `_PROMPT_PREFIX` example replaced with domain-neutral text (mitre=null). Confirmed via `test_reason_idempotent_payload` (payload deterministic, code clean) + 5/5 live runs post-fix with no SSH bleed.

7. [x] abuse_confidence_score semantic inversion (3b model read 100 as "low"): thresholds moved to Python _evaluate_enrichment(); prompt receives pre-evaluated risk labels. 206 tests passing. 5/5 live runs TRUE_POSITIVE/HIGH/risk=8 consistent.

Test suite: 221 passing (parser 32 + enricher + reasoner + router 29 + logger 23 + pipeline + main 9; 15 new OTX tests).

## v2 Exploration — Branch `v2-exploration`

[x] **v2-exploration COMPLETE & READY FOR SHUFFLE INTEGRATION**
  - OTX: error cache implemented, timeout raised 8s→15s (OTX_TIMEOUT env) after 2026-06-22 live audit found 8s too tight for ~45KB payloads (outliers >13.6s)
  - observables: independent verdict, sources, confidence
  - tags: from verdict + nature + type + mitre
  - key_factors: from enrichment + rule + LLM; truncation fixed (first complete sentence, no mid-word cuts)
  - case_description: 4-paragraph Spanish narrative
  - severity_num: 1–4 mapping (TheHive 5)
  - DEFERRED to v2.2: correlation_summary, full_description
  - Live audit (2026-06-22) via FastAPI TestClient: 7 fixtures, 14 live calls, all status=ok, v2 contract validated. Known-FP suppression confirmed (windows_spp_error/grouped → FALSE_POSITIVE/discard).
  - 281 tests passing

## v2.1 — Post-MVP Hardening (branch v2-exploration)

[x] **v2.1 COMPLETE & VALIDATED IN PRODUCTION**
  - Apache alert type: parser recognizes apache-errorlog decoder → alert_type="apache"; _extract_apache() extracts data.srcip as external IOC + GeoLocation context; _MITRE_MAP["apache"] = T1190 Exploit Public-Facing Application
  - MITRE mapping: deterministic via _evaluate_mitre() — T1110 (ssh), T1595 (network), T1190 (apache/vulnerability), T1204 (virustotal), T1078 (windows_event); returns null for known FP candidates
  - risk_score enforcement: FALSE_POSITIVE→1, TRUE_POSITIVE→[8,10], NEEDS_REVIEW→LLM value (guardrail resets to 5 on FP downgrade)
  - Shuffle integration validated in production: TRUE_POSITIVE→case created, NEEDS_REVIEW→alert created, FALSE_POSITIVE→CSV discard only
  - 282 tests passing, 0 regressions

## v2.2 — RAG Runtime Learning (branch v2-exploration)

[x] **v2.2 COMPLETE & PRODUCTION VALIDATED (2026-07-01, shadow mode)**
  - retrieve_similar() → similar_cases injected into reasoner prompt ("Of N similar alerts: X FP, Y TP, Z NEEDS_REVIEW")
  - decide_auto_fp() → shadow mode logging (without cutting verdicts); AUTO_FP_THRESHOLD=0.92 (similarity gate)
  - index_alert() → incremental ingestion post-routing (only real LLM verdicts, status=="ok"); feedback-loop guard active
  - correlation_summary → generated via build_correlation_summary(), returns English text (analyst-facing)
  - full_description → automatic concatenation of case_description + correlation_summary; None when RAG disabled or no hits (backward compatible)
  - ChromaDB embedded in-process (PersistentClient at ./chroma_db, bind-mounted); Ollama nomic-embed-text via /api/embeddings (no ML deps in image)
  - Backfill: 31 alerts indexed (18 TP, 9 NR, 4 FP); corpus foundation established
  - Shadow validation: auto-classification (Function 1) awaiting corpus growth to ≥200 alerts; context injection (Function 2) live immediately
  - Test suite: 318 tests (282 prior + 27 retriever + 9 correlation_summary), 0 regressions
  - Validated end-to-end: Windows FP detected (auto-similar), SSH NR contextualized, Apache TP enriched; all paths confirmed working

[x] **v2.2 COMPLETE & SHADOW-MODE DEPLOYED** (implementation details)
  - Embeddings: Ollama `nomic-embed-text` via /api/embeddings (reuses deployed Ollama host; no heavy ML deps)
  - Deployment: ChromaDB embedded (PersistentClient at ./chroma_db, bind-mounted like metrics/); offline-safe, no separate container
  - Function 1 (auto-FP): similarity ≥AUTO_FP_THRESHOLD (default 0.92) triggers auto-classification FALSE_POSITIVE WITHOUT LLM (saves ~10-20s); gated RAG_SHADOW_MODE=true (shadow logs "would_be=auto_fp" but doesn't act); conservative (never auto-classifies to TP/NEEDS_REVIEW)
  - Function 2 (context): N most similar past alerts aggregated ("Of N similar alerts: X FP, Y TP, Z NEEDS_REVIEW") → injected into reasoner prompt as enrichment signal (live immediately, low risk)
  - Feedback-loop guard: only real LLM verdicts (reasoner_meta.status=="ok") indexed back; auto-classified + fallback verdicts never stored
  - Fail-safe design: tools/retriever.py never raises; if Chroma/embeddings/RAG unavailable → returns empty → v2.1 behavior
  - Audit trail: auto-classified alerts use existing CSV columns (status="auto_fp", model="rag-similarity:nomic-embed-text", reason with score+precedent count)
  - Scripts: backfill_chroma.py (migration from metrics/triage_log.csv), validate_threshold.py (leave-one-out CV for AUTO_FP_THRESHOLD)
  - Tests: 27 retriever tests + 7 new integration/prompt tests; 309 passing (up from 282)

## Follow-up items (post-Shuffle, v2.1)

- [x] MITRE mapping: fixed via Python pre-evaluation (_evaluate_mitre()) — same design principle as enrichment thresholds. 269 tests passing.
- [x] risk_score determinism: fixed via verdict-range enforcement in Python (_validate_verdict()). FP→1, TP→[8,10], NR→unchanged. Root cause: BLAS float non-determinism even at temperature=0. 282 tests passing.
  - Live validation (2026-06-26): 3/3 fixtures confirmed correct. Two additional bugs found and fixed: (a) _evaluate_mitre() did not check is_known_fp_candidate — added guard (return None if FP candidate); (b) FP guardrail left risk_score=1 after downgrading to NEEDS_REVIEW — added reset to 5 in guardrail block. Tests added: test_known_fp_candidate_returns_none, test_non_fp_candidate_windows_event_returns_T1078, test_build_prompt_injects_null_mitre_for_known_fp_candidate, test_reason_fp_guardrail_downgrades_medium_confidence (updated).

[x] **Docker deployment — COMPLETE & VALIDATED**
  - Dockerfile: python:3.12-slim, prod dependencies only (pytest excluded)
  - docker-compose.yml: port 8000, restart unless-stopped, volumes para metrics/ y config/
  - Ollama connectivity: host-gateway:host-gateway → http://host-gateway:11434
  - .dockerignore: excluye .venv/, tests/, .env, .git/
  - Validado end-to-end desde Shuffle: Apache TRUE_POSITIVE → TheHive caso + observable ✅

## v2.x ideas (DO NOT implement now)

- [x] **v2.2: Runtime learning** — RAG + embeddings + ChromaDB. Implemented in shadow-mode (see v2.2 section above).
- [x] **v2.1: Direct case creation in TheHive** — implemented via Execute Python node in Shuffle (POST /api/v1/case directly, bypasses Shuffle's broken Create case node).
- Automatic FP filtering based on real v1 metrics (v2.3+).
- Visualizations (matplotlib) / metrics dashboard.
