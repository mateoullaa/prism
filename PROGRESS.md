# PROGRESS.md — Build Status

Build progress tracker. **Read** at the start of each session (after `init.sh` and `memory.md`).
**Written** when a component is completed/advanced or the plan changes. **Written by:** `scribe`.
States: `[ ]` pending · `[~]` in progress · `[x]` done and tested.

---

## MVP v1 — Build sequence (strict order, do not skip)

- [x] Harness: structure, `.claude/` (agents, commands, hooks), `init.sh`, docs, fixtures
- [x] **1. `tools/parser.py`** — classify type + extract IOCs *(no server, no Ollama)*
  - [x] Handle wrapped `_source` format and direct format
  - [x] Classifier for the 5 alert types
  - [x] IOC extraction per type (with private IP filter)
  - [x] `tests/test_parser.py` against all 6 fixtures (25/25 passing)
  - [x] `workflows/parser.md`
  - [x] Categorization axis by nature: `nature_category` field (public_attack / internal_movement / informational / unknown); INFORMATIONAL_GROUPS, INTERNAL_MOVEMENT_GROUPS, PUBLIC_ATTACK_SIGNATURES constants; evaluation order: public_attack → internal_movement → informational → unknown; 10 new tests (69/69 total)
  - [x] Public attack detection: decoder + groups + external srcip. Initial list: `ar_log_json` + `active_response`/`ossec` (firewall); `apache-errorlog` + `apache`/`web`/`invalid_request` (web attacks)
- [x] **2. `tools/enricher.py`** — VirusTotal + AbuseIPDB *(public APIs, no server)*
  - [x] VirusTotal client with rate limiting (~4 req/min free tier)
  - [x] AbuseIPDB client
  - [x] Parallel (ThreadPoolExecutor) + failure handling without breaking the pipeline
  - [x] Tests with mocked external calls (21 tests passing; 46/46 total with parser, no regressions)
  - [x] `workflows/enricher.md`
- [x] **3. `tools/reasoner.py`** — LLM via Ollama *(REQUIRES server running)*
  - [x] OllamaClient (injectable session) with `generate(prompt)` → `{status, response, latency_ms}`
  - [x] Analysis prompt builder: alert_type + nature_category + rule + IOCs + enrichment summary (ok/cached only) + is_known_fp_candidate hint + JSON schema with literal enums
  - [x] Defensive JSON validation (`_parse_llm_json`, `_validate_verdict`) + enum normalization + risk_score coerce/clamp 1–10
  - [x] Code-level FP guardrail: FALSE_POSITIVE + confidence != HIGH → NEEDS_REVIEW downgrade (conservative bias)
  - [x] Fallback verdict (NEEDS_REVIEW/LOW, never crash) for all failure paths (timeout, connection, HTTP!=200, invalid JSON, contract violation)
  - [x] `tests/test_reasoner.py` — 46 tests (mocked OllamaClient, no network); 115 total with parser+enricher
  - [x] `workflows/reasoner.md`
- [x] **4. `tools/router.py`** — action decision (Prism decides create-or-not-case; only alerts that warrant a case are sent to Shuffle)
  - [x] route() contract: reads parsed["verdict"] + parsed["reasoner_meta"], writes parsed["routing"], in-place mutation
  - [x] Decision rules: FALSE_POSITIVE → discard; TRUE_POSITIVE|NEEDS_REVIEW → create_case; missing/malformed → defensive escalation (create_case)
  - [x] Audit trail: reason field includes verdict, confidence, fallback context (if any), downgrade_note (if present)
  - [x] tests/test_router.py: 29 tests (TRUE_POSITIVE/FALSE_POSITIVE/NEEDS_REVIEW paths, fallback/downgrade handling, defensive edge cases, in-place mutation contract, end-to-end fixtures)
  - [x] Total test suite: 148 passing (zero regressions)
  - [x] Reviewer APPROVED (no blockers)
  - [x] workflows/router.md
- [ ] **5. `tools/logger.py`** — metrics in CSV + audit trail (timestamp, type, verdict, time; MUST log ALL discarded alerts with reason)
- [ ] **6. `main.py`** — FastAPI, endpoint `POST /analyze`, orchestration
- [ ] **7. Shuffle integration** — coordinate with the SOC team

## Blocked / waiting
- Own SSH credentials for the server (request a personal account; do not use a shared user).
- Live prompt iteration (1 of 6 fixtures tested: windows_spp_error.json via VPN smoke test PASSED, no regression). Enrichment interpretation rules added to reasoner prompt and verified live (malicious-IP alert flips to TRUE_POSITIVE as intended). Router build can proceed; remaining 5 fixtures and edge cases iterate post-router.

## Next immediate step
Build `tools/logger.py` (item 5 — metrics CSV + audit trail; MUST log ALL alerts NOT sent to Shuffle, reading parsed["routing"]["reason"] for the audit entry).

## Technical debt / pending (post-sanitization)

**DEUDA de código — RESOLVED:**
1. [x] Warning #1: OllamaClient now exposes a public `model` property; `reason()` reads `client.model` (no more `getattr`).
2. [x] Warning #2: `build_prompt` failure path now records real `latency_ms` (computed from `t_start`), not `0`.

**MEJORAS — RESOLVED:**
3. [x] End-to-end pipeline test added (`tests/test_pipeline.py`): chained `parse_alert → enrich → reason`, external-IP and no-IOC paths, all mocked.
4. [x] `parser.py` non-list `rule.groups` guard now covered (`tests/test_parser.py` §13: scalar treated as single element; no substring false-match).

**Pending (blocked — needs live server):**
5. [ ] Risk_score + enrichment calibration validated live on only 1/6 fixtures (`memory.md` live-test note); validate the remaining 5 against real Ollama (VPN + server) post-router.

Test suite: 148 passing (sanitization batch added +2 parser guard, +2 pipeline; router added +29).

## v2 ideas (DO NOT implement now)
- OTX (AlienVault) as additional enrichment source.
- Runtime learning: RAG + embeddings + ChromaDB (coordinate with the team).
- Direct case creation in TheHive.
- Automatic FP filtering based on real v1 metrics.
- Visualizations (matplotlib) / metrics dashboard.
