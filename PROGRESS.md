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
- [ ] **3. `tools/reasoner.py`** — LLM via Ollama *(REQUIRES server running)*
  - [ ] Ollama client (`/api/generate`)
  - [ ] Analysis prompt (iterate with real fixtures)
  - [ ] JSON output validation + fallback if not valid JSON
  - [ ] `workflows/reasoner.md`
- [ ] **4. `tools/router.py`** — action decision (Prism decides create-or-not-case; only alerts that warrant a case are sent to Shuffle)
- [ ] **5. `tools/logger.py`** — metrics in CSV + audit trail (timestamp, type, verdict, time; MUST log ALL discarded alerts with reason)
- [ ] **6. `main.py`** — FastAPI, endpoint `POST /analyze`, orchestration
- [ ] **7. Shuffle integration** — coordinate with the SOC team

## Blocked / waiting
- Reasoner and anything using Ollama: server running + `OLLAMA_HOST=0.0.0.0:11434`
  config agreed with the team.
- Own SSH credentials for the server (request a personal account; do not use a shared user).

## Next immediate step
Build `tools/reasoner.py` (LLM via Ollama; can now use `nature_category` from parser output).
*Blocked:* Ollama server running, `OLLAMA_HOST=0.0.0.0:11434` agreed with the team.

## v2 ideas (DO NOT implement now)
- OTX (AlienVault) as additional enrichment source.
- Runtime learning: RAG + embeddings + ChromaDB (coordinate with the team).
- Direct case creation in TheHive.
- Automatic FP filtering based on real v1 metrics.
- Visualizations (matplotlib) / metrics dashboard.
