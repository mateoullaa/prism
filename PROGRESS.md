# PROGRESS.md — Build Status

Build progress tracker. **Read** at the start of each session (after `init.sh` and `memory.md`).
**Written** when a component is completed/advanced or the plan changes. **Written by:** `scribe`.
States: `[ ]` pending · `[~]` in progress · `[x]` done and tested.

---

## MVP v1 — Build sequence (strict order, do not skip)

- [x] Harness: structure, `.claude/` (agents, commands, hooks), `init.sh`, docs, fixtures
- [ ] **1. `tools/parser.py`** — classify type + extract IOCs *(no server, no Ollama)*
  - [ ] Handle wrapped `_source` format and direct format
  - [ ] Classifier for the 5 alert types
  - [ ] IOC extraction per type (with private IP filter)
  - [ ] `tests/test_parser.py` against all 6 fixtures
  - [ ] `workflows/parser.md`
- [ ] **2. `tools/enricher.py`** — VirusTotal + AbuseIPDB *(public APIs, no server)*
  - [ ] VirusTotal client with rate limiting (~4 req/min free tier)
  - [ ] AbuseIPDB client
  - [ ] Parallel (ThreadPoolExecutor) + failure handling without breaking the pipeline
  - [ ] Tests with mocked external calls
  - [ ] `workflows/enricher.md`
- [ ] **3. `tools/reasoner.py`** — LLM via Ollama *(REQUIRES server running)*
  - [ ] Ollama client (`/api/generate`)
  - [ ] Analysis prompt (iterate with real fixtures)
  - [ ] JSON output validation + fallback if not valid JSON
  - [ ] `workflows/reasoner.md`
- [ ] **4. `tools/router.py`** — action decision (v1: always return to Shuffle)
- [ ] **5. `tools/logger.py`** — metrics in CSV (timestamp, type, verdict, time)
- [ ] **6. `main.py`** — FastAPI, endpoint `POST /analyze`, orchestration
- [ ] **7. Shuffle integration** — coordinate with the team

## Blocked / waiting
- Reasoner and anything using Ollama: server running + `OLLAMA_HOST=0.0.0.0:11434`
  config agreed with the team.
- Own SSH credentials (ask the team; do not use a shared user).

## Next immediate step
Build `tools/parser.py` + test + workflow. Does not require server or Ollama. Use `/build-tool parser`.

## v2 ideas (DO NOT implement now)
- Runtime learning: RAG + embeddings + ChromaDB (coordinate with the team).
- Direct case creation in TheHive.
- Automatic FP filtering based on real v1 metrics.
- Visualizations (matplotlib) / metrics dashboard.
