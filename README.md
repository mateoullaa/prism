# Prism — AI-Powered SOC Alert Triage Agent

[![tests](https://github.com/mateoullaa/prism/actions/workflows/tests.yml/badge.svg)](https://github.com/mateoullaa/prism/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.12-blue)
![status](https://img.shields.io/badge/status-production%20v2.2-brightgreen)
![tests](https://img.shields.io/badge/tests-334%20passing-success)

> _A prism separates light from noise — exactly what this agent does with security alerts._

Prism is an **on-premise AI agent** that automates the first triage layer of a SOC. It receives
[Wazuh](https://wazuh.com/) alerts via webhook, classifies them, enriches indicators of compromise
(IOCs) against three threat intelligence APIs in parallel, and uses a **local LLM** (via Ollama)
to produce a structured verdict — including MITRE ATT&CK mapping, risk score, and recommended next
action. The verdict is returned to a [Shuffle](https://shuffler.io/) SOAR workflow which creates
cases in [TheHive 5](https://thehive-project.org/).

**All inference runs locally. No alert data ever leaves the network.**

---

## The problem it solves

On a real production corpus of **6,320 alerts over 3 days, 61% were a single recurring false positive** (Windows Security-SPP rule 60602). Analysts were re-triaging the same noise manually, every day.

Prism front-loads that work: it classifies the obvious, enriches what matters, contextualizes with historical precedents, and delivers the analyst a reasoned verdict instead of a raw alert.

---

## Architecture

```
Wazuh alert (JSON)
      │
      ▼
  ┌─────────┐     ┌──────────────────────────────────┐     ┌──────────┐
  │  parser  │────▶│           enricher               │────▶│ reasoner │
  │          │     │  VirusTotal · AbuseIPDB · OTX    │     │ (Ollama) │
  │ classify │     │  parallel threads · TTL cache    │     │ local LLM│
  │ + IOCs   │     │  rate limiting · fail-safe       │     └────┬─────┘
  └─────────┘     └──────────────────────────────────┘          │
                                                                 │ verdict
                  ┌──────────────────────────────────┐          │
                  │          retriever (RAG)          │◀─────────┤
                  │  ChromaDB · nomic-embed-text      │          │
                  │  similar_cases · auto-FP shadow   │          │
                  └──────────────────────────────────┘          │
                                                                 ▼
                                                          ┌────────────┐
                                                          │   router   │
                                                          │ TP → case  │
                                                          │ NR → alert │
                                                          │ FP → discard│
                                                          └─────┬──────┘
                                                                │
                                                          ┌─────▼──────┐
                                                          │   logger   │
                                                          │ CSV audit  │
                                                          │ every alert│
                                                          └────────────┘
                                                                │
                                                                ▼
                                                         verdict → Shuffle
                                                         → TheHive 5 case
```

### Pipeline components

| Component | Responsibility |
|-----------|---------------|
| **parser** | Classifies alerts into 6 types (ssh, web, apache, firewall, malware, generic). Extracts IOCs (IPs, hashes, CVEs), filters private ranges. Deterministic — no external calls. |
| **enricher** | Queries VirusTotal, AbuseIPDB, and OTX AlienVault **in parallel** (ThreadPoolExecutor). Rate limiter (4 req/min free tier), in-memory TTL cache, per-source error cache (60 s). Skips enrichment when no external IOC is present (~85% of traffic). |
| **reasoner** | Builds a structured prompt with alert context, enrichment summary, MITRE candidate, and historical precedents. Sends to a local Ollama model. Validates and enforces the JSON contract: verdict enum, risk\_score range, MITRE determinism. Conservative fallback on any failure. |
| **retriever** (RAG) | Embeds the alert signature via `nomic-embed-text` (Ollama), queries ChromaDB for the top-K most similar historical alerts, and injects a summary into the LLM prompt. In shadow mode, also computes auto-FP decisions without acting on them. |
| **router** | Routes `TRUE_POSITIVE` to a TheHive case, `NEEDS_REVIEW` to a TheHive alert, `FALSE_POSITIVE` to discard + CSV audit. Conservative by design: on any ambiguity it escalates. |
| **logger** | Appends a CSV audit row for **every** alert processed, including discarded false positives. No routing decision is ever untraced. |

---

## Key features

### v2.2 — RAG Runtime Learning (shadow mode)
- **Context injection**: the N most similar historical alerts are retrieved from ChromaDB and injected into the LLM prompt as a supporting signal (`"Of 5 similar alerts: 4 FALSE_POSITIVE, 1 TRUE_POSITIVE"`).
- **Auto-FP classification** (shadow mode): when ≥5 neighbors above similarity threshold 0.92 are unanimously `FALSE_POSITIVE/HIGH`, the agent would skip the LLM entirely (~15s saved per alert). Currently logging `would_be=auto_fp` for production validation before activation.
- **Correlation summary**: a human-readable English interpretation of the RAG result (`correlation_summary`) is appended to the case description (`full_description`), surfacing historical patterns to the analyst.
- **Feedback-loop guard**: only real LLM verdicts (`status="ok"`) are indexed back into ChromaDB — auto-classified and fallback verdicts are never stored.
- **Fail-safe**: if ChromaDB or the embeddings endpoint is unavailable, the pipeline degrades silently to v2.1 behavior.

### Determinism over probabilism
Fields that cannot be left to LLM discretion are computed in Python:
- `mitre` — determined by `_evaluate_mitre()` from alert type and known-FP status
- `risk_score` — enforced: `FALSE_POSITIVE → 1`, `TRUE_POSITIVE → [8, 10]`, `NEEDS_REVIEW → LLM value`
- Enrichment thresholds — AbuseIPDB score, VT malicious count, OTX pulse count evaluated in Python; the LLM receives pre-evaluated labels, not raw numbers

### Metrics dashboard
- `GET /metrics` — JSON statistics from the audit log (verdicts, latency, fallback rate, auto-FP rate, alert types, top rules)
- `GET /dashboard` — self-contained HTML dashboard with Chart.js (dark theme, 7 KPI cards, 5 charts, top-rules table). Zero new Python dependencies.

---

## Sample response

An Apache exploit attempt comes in (`rule.id=31166`, `srcip=185.220.101.1`):

```json
{
  "alert_type": "apache",
  "nature_category": "public_attack",
  "iocs": [{ "value": "185.220.101.1", "type": "ip", "external": true }],
  "enrichment": {
    "185.220.101.1": {
      "virustotal":  { "status": "ok", "malicious": 12, "suspicious": 2 },
      "abuseipdb":  { "status": "ok", "abuse_confidence_score": 98, "total_reports": 387 },
      "otx":        { "status": "ok", "pulse_count": 14 }
    }
  },
  "verdict": {
    "verdict":      "TRUE_POSITIVE",
    "confidence":   "HIGH",
    "risk_score":   9,
    "mitre":        { "id": "T1190", "name": "Exploit Public-Facing Application" },
    "justification": "Exploit attempt targeting /admin/.env from a Tor exit node flagged by 12 VT engines, 98% AbuseIPDB confidence, and 14 OTX pulses.",
    "next_action":  "Block 185.220.101.1 at the perimeter and audit web server logs for successful access.",
    "key_factors":  ["Tor exit node", "High VT score", "OTX: 14 pulses"],
    "tags":         ["T1190", "apache", "exploit"],
    "severity_num": 3
  },
  "correlation_summary": "1/1 similar past alerts were TRUE_POSITIVE (avg similarity 94%). High-risk pattern — prioritize review.",
  "routing": {
    "action": "create_case",
    "send_to_shuffle": true
  }
}
```

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12 |
| API framework | FastAPI + Uvicorn |
| Local LLM | Ollama (`qwen2.5:3b`) |
| Vector store | ChromaDB (embedded, persistent) |
| Embeddings | Ollama `nomic-embed-text` |
| Threat intel | VirusTotal API · AbuseIPDB API · OTX AlienVault |
| SOAR integration | Shuffle → TheHive 5 |
| Alerting source | Wazuh |
| Containerization | Docker + Docker Compose |
| Testing | Pytest (334 tests, no network required) |

---

## Project status

```
v1    LIVE    — core pipeline (parse → enrich → reason → route → log)
v2    LIVE    — OTX enrichment, observables, tags, case_description, TheHive integration
v2.1  LIVE    — Apache alert type, deterministic MITRE mapping, risk_score enforcement
v2.2  LIVE    — RAG context injection (shadow mode auto-FP), correlation_summary, metrics dashboard
```

### Component checklist

- [x] **Parser** — 6 alert types, IOC extraction, nature categorization · _32 tests_
- [x] **Enricher** — VirusTotal + AbuseIPDB + OTX parallel, TTL cache, rate limiting · _31 tests_
- [x] **Reasoner** — local LLM verdict, deterministic MITRE + risk\_score, conservative fallback · _75 tests_
- [x] **Router** — conservative escalation to TheHive (cases + alerts) · _29 tests_
- [x] **Logger** — CSV audit trail for every alert (including discarded FPs) · _23 tests_
- [x] **Service** — FastAPI `POST /analyze` + `GET /health` · _33 tests_
- [x] **Retriever (RAG)** — ChromaDB + Ollama embeddings, shadow auto-FP, correlation summary · _36 tests_
- [x] **Metrics** — `GET /metrics` JSON + `GET /dashboard` HTML · _14 tests_
- [x] **Docker** — containerized, production-deployed at `192.168.11.105:8000`
- [x] **Shuffle integration** — end-to-end: Wazuh → Prism → TheHive (cases + alerts + observables)

**334 tests · 0 regressions · deterministic · no network required**

---

## Engineering approach

- **Determinism first** — fields that can be computed deterministically in Python are never delegated to the LLM. The model handles language and reasoning; Python handles rules and contracts.
- **Fail-safe at every layer** — each tool catches its own exceptions and returns a conservative result. The service never returns HTTP 500; no alert is ever lost.
- **Injectable dependencies** — all external clients (Ollama, VirusTotal, ChromaDB) are injected via constructor or FastAPI `Depends`, making every component unit-testable without network or disk.
- **Mocked test suite** — 334 deterministic tests, no external calls. External APIs are replaced by `MagicMock` sessions with canned responses.
- **On-premise by design** — all LLM inference and vector search run locally. Alert data never leaves the host.
- **Multi-agent development harness** — built with a Claude Code orchestrator + specialized subagents (builder, reviewer, scribe). Per-component SOPs in [`workflows/`](workflows/), architectural decisions in [`docs/`](docs/).

---

## Setup

### Docker (recommended for production)

```bash
git clone https://github.com/mateoullaa/prism.git && cd prism
cp .env.example .env        # fill in API keys + Ollama host
docker compose up -d
curl http://localhost:8000/health
```

> Ollama must be running on the host. The container reaches it via `http://host-gateway:11434`.

### Local development

```bash
python -m venv .venv && source .venv/Scripts/activate   # Git Bash / Windows
pip install -r requirements.txt
cp .env.example .env
bash init.sh                # health check
python main.py              # serves on 0.0.0.0:8000
```

### Send an alert

```bash
curl -X POST localhost:8000/analyze \
     -H "Content-Type: application/json" \
     -d @data/sample_alerts/apache_attack.json
```

### Run tests

```bash
pytest -q   # 334 tests, ~30s, no network
```

---

## Repository structure

```
main.py                   FastAPI service — full pipeline orchestration
Dockerfile                Production image (python:3.12-slim)
docker-compose.yml        Port 8000, bind-mounts for metrics/ and chroma_db/
tools/
  parser.py               Alert classification + IOC extraction
  enricher.py             VirusTotal + AbuseIPDB + OTX (parallel, cached)
  reasoner.py             Ollama LLM client + prompt builder + JSON validation
  router.py               Verdict → TheHive routing decision
  logger.py               CSV audit trail (every alert, including discarded)
  retriever.py            ChromaDB RAG — embed, query, index, auto-FP logic
  metrics.py              Audit log statistics for dashboard
scripts/
  backfill_chroma.py      One-time CSV → ChromaDB migration
  validate_threshold.py   Leave-one-out CV for AUTO_FP_THRESHOLD selection
tests/                    334 deterministic tests (mocked external dependencies)
data/sample_alerts/       Anonymized alert fixtures per type
docs/                     Architecture + conventions
workflows/                Per-component SOPs
.claude/                  Dev harness: subagents, slash commands, hooks
```

---

## Environment variables

Copy `.env.example` to `.env` and fill in:

| Variable | Description |
|----------|-------------|
| `VT_API_KEY` | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |
| `OTX_API_KEY` | OTX AlienVault API key |
| `OLLAMA_HOST` | Ollama base URL (e.g. `http://localhost:11434`) |
| `OLLAMA_MODEL` | Model name (e.g. `qwen2.5:3b`) |
| `RAG_ENABLED` | Enable ChromaDB retriever (`true`/`false`) |
| `RAG_SHADOW_MODE` | Log auto-FP decisions without acting (`true`/`false`) |
| `AUTO_FP_THRESHOLD` | Cosine similarity threshold for auto-FP (default `0.92`) |

Full variable list and defaults in [`.env.example`](.env.example).

---

© 2026 Mateo Ulla · Sample alerts are anonymized; no real or company data is included.
