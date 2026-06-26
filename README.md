# Prism — SOC Alert Triage Agent

[![tests](https://github.com/mateoullaa/prism/actions/workflows/tests.yml/badge.svg)](https://github.com/mateoullaa/prism/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![status](https://img.shields.io/badge/status-v2%20production-brightgreen)

> _Named **Prism** — a prism separates light from noise, which is exactly what this agent does with security alerts._

An on-premise agent that automates the **first intelligence layer of SOC triage**. It receives
[Wazuh](https://wazuh.com/) alerts via webhook, classifies them, enriches IOCs with public threat
intelligence, and uses a **local LLM** to decide false positive vs. true positive — mapping
MITRE ATT&CK techniques and recommending next steps. The structured verdict is returned to the
[Shuffle](https://shuffler.io/) SOAR workflow.

Built to run **fully on-premise with a local model**, so sensitive alert data never leaves the network.

---

## The problem

On a real corpus of **6,320 alerts over 3 days, 61% were a single recurring false positive.**
Analysts burn hours re-triaging the same noise by hand. Prism front-loads that work: it filters
the obvious, enriches what matters, and hands the analyst a reasoned verdict instead of a raw alert.

---

## How it works

```
Wazuh alert (JSON)
   │
   ▼
 parser ──▶ enricher* ──▶ reasoner (local LLM) ──▶ router ──▶ logger ──▶ verdict to Shuffle
   │           │                  │                   │
classify    VirusTotal +     FP/TP + MITRE +      TRUE_POSITIVE → TheHive case
+ extract   AbuseIPDB +     risk_score +           NEEDS_REVIEW → TheHive alert
  IOCs      OTX             key_factors +           FALSE_POSITIVE → discard + CSV
            (in parallel)   next_action

 * enrichment runs only when the alert has an external IOC (~15% of traffic) → saves API quota
```

- **parser** — classifies an alert into one of 6 types (ssh, web, apache, firewall, malware, generic) and extracts IOCs (IPs, hashes, CVEs), filtering private IPs. Pure, deterministic, no external calls.
- **enricher** — looks up external IPs on VirusTotal + AbuseIPDB + OTX AlienVault **in parallel**, with a fail-fast rate limiter and an in-memory TTL cache (error cache: 60 s) to respect free-tier quotas.
- **reasoner** — a local LLM (Ollama) returns a strict-JSON verdict: `verdict` (FP/TP/NEEDS_REVIEW), `confidence`, `justification`, `mitre` (deterministic via `_evaluate_mitre`), `next_action`, `risk_score` (deterministic: FP→1, TP→[8,10]), `key_factors`, `observables`, `tags`, `case_description`, `severity_num`. On any failure it falls back to a conservative `NEEDS_REVIEW`.
- **router** — Prism's decision layer: routes TRUE_POSITIVE to a TheHive case, NEEDS_REVIEW to a TheHive alert, and FALSE_POSITIVE to discard + CSV. Conservative by design — on any doubt it escalates.
- **logger** — appends a CSV audit row for **every** alert, including discarded ones, so no routing decision is ever untraceable.
- **service** (`main.py`) — a FastAPI `POST /analyze` endpoint orchestrates the whole pipeline and returns the verdict; the caller reads `routing.send_to_shuffle` to decide what comes next.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and rationale.

---

## Example (illustrative)

An Apache web application exploit attempt comes in:

```json
{
  "rule": {
    "id": "31166",
    "level": 10,
    "description": "Apache: Attempt to exploit web application"
  },
  "data": { "srcip": "185.220.101.1", "url": "/admin/.env" },
  "decoder": { "name": "apache-errorlog" },
  "GeoLocation": { "country_name": "Netherlands" }
}
```

Prism returns the enriched alert with a reasoned verdict and a routing decision (the response
body is the full pipeline dict; abbreviated here):

```json
{
  "alert_type": "apache",
  "nature_category": "public_attack",
  "iocs": [{ "value": "185.220.101.1", "type": "ip", "external": true }],
  "enrichment": {
    "185.220.101.1": {
      "virustotal": { "status": "ok", "malicious": 12, "suspicious": 2 },
      "abuseipdb": { "status": "ok", "abuse_confidence_score": 98, "total_reports": 387 },
      "otx": { "status": "ok", "pulse_count": 14 }
    }
  },
  "verdict": {
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "justification": "Exploit attempt targeting /admin/.env from a Tor exit node flagged by 12 VT engines, 98% AbuseIPDB confidence, and 14 OTX pulses.",
    "mitre": { "id": "T1190", "name": "Exploit Public-Facing Application" },
    "next_action": "Block 185.220.101.1 at the perimeter and audit web server logs for successful access.",
    "risk_score": 9,
    "severity_num": 3,
    "key_factors": ["Tor exit node", "High VT score", "OTX: 14 pulses"],
    "observables": [{ "value": "185.220.101.1", "type": "ip" }],
    "tags": ["T1190", "apache", "exploit"]
  },
  "routing": {
    "action": "create_case",
    "send_to_shuffle": true,
    "reason": "Verdict is TRUE_POSITIVE (confidence=HIGH). Case created for analyst review."
  }
}
```

---

## Project status

v2 is production-ready. The full pipeline runs in Docker on `192.168.11.105:8000`,
wired end-to-end with Shuffle → Wazuh → Prism → TheHive. **282 tests, deterministic, no network.**

- [x] **Parser** — 6 alert types + IOC extraction · _32 tests_
- [x] **Enricher** — VirusTotal + AbuseIPDB + OTX, rate limiting + TTL cache · _31 tests_
- [x] **Reasoner** — local LLM verdict, deterministic MITRE + risk_score enforcement · _75 tests_
- [x] **Router** — conservative escalation to TheHive (cases + alerts) · _29 tests_
- [x] **Logger** — CSV audit row for every alert, including discarded ones · _23 tests_
- [x] **FastAPI service** — `POST /analyze` orchestration · _33 tests_
- [x] **Shuffle integration** — Wazuh → Prism → TheHive (cases + alerts + observables) ✅
- [x] **Docker deployment** — containerized at `192.168.11.105:8000` ✅
- [ ] **RAG + correlation** — runtime learning (v2.2)
- [ ] **UI dashboard** — graphical interface (v2.3)

---

## Tech stack

**Python 3.10+** · FastAPI · Ollama (local LLM) · VirusTotal API · AbuseIPDB API · OTX AlienVault ·
TheHive 5 · Docker · integrates with Wazuh and Shuffle. No data leaves the host.

Shuffle routing: `TRUE_POSITIVE` → TheHive case · `NEEDS_REVIEW` → TheHive alert · `FALSE_POSITIVE` → discard + CSV audit log.

---

## Engineering approach

This repo doubles as a study in disciplined, agent-assisted development:

- **WAT pattern** (Workflows · Agents · Tools) — LLM reasoning is kept separate from
  deterministic Python execution, so each tool is independently testable.
- **Deterministic tests** — external APIs are mocked; the suite needs no network or server.
- **Conventions & scope are documented and enforced** ([`docs/`](docs/),
  [`CLAUDE.md`](CLAUDE.md)); secrets live only in `.env`, and fixtures are anonymized.
- Built with a **multi-agent Claude Code harness** (orchestrator + builder + reviewer + scribe);
  the process notes live in [`PROGRESS.md`](PROGRESS.md) and the per-component SOPs in
  [`workflows/`](workflows/).

---

## Setup

```bash
git clone https://github.com/mateoullaa/prism.git && cd prism
python -m venv .venv && source .venv/Scripts/activate   # Git Bash on Windows
pip install -r requirements.txt
cp .env.example .env   # fill in API keys and the Ollama host
bash init.sh           # health check
```

## Run with Docker (recommended)

```bash
docker compose up -d
curl -s http://localhost:8000/health
```

> Ollama must be running on the host. The container reaches it via `http://host-gateway:11434`
> (configured in `docker-compose.yml`).

## Run locally (development)

```bash
python main.py            # serves on SERVICE_HOST:SERVICE_PORT (default 0.0.0.0:8000)
# then POST a Wazuh alert:
curl -X POST localhost:8000/analyze -H "Content-Type: application/json" \
     -d @data/sample_alerts/apache_attack.json
```

## Tests

```bash
pytest -q
```

## Structure

```
main.py                   FastAPI service — POST /analyze pipeline orchestration
Dockerfile                Production container image (python:3.12-slim)
docker-compose.yml        Service definition: port 8000, volumes, host-gateway for Ollama
tools/                    Execution tools (parser, enricher, reasoner, router, logger)
workflows/                Per-component SOPs (WAT)
tests/                    Deterministic tests for each tool (282 total)
docs/                     Architecture and conventions
data/sample_alerts/       Anonymized alert fixtures per type (ssh, apache, firewall…)
.claude/                  Dev harness: subagents, commands, hooks
```

© 2026 Mateo Ulla · Sample alerts are anonymized; no real or company data is included.
