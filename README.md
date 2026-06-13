# Prism — SOC Alert Triage Agent

[![tests](https://github.com/mateoullaa/prism/actions/workflows/tests.yml/badge.svg)](https://github.com/mateoullaa/prism/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![status](https://img.shields.io/badge/status-v1%20in%20progress-orange)

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
   │           │                  │
classify    VirusTotal +     FP/TP + MITRE +
+ extract   AbuseIPDB        next action (strict JSON)
  IOCs      (in parallel)

 * enrichment runs only when the alert has an external IOC (~15% of traffic) → saves API quota
```

- **parser** — classifies an alert into one of 5 types and extracts IOCs (IPs, hashes, CVEs),
  filtering private IPs. Pure, deterministic, no external calls.
- **enricher** — looks up external IPs on VirusTotal + AbuseIPDB **in parallel**, with a
  fail-fast rate limiter and an in-memory TTL cache to respect free-tier quotas.
- **reasoner** — a local LLM (Ollama) returns a strict-JSON verdict (FP/TP, confidence,
  MITRE technique, next action, risk score). On any failure it falls back to a conservative
  `NEEDS_REVIEW` — it never crashes and never silently discards an alert.
- **router** — Prism's decision layer: decides whether the alert warrants a case (sent to
  Shuffle) or can be discarded. Conservative by design — on any doubt it escalates.
- **logger** — appends a CSV audit row for **every** alert, including discarded ones, so no
  routing decision is ever untraceable.
- **service** (`main.py`) — a FastAPI `POST /analyze` endpoint orchestrates the whole pipeline
  and returns the verdict; the caller reads `routing.send_to_shuffle` to decide what comes next.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and rationale.

---

## Example (illustrative)

An SSH brute-force attempt comes in:

```json
{
  "rule": {
    "id": "5710",
    "level": 5,
    "description": "sshd: Attempt to login using a non-existent user"
  },
  "data": { "srcip": "5.5.5.5", "srcuser": "hacker" },
  "decoder": { "name": "sshd" },
  "GeoLocation": { "country_name": "Germany" }
}
```

Prism returns the enriched alert with a reasoned verdict and a routing decision (the response
body is the full pipeline dict; abbreviated here):

```json
{
  "alert_type": "ssh",
  "nature_category": "public_attack",
  "iocs": [{ "value": "5.5.5.5", "type": "ip", "external": true }],
  "enrichment": {
    "5.5.5.5": {
      "virustotal": { "status": "ok", "malicious": 7, "suspicious": 1 },
      "abuseipdb": { "status": "ok", "abuse_confidence_score": 100, "total_reports": 42 }
    }
  },
  "verdict": {
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "justification": "Login attempt with a non-existent user from an IP flagged by 7 VT engines and 100% AbuseIPDB confidence.",
    "mitre": { "id": "T1110", "name": "Brute Force" },
    "next_action": "Block 5.5.5.5 at the firewall and review auth logs from this source.",
    "risk_score": 8
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

v1 is built incrementally, one component at a time, each with tests before moving on.
The full pipeline is built and tested (**180 tests, deterministic, no network**); only the
operational Shuffle wiring remains.

- [x] **Parser** — alert classification + IOC extraction · _25 tests_
- [x] **Enricher** — VirusTotal + AbuseIPDB, rate limiting + cache · _21 tests_
- [x] **Reasoner** — local LLM verdict (Ollama), strict-JSON contract + conservative fallback · _46 tests_
- [x] **Router** — Prism's create-a-case-or-discard decision (conservative escalation) · _29 tests_
- [x] **Logger** — CSV audit row for **every** alert, including discarded ones · _23 tests_
- [x] **FastAPI service** — `POST /analyze` orchestration (`main.py`) · _9 tests_
- [ ] **Shuffle integration** — operational wiring with the SOC team

**v2 (planned):** runtime learning (RAG + ChromaDB), direct case creation in TheHive,
automatic FP filtering driven by v1 metrics.

---

## Tech stack

**Python 3.10+** · FastAPI · Ollama (local LLM) · VirusTotal API · AbuseIPDB API ·
integrates with Wazuh and Shuffle. No data leaves the host.

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

## Run the service

```bash
python main.py            # serves on SERVICE_HOST:SERVICE_PORT (default 0.0.0.0:8000)
# then POST a Wazuh alert:
curl -X POST localhost:8000/analyze -H "Content-Type: application/json" \
     -d @data/sample_alerts/ssh_attack.json
```

> The reasoner needs a reachable Ollama host (`OLLAMA_HOST` in `.env`). Without one, the
> pipeline still responds — it returns a conservative `NEEDS_REVIEW` verdict and logs the
> alert, never crashing.

## Tests

```bash
pytest -q
```

## Structure

```
main.py     FastAPI service — POST /analyze pipeline orchestration
tools/      Execution tools (parser, enricher, reasoner, router, logger)
workflows/  Per-component SOPs (WAT)
tests/      Deterministic tests for each tool
docs/       Architecture and conventions
data/       Anonymized alert fixtures
.claude/    Dev harness: subagents, commands, hooks
```

© 2026 Mateo Ulla · Sample alerts are anonymized; no real or company data is included.
