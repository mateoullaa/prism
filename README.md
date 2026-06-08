# Prism — SOC Alert Triage Agent

[![tests](https://github.com/mateoullaa/prism/actions/workflows/tests.yml/badge.svg)](https://github.com/mateoullaa/prism/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-v1%20in%20progress-orange)

> *Named **Prism** — a prism separates light from noise, which is exactly what this agent does with security alerts.*

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
  MITRE technique, next action, risk score).
- **router / logger** — return the verdict to Shuffle and record metrics for later analysis.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and rationale.

---

## Example (illustrative)

An SSH brute-force attempt comes in:

```json
{
  "rule": { "id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user" },
  "data": { "srcip": "5.5.5.5", "srcuser": "hacker" },
  "decoder": { "name": "sshd" },
  "GeoLocation": { "country_name": "Germany" }
}
```

Prism returns a reasoned verdict:

```json
{
  "alert_type": "ssh",
  "iocs": [{ "value": "5.5.5.5", "type": "ip", "external": true }],
  "enrichment": {
    "5.5.5.5": {
      "virustotal": { "malicious": 7, "suspicious": 1 },
      "abuseipdb":  { "abuse_confidence_score": 100, "total_reports": 42 }
    }
  },
  "verdict": "TRUE_POSITIVE",
  "confidence": "HIGH",
  "justification": "Login attempt with a non-existent user from an IP flagged by 7 VT engines and 100% AbuseIPDB confidence.",
  "mitre": { "id": "T1110", "name": "Brute Force" },
  "next_action": "Block 5.5.5.5 at the firewall and review auth logs from this source.",
  "risk_score": 8
}
```

---

## Project status

v1 is built incrementally, one component at a time, each with tests before moving on.

- [x] **Parser** — alert classification + IOC extraction · *25 tests*
- [x] **Enricher** — VirusTotal + AbuseIPDB, rate limiting + cache · *21 tests*
- [ ] **Reasoner** — local LLM verdict (Ollama)
- [ ] **Router / Logger** — return to Shuffle + CSV metrics
- [ ] **FastAPI service** — `POST /analyze` orchestration
- [ ] **Shuffle integration**

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

## Tests

```bash
pytest -q
```

## Structure

```
tools/      Execution tools (parser, enricher, reasoner, router, logger)
workflows/  Per-component SOPs (WAT)
tests/      Deterministic tests for each tool
docs/       Architecture and conventions
data/       Anonymized alert fixtures
.claude/    Dev harness: subagents, commands, hooks
```

---

## License

[MIT](LICENSE) © 2026 Mateo Ulla · *Sample alerts are anonymized; no real or company data is included.*
