# Prism

*Named Prism — because a prism separates light from noise, which is exactly what this agent does with security alerts.*

SOC alert triage agent. Receives Wazuh alerts (webhook), classifies their type,
enriches IOCs with public threat intelligence APIs, and uses a local LLM (Ollama)
to classify false positives, map MITRE ATT&CK techniques, and recommend next steps.
The structured verdict is returned to the orchestration workflow (Shuffle).

Designed to run **on-premise with a local model**, without exposing sensitive data.

## Why

On a real corpus of 6,320 alerts over 3 days, 61% were a single recurring false positive.
This agent automates the initial intelligence layer of triage.

## Architecture

**WAT pattern (Workflows, Agents, Tools)**: separates LLM reasoning from deterministic
Python execution. Development uses a Claude Code multi-agent harness
(orchestrator + builder + reviewer + scribe). See `docs/ARCHITECTURE.md`.

## Stack

Python 3.10+ · FastAPI · Ollama (local LLM) · VirusTotal API · AbuseIPDB API ·
integration with Wazuh and TheHive via Shuffle.

## Setup

```bash
git clone <repo> && cd prism
python -m venv .venv && source .venv/Scripts/activate   # Git Bash on Windows
pip install -r requirements.txt
cp .env.example .env   # fill in API keys and Ollama host
bash init.sh           # health check
```

## Structure

```
tools/      Execution tools (parser, enricher, reasoner, router, logger)
workflows/  SOPs per component (WAT)
tests/      Tests for each tool
docs/       Architecture, conventions, context
data/       Anonymized alert fixtures
.claude/    Harness: subagents, commands, hooks
```

## Roadmap

- **v1**: webhook + intelligence analysis → Shuffle.
- **v2**: runtime learning (RAG + ChromaDB), direct case creation in TheHive, automatic FP filtering.

_Sample alerts are anonymized._
