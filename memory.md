# memory.md — Development Memory

Persistent memory across sessions (self-improvement / self-healing of the development process).

**Written here:** when the user corrects something or asks to remember something (immediately,
concisely); when a non-trivial error is resolved; when a constraint or quirk is discovered.
**Read:** at the start of each session, after reviewing `init.sh` output.
**Written by:** the `scribe` subagent.
**Hygiene:** entries of 1–2 lines. Compact if redundant. Do not delete user decisions without
confirmation. Keep the file under 200 lines.

Format: `[date] category — learning / decision`.

---

## User decisions (do not change without confirmation)
- [2026-06] v1 scope = webhook + intelligence analysis (replaces Cortex, detects FPs),
  returns to Shuffle. TheHive, runtime learning, and automatic FP filtering are v2.
- [2026-06] v1 uses DEVELOPMENT memory, not runtime learning.
- [2026-06] Local LLM with Ollama, no data exposure. Actual model: qwen2.5:3b (CPU-only, ~500ms warm inference, ~8-9s cold start) → OLLAMA_TIMEOUT=30s default.
- [2026-06] Dev of parser/enricher on Windows (no server). Reasoner with remote Ollama
  (option A). Final deployment on the server (option B).
- [2026-06] Server connection via SSH from Git Bash (not PuTTY). VPN FortiClient first.
- [2026-06] Workflows created one by one as each tool is finished, not in advance.
- [2026-06] Input confirmed: JSON arrives directly from Wazuh to Prism via webhook POST /analyze.
  Shuffle does NOT transform it; all alert fields (decoder.name, rule.groups, GeoLocation, data.srcip, etc.) are intact and trustworthy.
- [2026-06] Categorization by nature (NEW AXIS): public_attack / internal_movement / informational / unknown (default).
  Criteria: module-level configurable constants. Evaluation order: public_attack → internal_movement → informational → unknown.
- [2026-06] v1 focus narrows to PUBLIC indicators: attacks from external IPs targeting exposed assets.
- [2026-06] rule.level discarded as filtering gate: corpus showed it does not separate attack from noise
  (external IPs fall in levels 3 and 5; levels 9–10 are internal noise e.g., Windows SPP FP). No "lightweight path without LLM" by level.
- [2026-06] PRISM decides create-or-not-case (not Shuffle). Router routes by verdict: FALSE_POSITIVE → discard (send_to_shuffle=False); TRUE_POSITIVE/NEEDS_REVIEW → create_case (send_to_shuffle=True); missing/unknown verdict → defensive escalation (create_case, never discard on doubt). Mandatory audit trail: parsed["routing"]["reason"] persisted by logger for every alert (including discarded).
- [2026-06] Public attack detection: match decoder + groups against configurable list AND external srcip (public).
  List is CONFIGURABLE (config file or constant, never hardcoded); extends over time. Initial list (3-day corpus):
  `ar_log_json` + `active_response`/`ossec` (firewall blocks); `apache-errorlog` + `apache`/`web`/`invalid_request` (web attacks).
- [2026-06] Shodan discarded (paid). OTX → v2 candidate.
- [2026-06] Project language is ENGLISH: all code, comments, docstrings, `.md` docs, and commit
  messages are written in English even when the user's prompts/discussion are in Spanish.

## Technical learnings
- [2026-06] Enrichment interpretation rules added to reasoner prompt (not code): qwen2.5:3b was ignoring strong enrichment signals (e.g., AbuseIPDB score=100, VT malicious=16) and returning NEEDS_REVIEW. Thresholds now explicit in prompt (score≥80 + reports≥10 → TRUE_POSITIVE; VT malicious≥5 → TRUE_POSITIVE).
- [2026-06] Risk_score calibration: FALSE_POSITIVE alerts must return 1–2, critical TRUE_POSITIVE attacks 8–10. Rule enforced in prompt via _PROMPT_PREFIX conservative-bias section (not code-level guardrail). Calibration ensures verdict and risk_score align.
- [2026-06] Live smoke test (windows_spp_error.json vs. real Ollama, qwen2.5:3b): verdict FALSE_POSITIVE, confidence HIGH, risk_score 1, latency 9873 ms (cold start ~9s, within 30s timeout). Confirms valid JSON contract, format rule honored, calibration rule applied.
- [2026-06] Real corpus: 6,320 alerts / 3 days. 61% is a single FP: Rule 60602 (Windows SPP
  service, on an endpoint agent, every ~30s). Test case #1 for FP detection.
- [2026-06] ~85% of alerts have no external IOCs → conditional enrichment.
- [2026-06] Wazuh already includes GeoLocation in network/SSH alerts. Do not geolocate separately.
- [2026-06] VirusTotal free API ≈ 4 req/min. Handle rate limiting in the enricher.
- [2026-06] Enricher clients (RateLimiter + TTLCache) must be module-level singletons in main.py
  and injected via clients= param, or VT rate limit won't hold across alerts.
- [2026-06] Dependencies (requests, python-dotenv) installed system-wide Python 3.14 via
  `pip install --isolated` (venv pip.ini broken). Both in requirements.txt.
- [2026-06] Conservative bias enforced in reasoner CODE: FP guardrail (FALSE_POSITIVE + confidence != HIGH → NEEDS_REVIEW downgrade); all failure paths (timeout, connection, JSON invalid, contract violation) fall back to NEEDS_REVIEW/LOW. Never crash, never discard an alert.
- [2026-06] Ollama `format: "json"` + `temperature=0` force strict JSON from qwen2.5:3b; output still validated defensively (extract `{...}`, normalize enums, coerce risk_score to int 1–10, null malformed mitre).
- [2026-06] WAT docs drift silently from actual tool code: pre-router audit found `workflows/*.md` documented non-existent nested verdicts (`verdict.classification`, `mitre_tags`) that never existed in actual `tools/reasoner.py` (which returns flat dict). Before building any downstream consumer (router, logger, main), verify each tool's output contract against the actual tool code, not just the `.md` (reviewer audit caught this before router was built on a wrong contract).

## Resolved errors
- [2026-06] Project venv's pip.ini has global `target` pointing to Python 3.12 dir; breaks
  `pip install` for 3.14 venv. Workaround: run tests directly with 3.14 interpreter:
  `"C:/Users/usuario/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m pytest tests/...`
- [2026-06] RFC 5737 TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) return
  `is_private=True` in Python 3.11+. For public IP tests use 8.8.8.8 or 1.1.1.1 instead.

## Pending items (non-blocking)
- [2026-06] RESOLVED: OllamaClient now exposes a public `model` property; `reason()` reads
  `client.model` (no more `getattr(client, "_model")`).
