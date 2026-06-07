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
- [2026-06] Local LLM with Ollama, no data exposure. Suggested initial model: qwen2.5:7b
  (adjust based on server specs and JSON output quality). the team uses llama.
- [2026-06] Dev of parser/enricher on Windows (no server). Reasoner with remote Ollama
  (option A). Final deployment on the server (option B).
- [2026-06] Server connection via SSH from Git Bash (not PuTTY). VPN FortiClient first.
- [2026-06] Workflows created one by one as each tool is finished, not in advance.

## Technical learnings
- [2026-06] Real corpus: 6,320 alerts / 3 days. 61% is a single FP: Rule 60602 (Windows SPP
  service, an endpoint agent, every ~30s). Test case #1 for FP detection.
- [2026-06] ~85% of alerts have no external IOCs → conditional enrichment.
- [2026-06] Wazuh already includes GeoLocation in network/SSH alerts. Do not geolocate separately.
- [2026-06] VirusTotal free API ≈ 4 req/min. Handle rate limiting in the enricher.

## Resolved errors
(empty)
