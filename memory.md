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
- [2026-06] Risk_score calibration (valid LLM JSON only): FALSE_POSITIVE 1–2, TRUE_POSITIVE 8–10, enforced in prompt via _PROMPT_PREFIX. Fallback verdicts use fixed risk_score=5 (independent of calibration). Ensures verdict and risk_score align.
- [2026-06] All 6 reasoner fixtures validated live (2026-06-21): 4/6 valid JSON; 2/6 (vulnerability.json, windows_logon.json) → fallback. virustotal.json: FP guardrail worked (downgraded FALSE_POSITIVE/non-HIGH → NEEDS_REVIEW). ssh_attack.json "Enrichment: unavailable" is a runner artifact — `reasoner.py` `__main__` never calls `enrich()` (main.py pipeline does); .env keys irrelevant there; not a bug.
- [2026-06] Contract-validation fallback RESOLVED: qwen2.5:3b omits `risk_score` on NEEDS_REVIEW/LOW verdicts. Fix in _validate_verdict(): if verdict==NEEDS_REVIEW and risk_score is None, default to 5 (logged at INFO); TRUE_POSITIVE/FALSE_POSITIVE with missing risk_score still fatal (calibration-significant). Both previously-failing fixtures (vulnerability.json, windows_logon.json) now return status=ok with real LLM justification. 189 tests passing.
- [2026-06] Real corpus: 6,320 alerts / 3 days. 61% is a single FP: Rule 60602 (Windows SPP
  service, on an endpoint agent, every ~30s). Test case #1 for FP detection.
- [2026-06] ~85% of alerts have no external IOCs → conditional enrichment.
- [2026-06] Wazuh already includes GeoLocation in network/SSH alerts. Do not geolocate separately.
- [2026-06] VirusTotal free API ≈ 4 req/min. Handle rate limiting in the enricher.
- [2026-06] Enricher clients (RateLimiter + TTLCache) must be module-level singletons in main.py
  and injected via clients= param, or VT rate limit won't hold across alerts.
- [2026-06] Conservative bias enforced in reasoner CODE: FP guardrail (FALSE_POSITIVE + confidence != HIGH → NEEDS_REVIEW downgrade); all failure paths (timeout, connection, JSON invalid, contract violation) fall back to NEEDS_REVIEW/LOW. Never crash, never discard an alert.
- [2026-06] Ollama `format: "json"` + `temperature=0` force strict JSON from qwen2.5:3b; output still validated defensively (extract `{...}`, normalize enums, coerce risk_score to int 1–10, null malformed mitre).
- [2026-06] WAT docs drift silently from actual tool code: pre-router audit found `workflows/*.md` documented non-existent nested verdicts (`verdict.classification`, `mitre_tags`) that never existed in actual `tools/reasoner.py` (which returns flat dict). Before building any downstream consumer (router, logger, main), verify each tool's output contract against the actual tool code, not just the `.md` (reviewer audit caught this before router was built on a wrong contract).
- [2026-06] Mandatory audit-trail design: logger persists EVERY alert including discarded FALSE_POSITIVEs with router reason (verdict, confidence, fallback/downgrade context). No silent discards — SOC audits every decision and discovers patterns (e.g., all FPs from Rule 60602). Transparency, accountability, and learning enabler.
- [2026-06] main.py endpoint is SYNC (blocking), so FastAPI runs it in threadpool; enricher+Ollama clients are module-level singletons injected via get_pipeline() dependency (tests override). Ensures VT rate-limit/TTLCache hold across concurrent requests (critical for high-volume v1).
- [2026-06] Defensive last-resort catch-all wraps main orchestration: any unexpected error returns HTTP 200 + conservative create_case escalation body (never 500), AND writes best-effort CSV audit row (wrapped, never re-raises). Honors mandatory "every alert logged" invariant even on catastrophic pipeline failure.
- [2026-06-21] BUG RESOLVED — few-shot example in `_PROMPT_PREFIX` (tools/reasoner.py line 150) contained SSH-specific justification text ("invalid usernames", "brute-force credential stuffing") that qwen2.5:3b occasionally copied verbatim into unrelated alerts (e.g. firewall_block.json), producing hallucinated SSH content. Root cause confirmed: payload idempotency test (`test_reason_idempotent_payload`, 5× same dict, 190 tests passing) proved our code is clean — the example text was the sole source. Fix: replaced with a domain-neutral example (`"mitre": null`, generic language). Verified: 5/5 live runs post-fix with no SSH bleed, consistent firewall-specific justifications.
- [2026-06-21] BUG RESOLVED — qwen2.5:3b inverted the semantic of abuse_confidence_score: it read the integer 100 as "low / not strong evidence" instead of the maximum value on a 0–100 scale, then ignored VirusTotal in cascade after that misread. Root cause: asking a 3b model to apply numeric threshold comparisons from prose rules is structurally unreliable. Fix: threshold evaluation moved to Python (_evaluate_enrichment(), named constants _ABUSEIPDB_SCORE_THRESHOLD=80, _ABUSEIPDB_REPORTS_THRESHOLD=10, _VT_MALICIOUS_THRESHOLD=5); model now receives pre-evaluated conclusions ("threshold MET -> HIGH RISK" / "threshold NOT MET -> LOW RISK") instead of raw numbers. ENRICHMENT INTERPRETATION RULES in prompt simplified to four lines describing what HIGH/LOW RISK mean. Verified: 5/5 live runs TRUE_POSITIVE/HIGH/risk=8, consistent, no cascade failure.
- [2026-06-21] DESIGN PRINCIPLE — never delegate numeric threshold comparisons to a small LLM when Python can evaluate them deterministically. Pre-evaluate and inject conclusions; reserve LLM judgment for semantic/contextual decisions where code cannot decide.
- [2026-06-21] OTX enrichment (v2 item 1): OTXClient mirrors VirusTotal/AbuseIPDB pattern. Endpoint GET v1/indicators/IPv4/{ip}/general, header X-OTX-API-KEY. Normalizes pulse_count (from pulse_info.count) + reputation. RateLimiter bucket 60 req/min (capacity 60 / 60s). Reasoner threshold _OTX_PULSE_THRESHOLD=1 (pulse_count≥1 → HIGH RISK); evaluated in Python per design principle.
- [2026-06-21] _build_default_clients() now 3-tuple (VirusTotal, AbuseIPDB, OTX) sharing one session + TTLCache. Caught regression in test_main.py/test_pipeline.py where client-tuple unpacking sites must update when adding providers. Parallel queries max_workers=6; 221 tests passing.
- [2026-06-22] OTX error cache (v2): TTLCache(ttl=60, maxsize=1000) privado en OTXClient previene reintentos de IPs lentas/Tor dentro del minuto. Reduce impacto de 185.220.101.1 y similares de 10s por alerta a 10s una sola vez/minuto. Status "error" del cache es idéntico al error real — _evaluate_enrichment() en reasoner los descarta igual (allowlist solo "ok"/"cached"). No hay gap en flujo. TTLCache también recibe maxsize opcional (backward-compatible). 225 tests passing.

## Resolved errors
- [2026-06-21] SSH hallucination in firewall_block alerts: few-shot example in _PROMPT_PREFIX seeded SSH vocabulary into model attention. Fixed by domain-neutral example with mitre=null. 5/5 live runs clean. 190 tests passing.
- [2026-06-21] abuse_confidence_score semantic inversion (3b model read 100 as "low"): moved threshold evaluation to Python _evaluate_enrichment(); model reads pre-evaluated risk labels. 5/5 live TRUE_POSITIVE/HIGH. 206 tests passing.
- [2026-06] pip: global `global.target` setting pointed to OLD Python 3.12 (revealed by `pip config list`), forcing installs to wrong location. Fixed with `python -m pip config unset global.target`; pip then installed normally into 3.14 venv. (Supersedes earlier "--isolated" and "hardcoded interpreter" workarounds.)
- [2026-06] RFC 5737 TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) return
  `is_private=True` in Python 3.11+. For public IP tests use 8.8.8.8 or 1.1.1.1 instead.

## Pending items (non-blocking)
- [2026-06] RESOLVED: OllamaClient now exposes a public `model` property; `reason()` reads
  `client.model` (no more `getattr(client, "_model")`).
- [2026-06] Rule 61061 (Windows SPP aggregation) is the grouping rule for 60602 errors. Both emitted by production; treat as known FP pair. Listed in `config/known_patterns.json` under `known_fp_rule_ids`.
- [2026-06] Parser classification lists (INFORMATIONAL_GROUPS, INTERNAL_MOVEMENT_GROUPS, PUBLIC_ATTACK_SIGNATURES, KNOWN_FP_RULE_IDS) externalized to `config/known_patterns.json`. Loader in parser.py: per-key fallback to code `_DEFAULTS` if file missing or key malformed; no exception, no silent degradation (logs warning + uses default). Safe for hand-edits to config without breaking pipeline.
