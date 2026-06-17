# ARCHITECTURE.md — Technical Design

Source of truth for technical decisions. Load before writing or modifying `tools/parser.py`,
`enricher.py`, or `reasoner.py`, or when in doubt about alert structure / output format.

## Data flow (v1)

```
Wazuh alert (JSON)
  → main.py [POST /analyze]
  → parser.py     classify type + extract IOCs + categorize by nature
  → external IOCs?  yes → enricher.py (VirusTotal + AbuseIPDB, in parallel)
                    no  → skip enrichment
  → reasoner.py   LLM (Ollama) → structured verdict
  → router.py     Prism decides: create case or not (audit-driven)
                  Only alerts warranting a case → Shuffle
  → logger.py     record metrics in CSV + audit trail (all discarded alerts with reason)
  → JSON response to Shuffle or drop (with logging)
```

## Input format
Wazuh alert arrives directly via webhook POST /analyze. Shuffle does NOT transform it.
Alert may be wrapped (`{_source:{...}}`) or as the `_source` directly. Parser handles both: `alert.get('_source', alert)`.
All fields (decoder.name, rule.groups, GeoLocation, data.srcip, etc.) are intact and trustworthy.

## Alert types and field paths

**Type 1 — Windows Event** · detection: `decoder.name == "windows_eventchannel"` · no external IOCs
- `rule.id`, `rule.level`, `rule.description`, `rule.groups`
- `data.win.system.eventID` / `.computer` / `.message`
- `agent.name`
- Rule 60602 (EventID 16385, SPP service) = dominant FP (61% of corpus).

**Type 2 — Network/Firewall** · detection: `decoder.name == "ar_log_json"` (group `active_response`) · IOC: srcip
- `data.srcip` (blocked IP)
- `data.parameters.alert.data.srcip` (original attack IP)
- `data.parameters.alert.rule.description`
- `GeoLocation.country_name`, `GeoLocation.location` (already provided by Wazuh)

**Type 3 — SSH attack** · detection: `decoder.name == "sshd"` · IOCs: srcip + srcuser
- `data.srcip`, `data.srcuser`, `rule.firedtimes`, `full_log`, `GeoLocation`

**Type 4 — Vulnerability** · detection: `location == "vulnerability-detector"` · IOC: CVE (no external API)
- `data.vulnerability.cve` / `.severity` / `.score.base` (CVSS) / `.rationale` / `.package.name`

**Type 5 — VirusTotal** · detection: `location == "virustotal"` · hash already enriched
- `data.virustotal.malicious` / `.found` / `.source.md5` / `.source.sha1` / `.source.file`

**Key fact:** ~85% of alerts have no external IOCs → conditional enrichment.
The parser decides; if no external IOC, goes directly to the reasoner.

## Categorization by nature

Alerts classified on a separate axis by nature (independent of technical type):
- **public attack:** external IP targeting exposed asset. Firm criterion: match decoder + groups against PUBLIC_ATTACK_SIGNATURES (loaded from `config/known_patterns.json`) AND srcip is public.
- **informational:** non-attack alert (e.g., log rotation, service start). Criterion: rule.groups match INFORMATIONAL_GROUPS (from config, with code defaults fallback).
- **internal movement:** internal host-to-host or host-to-service traffic. Criterion: rule.groups match INTERNAL_MOVEMENT_GROUPS (from config, with code defaults fallback).

v1 focus is on detecting PUBLIC ATTACKS (public threat indicators).

## Public attack detection

**Criterion:** match decoder + groups against configurable list AND srcip is public (not 192.168.*, 10.*, 172.16–31.*).

**Configurable list** (loaded from `config/known_patterns.json` at runtime; with code `_DEFAULTS` as fallback):
- `ar_log_json` + groups `active_response`, `ossec` → firewall block alerts
- `apache-errorlog` + groups `apache`, `web`, `invalid_request` → web attacks

List refined with corpus data over time. Parser loader handles missing/malformed config gracefully (per-key fallback to code defaults, no exception).

## Reasoner output contract (strict JSON)

**Verdict** (parsed["verdict"]):
```json
{
  "verdict": "TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW",
  "confidence": "HIGH | MEDIUM | LOW",
  "justification": "max 3 sentences",
  "mitre": { "id": "TXXXX", "name": "technique" },
  "next_action": "concrete action",
  "risk_score": 1-10
}
```
`risk_score`: integer 1–10. `mitre` may be `null`.

**Metadata** (parsed["reasoner_meta"]):
```json
{
  "status": "ok | fallback",
  "fallback_reason": "string | null",
  "model": "string",
  "latency_ms": 0,
  "downgrade_note": "string (optional; present only on FP guardrail downgrade)"
}
```
- `status="ok"` on successful LLM analysis; `fallback_reason=null`.
- `status="fallback"` on any error (timeout, connection, HTTP!=200, JSON invalid, contract violation, build_prompt error); `fallback_reason` populated; verdict is conservative NEEDS_REVIEW.
- `downgrade_note` present only when FP guardrail downgrades FALSE_POSITIVE (confidence != HIGH) → NEEDS_REVIEW.

**Conservative bias:** on doubt, reasoner returns `NEEDS_REVIEW` (not `FALSE_POSITIVE`); router routes to Shuffle (create case). Never discard on LLM uncertainty.

## Design decisions (with rationale)
- **Direct APIs instead of Cortex:** lower latency, no SOAR dependency, control over format.
- **Conditional enrichment:** 85% have no external IOCs; enriching everything wastes quota.
- **Prism decides create-or-not-case (not Shuffle):** audit-driven filtering; logger must record all discarded alerts with reason (mandatory audit trail).
  Router is conservative: on doubt (NEEDS_REVIEW), create case; never discard on LLM uncertainty.
- **Local LLM (Ollama):** sensitive data is not exposed to external APIs.
- **Don't rebuild what Wazuh already provides:** GeoLocation is included in network/SSH alerts.
- **rule.level discarded as filtering gate:** corpus evidence (external IPs fall in levels 3–5; levels 9–10 are internal noise) shows rule.level
  does not separate attack from FP. No "lightweight path without LLM" by level.
- **Shodan discarded (paid service).** OTX → v2 candidate for additional enrichment.

## Known technical constraints
- VirusTotal free API: ~4 req/min. Handle rate limiting in the enricher.
- Do not enrich private IPs (192.168.x, 10.x, 172.16-31.x).
