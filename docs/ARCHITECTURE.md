# ARCHITECTURE.md — Technical Design

Source of truth for technical decisions. Load before writing or modifying `tools/parser.py`,
`enricher.py`, or `reasoner.py`, or when in doubt about alert structure / output format.

## Data flow (v1)

```
Wazuh alert (JSON)
  → main.py [POST /analyze]
  → parser.py     classify type + extract IOCs
  → external IOCs?  yes → enricher.py (VirusTotal + AbuseIPDB, in parallel)
                    no  → skip enrichment
  → reasoner.py   LLM (Ollama) → structured verdict
  → router.py     decide action (v1: ALWAYS return to Shuffle)
  → logger.py     record metrics in CSV
  → JSON response to Shuffle
```

## Input format
The alert may arrive wrapped (`{_source:{...}}`) or as the `_source` directly. The parser
handles both: `alert.get('_source', alert)`.

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

## Reasoner output contract (strict JSON)

```json
{
  "verdict": "TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW",
  "confidence": "HIGH | MEDIUM | LOW",
  "justification": "max 3 sentences",
  "mitre": { "id": "TXXXX", "name": "technique" },
  "next_action": "concrete action",
  "risk_score": 1
}
```
`risk_score`: integer 1–10. `mitre` may be `null`.

## Design decisions (with rationale)
- **Direct APIs instead of Cortex:** lower latency, no SOAR dependency, control over format.
- **Conditional enrichment:** 85% have no external IOCs; enriching everything wastes quota.
- **v1 always returns to Shuffle (no auto FP filtering):** avoids missing a real alert due to LLM error;
  automatic filtering will be validated with v1 metrics in v2.
- **Local LLM (Ollama):** sensitive data is not exposed to external APIs.
- **Don't rebuild what Wazuh already provides:** GeoLocation is included in network/SSH alerts.

## Known technical constraints
- VirusTotal free API: ~4 req/min. Handle rate limiting in the enricher.
- Do not enrich private IPs (192.168.x, 10.x, 172.16-31.x).
