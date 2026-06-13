# parser.md — Alert Classification & IOC Extraction

**Objective:** Classify Wazuh alerts into one of 5 types, extract IOCs with metadata, detect known FP candidates.

**Input:** Wazuh alert (wrapped in `_source` or direct object).

**Output contract:**
```json
{
  "alert_type": "network|ssh|windows_event|vulnerability|virustotal|unknown",
  "rule_id": "string",
  "rule_level": "int",
  "rule_description": "string",
  "agent_name": "string",
  "iocs": [{"value": "string", "type": "ip|user|hash|cve", "external": bool}],
  "has_external_iocs": "bool",
  "nature_category": "public_attack|internal_movement|informational|unknown",
  "context": "dict (type-specific metadata)",
  "is_known_fp_candidate": "bool"
}
```

---

## Classification order (strict precedence)

Detection by decoder/location (order matters; first match wins):
1. **vulnerability** → `location == "vulnerability-detector"`
2. **virustotal** → `location == "virustotal"` (hash already enriched by Wazuh)
3. **network** → `decoder.name == "ar_log_json"` (firewall blocks, active_response)
4. **ssh** → `decoder.name == "sshd"` (brute-force, login attempts)
5. **windows_event** → `decoder.name == "windows_eventchannel"` (Windows events, rule 60602 dominant FP)
6. **unknown** → no match (fallback; no external IOCs)

---

## IOC extraction

| Type | IOCs extracted |
|------|---|
| **network** | Attack srcip + blocked srcip (marked external if public), nested srcip from `data.parameters.alert.data.srcip` |
| **ssh** | Source srcip (marked external if public), source username |
| **windows_event** | None (no external IOCs; event metadata only) |
| **vulnerability** | CVE ID (external=False; v1 skips enrichment) |
| **virustotal** | MD5, SHA1, SHA256 hashes (external=False; already enriched by Wazuh) |
| **unknown** | None |

**Private IPs:** included as IOCs with external=False (e.g., 192.168.x, 10.x, 172.16-31.x). Public IPs marked external=True and passed to enricher.
Determined via `ipaddress.ip_address(str).is_private`.

---

## Categorization by nature (v1 axis)

**Purpose:** Distinguish alerts by origin/intent. Focus v1 on external threats.

**Categories:** `public_attack` (external IP + known threat pattern) | `internal_movement` (host-to-host) | `informational` (system noise) | `unknown` (default).
- Criteria: configurable module-level constants (INFORMATIONAL_GROUPS, INTERNAL_MOVEMENT_GROUPS, PUBLIC_ATTACK_SIGNATURES).

**Public attack detection:** Match decoder + groups (from alert.rule) against module-level `PUBLIC_ATTACK_SIGNATURES` constant AND require `srcip` to be public (external, not loopback/link-local). Signature list is configurable (dict keys: decoder, groups list):
```python
PUBLIC_ATTACK_SIGNATURES = [
  {"decoder": "ar_log_json", "groups": ["active_response", "ossec"]},  # firewall blocks
  {"decoder": "apache-errorlog", "groups": ["apache", "web", "invalid_request"]},  # web attacks
]
```

**Default:** alerts not matching any criterion → `"unknown"` (string, not null). Guard for rule.groups not-list (no exception).

**Extend:** add dicts to `PUBLIC_ATTACK_SIGNATURES` as new patterns emerge; no code changes needed.

---

## Known FP detection

**Rule 60602** (Windows SPP service) → `is_known_fp_candidate = True`.
(61% of real corpus, test case #1.)

---

## Running tests

```bash
"C:/Users/usuario/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m pytest tests/test_parser.py -v
```

**Coverage:** 6 fixtures (network, auth, malware, vulnerability, system, known FP).

---

## Implementation notes

- Handles both `_source`-wrapped and direct alert formats.
- IOC type inferred by regex/pattern matching (IP, CIDR, domain, hash, CVE regex).
- Output is always valid JSON, ready for the enricher pipeline.
- No external API calls; purely structural and regex-based.
