# parser.md — Alert Classification & IOC Extraction

**Objective:** Classify Wazuh alerts into one of 5 types, extract IOCs with metadata, detect known FP candidates.

**Input:** Wazuh alert (wrapped in `_source` or direct object).

**Output contract:**
```json
{
  "alert_type": "network|auth|malware|vulnerability|system",
  "rule_id": "string",
  "rule_level": "int",
  "rule_description": "string",
  "agent_name": "string",
  "iocs": [{"value": "string", "type": "ip|domain|hash|cve", "external": bool}],
  "has_external_iocs": "bool",
  "context": "dict (raw timestamp, mitre, etc)",
  "is_known_fp_candidate": "bool"
}
```

---

## Classification order (strict precedence)

1. **malware** → decoder.name="json" AND location contains "virustotal"
2. **vulnerability** → rule_id∈{18000..18999}
3. **auth** → rule_id∈{5000..5999}
4. **network** → rule_id∈{4000..4999}
5. **system** → all others

(Uses `location` before `decoder.name` to disambiguate: virustotal and CVE both have decoder.name=="json".)

---

## IOC extraction

| Type | IOCs extracted |
|------|---|
| **network** | Source/dest IPs (private included, external=False), domains, ports, hashes |
| **auth** | IPs from failed login contexts (private=external:False), usernames |
| **malware** | SHA256/MD5 hashes (external=False if v1, i.e., already from VirusTotal JSON), domains |
| **vulnerability** | CVE IDs (external=False, v1 enrichment is conditional), affected IPs |
| **system** | Usernames, file hashes, process paths |

**Private IPs:** included as IOCs with external=False. Filtered via `ipaddress.ip_address(str).is_private`.

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
