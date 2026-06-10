"""
parser.py — Wazuh alert parser for the AI triage pipeline.

Classifies an alert by type, extracts IOCs, categorizes by nature, and returns
a structured dict ready for the enricher or reasoner. No external calls; pure stdlib.
"""

import ipaddress
from typing import Any


# ---------------------------------------------------------------------------
# Configurable list of (decoder, groups) signatures for public attack detection.
#
# An alert is classified as "public_attack" when:
#   (a) decoder.name == entry["decoder"]  AND
#   (b) at least ONE of entry["groups"] appears in rule.groups  AND
#   (c) at least one relevant srcip in the alert is a public (non-private) IP.
#
# Extend this list as new attack patterns are observed in corpus data.
# rule.level is intentionally excluded — corpus evidence shows it does not
# separate attacks from noise (external IPs appear across levels 3–5;
# levels 9–10 are dominated by internal events).
# ---------------------------------------------------------------------------
PUBLIC_ATTACK_SIGNATURES: list[dict] = [
    {
        # Firewall-drop active response blocks: the original attack IP is also
        # available at data.parameters.alert.data.srcip in addition to data.srcip.
        "decoder": "ar_log_json",
        "groups": ["active_response", "ossec"],
    },
    {
        # Direct Apache error-log web attacks.
        "decoder": "apache-errorlog",
        "groups": ["apache", "web", "invalid_request"],
    },
]

# ---------------------------------------------------------------------------
# Configurable group lists for the informational and internal_movement categories.
#
# INFORMATIONAL_GROUPS — rule.groups values that indicate non-actionable noise
# (e.g. Windows service errors, dpkg packaging events).  Match ANY group present.
#
# INTERNAL_MOVEMENT_GROUPS — rule.groups values that indicate internal activity
# with no public IP (auth events, file-integrity checks, group changes, PAM/sudo,
# vulnerability scan hits, VirusTotal syscheck callbacks).  Match ANY group present.
#
# Evaluation order in _categorize_by_nature is STRICT:
#   (1) public_attack  →  (2) internal_movement  →  (3) informational  →  "unknown"
# This means public_attack always wins even if an alert also carries an
# internal_movement or informational group.
# ---------------------------------------------------------------------------
INFORMATIONAL_GROUPS: list[str] = [
    "system_error",
    "windows_application",
    "dpkg",
]

INTERNAL_MOVEMENT_GROUPS: list[str] = [
    "authentication_success",
    "authentication_failed",
    "group_changed",
    "win_group_changed",
    "syscheck",
    "syscheck_entry_added",
    "syscheck_entry_modified",
    "WEF",
    "pam",
    "sudo",
    "vulnerability-detector",
    "virustotal",
]


def _get(src: dict, path: str, default: Any = None) -> Any:
    """Safely retrieve a nested value using a dot-separated path."""
    keys = path.split(".")
    node = src
    for key in keys:
        if not isinstance(node, dict):
            return default
        node = node.get(key, default)
        if node is default:
            return default
    return node


def _is_external_ip(value: str) -> bool:
    """Return True if value is a valid, non-private IP address."""
    try:
        addr = ipaddress.ip_address(value)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False


def _classify(src: dict) -> str:
    """Determine the alert type. Order matters for overlapping decoders."""
    location = src.get("location", "")
    decoder_name = _get(src, "decoder.name", "")

    if location == "vulnerability-detector":
        return "vulnerability"
    if location == "virustotal":
        return "virustotal"
    if decoder_name == "ar_log_json":
        return "network"
    if decoder_name == "sshd":
        return "ssh"
    if decoder_name == "windows_eventchannel":
        return "windows_event"
    return "unknown"


def _categorize_by_nature(src: dict) -> str:
    """Categorize the alert on a separate, independent axis by its nature.

    Evaluation order is strict — the first matching rule wins:

    1. ``"public_attack"`` — decoder+groups match PUBLIC_ATTACK_SIGNATURES AND
       at least one source IP in the alert is a public (non-private) address.
       Source IP lookup checks both ``data.srcip`` and
       ``data.parameters.alert.data.srcip`` (the latter is the original attack
       IP present in ar_log_json active-response blocks).

    2. ``"internal_movement"`` — ANY of INTERNAL_MOVEMENT_GROUPS appears in
       rule.groups.  Covers auth events, file-integrity checks, group changes,
       PAM/sudo, vulnerability-detector, and VirusTotal callbacks.

    3. ``"informational"`` — ANY of INFORMATIONAL_GROUPS appears in
       rule.groups.  Covers non-actionable noise (service errors, dpkg events).

    4. ``"unknown"`` — no rule matched.  Never raises.
    """
    decoder_name: str = _get(src, "decoder.name", "") or ""
    rule_groups = _get(src, "rule.groups") or []
    if not isinstance(rule_groups, list):
        # A non-list rule.groups (e.g. a raw string) would turn `in` into
        # substring matching; treat it as a single-element list instead.
        rule_groups = [rule_groups]

    # ---- (1) public_attack ------------------------------------------------
    signature_matched = False
    for sig in PUBLIC_ATTACK_SIGNATURES:
        if decoder_name == sig["decoder"]:
            if any(g in rule_groups for g in sig["groups"]):
                signature_matched = True
                break

    if signature_matched:
        # Collect candidate source IPs and test for public addresses.
        candidate_ips: list[str] = []
        primary = _get(src, "data.srcip")
        if primary:
            candidate_ips.append(str(primary))
        nested = _get(src, "data.parameters.alert.data.srcip")
        if nested and nested not in candidate_ips:
            candidate_ips.append(str(nested))
        if any(_is_external_ip(ip) for ip in candidate_ips):
            return "public_attack"

    # ---- (2) internal_movement --------------------------------------------
    if any(g in rule_groups for g in INTERNAL_MOVEMENT_GROUPS):
        return "internal_movement"

    # ---- (3) informational ------------------------------------------------
    if any(g in rule_groups for g in INFORMATIONAL_GROUPS):
        return "informational"

    # ---- (4) fallback -----------------------------------------------------
    return "unknown"


def _extract_windows_event(src: dict) -> tuple[list[dict], dict, bool]:
    """Extract IOCs and context for windows_event alerts."""
    iocs: list[dict] = []
    rule_id = str(_get(src, "rule.id", "") or "")
    context = {
        "rule_id": rule_id,
        "rule_level": _get(src, "rule.level"),
        "event_id": _get(src, "data.win.system.eventID"),
        "computer": _get(src, "data.win.system.computer"),
        "agent_name": _get(src, "agent.name"),
    }
    is_fp = rule_id == "60602"
    return iocs, context, is_fp


def _extract_network(src: dict) -> tuple[list[dict], dict, bool]:
    """Extract IOCs and context for network/firewall alerts."""
    iocs: list[dict] = []

    blocked_ip = _get(src, "data.srcip")
    if blocked_ip:
        iocs.append({
            "value": blocked_ip,
            "type": "ip",
            "external": _is_external_ip(blocked_ip),
        })

    attack_ip = _get(src, "data.parameters.alert.data.srcip")
    if attack_ip and attack_ip != blocked_ip:
        iocs.append({
            "value": attack_ip,
            "type": "ip",
            "external": _is_external_ip(attack_ip),
        })

    context = {
        "rule_description": _get(src, "data.parameters.alert.rule.description"),
        "country": _get(src, "GeoLocation.country_name"),
    }
    return iocs, context, False


def _extract_ssh(src: dict) -> tuple[list[dict], dict, bool]:
    """Extract IOCs and context for SSH alerts."""
    iocs: list[dict] = []

    srcip = _get(src, "data.srcip")
    if srcip:
        iocs.append({
            "value": srcip,
            "type": "ip",
            "external": _is_external_ip(srcip),
        })

    srcuser = _get(src, "data.srcuser")
    if srcuser:
        iocs.append({
            "value": srcuser,
            "type": "user",
            "external": False,
        })

    context = {
        "firedtimes": _get(src, "rule.firedtimes"),
        "full_log": src.get("full_log"),
        "country": _get(src, "GeoLocation.country_name"),
    }
    return iocs, context, False


def _extract_vulnerability(src: dict) -> tuple[list[dict], dict, bool]:
    """Extract IOCs and context for vulnerability alerts."""
    iocs: list[dict] = []

    cve = _get(src, "data.vulnerability.cve")
    if cve:
        iocs.append({
            "value": cve,
            "type": "cve",
            "external": False,  # no external CVE API in v1
        })

    context = {
        "severity": _get(src, "data.vulnerability.severity"),
        "cvss_base": _get(src, "data.vulnerability.score.base"),
        "package": _get(src, "data.vulnerability.package.name"),
        "rationale": _get(src, "data.vulnerability.rationale"),
    }
    return iocs, context, False


def _extract_virustotal(src: dict) -> tuple[list[dict], dict, bool]:
    """Extract IOCs and context for VirusTotal alerts."""
    iocs: list[dict] = []

    md5 = _get(src, "data.virustotal.source.md5")
    if md5:
        iocs.append({"value": md5, "type": "hash", "external": False})

    sha1 = _get(src, "data.virustotal.source.sha1")
    if sha1:
        iocs.append({"value": sha1, "type": "hash", "external": False})

    context = {
        "malicious": _get(src, "data.virustotal.malicious"),
        "found": _get(src, "data.virustotal.found"),
        "file": _get(src, "data.virustotal.source.file"),
    }
    return iocs, context, False


_EXTRACTORS = {
    "windows_event": _extract_windows_event,
    "network": _extract_network,
    "ssh": _extract_ssh,
    "vulnerability": _extract_vulnerability,
    "virustotal": _extract_virustotal,
}


def parse_alert(alert: dict) -> dict:
    """Parse a Wazuh alert (wrapped or direct) into a structured triage dict.

    Args:
        alert: Raw alert dict, optionally wrapped under ``_source``.

    Returns:
        Structured dict with:
        - ``alert_type``: technical classification (network, ssh, vulnerability, …)
        - ``nature_category``: orthogonal axis — ``"public_attack"``,
          ``"internal_movement"``, ``"informational"``, or ``"unknown"``
          (see ``_categorize_by_nature`` for the strict evaluation order).
        - rule metadata, IOCs, context, and FP candidate flag.
        Never raises; returns partial result on bad input.
    """
    src: dict = alert.get("_source", alert) if isinstance(alert, dict) else {}

    alert_type = _classify(src)
    nature_category = _categorize_by_nature(src)

    # Common rule fields
    rule_id: str | None = str(_get(src, "rule.id")) if _get(src, "rule.id") is not None else None
    rule_level_raw = _get(src, "rule.level")
    try:
        rule_level: int | None = int(rule_level_raw) if rule_level_raw is not None else None
    except (ValueError, TypeError):
        rule_level = None
    rule_description: str | None = _get(src, "rule.description")
    agent_name: str | None = _get(src, "agent.name")

    iocs: list[dict] = []
    context: dict = {}
    is_known_fp_candidate = False

    extractor = _EXTRACTORS.get(alert_type)
    if extractor is not None:
        try:
            iocs, context, is_known_fp_candidate = extractor(src)
        except Exception:
            # Never break the pipeline; return empty IOCs on unexpected error
            iocs, context, is_known_fp_candidate = [], {}, False

    has_external_iocs = any(ioc.get("external", False) for ioc in iocs)

    return {
        "alert_type": alert_type,
        "nature_category": nature_category,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
        "agent_name": agent_name,
        "iocs": iocs,
        "has_external_iocs": has_external_iocs,
        "context": context,
        "is_known_fp_candidate": is_known_fp_candidate,
    }
