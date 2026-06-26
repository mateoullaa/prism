"""
parser.py — Wazuh alert parser for the AI triage pipeline.

Classifies an alert by type, extracts IOCs, categorizes by nature, and returns
a structured dict ready for the enricher or reasoner. No external calls; pure stdlib.
"""

import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Classification pattern lists.
#
# These are loaded at import time from config/known_patterns.json so a SOC
# analyst can add new FP rules or attack patterns by editing that file — no
# code change, no test run required.  The values below are the built-in
# DEFAULTS: a safety net used (per key) whenever the file is missing or a key
# is malformed, so classification never silently degrades.
#
# Meaning of each key:
#
# public_attack_signatures — (decoder, groups) signatures for public attacks.
#   An alert is "public_attack" when (a) decoder.name == entry["decoder"] AND
#   (b) at least ONE of entry["groups"] is in rule.groups AND (c) at least one
#   relevant srcip is a public (non-private) IP.  rule.level is intentionally
#   excluded — corpus evidence shows it does not separate attacks from noise.
#
# informational_groups — rule.groups values indicating non-actionable noise
#   (Windows service errors, dpkg packaging events).  Match ANY group present.
#
# internal_movement_groups — rule.groups values indicating internal activity
#   with no public IP (auth events, file-integrity checks, group changes,
#   PAM/sudo, vulnerability scans, VirusTotal callbacks).  Match ANY present.
#
# known_fp_rule_ids — Windows rule IDs that are dominant, well-understood false
#   positives.  60602 = single Security-SPP service-restart error; 61061 = the
#   aggregation rule that groups multiple 60602 events (same root cause, FP).
#
# Evaluation order in _categorize_by_nature is STRICT:
#   (1) public_attack → (2) internal_movement → (3) informational → "unknown".
# public_attack always wins even if the alert also carries another group.
# ---------------------------------------------------------------------------
_DEFAULTS: dict[str, Any] = {
    "known_fp_rule_ids": ["60602", "61061"],
    "informational_groups": [
        "system_error",
        "windows_application",
        "dpkg",
    ],
    "internal_movement_groups": [
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
    ],
    "public_attack_signatures": [
        {"decoder": "ar_log_json", "groups": ["active_response", "ossec"]},
        {"decoder": "apache-errorlog", "groups": ["apache", "web", "invalid_request"]},
    ],
}


def _config_path() -> Path:
    """Resolve the known-patterns config file path.

    Honors the ``KNOWN_PATTERNS_PATH`` environment override (useful for tests
    and alternate deployments); otherwise defaults to the repo-root
    ``config/known_patterns.json`` (this file lives in ``tools/``).
    """
    override = os.getenv("KNOWN_PATTERNS_PATH")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "config" / "known_patterns.json"


def _is_str_list(value: Any) -> bool:
    """True if value is a list whose every element is a string."""
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_signature_list(value: Any) -> bool:
    """True if value is a list of {decoder: str, groups: non-empty str list} dicts."""
    if not isinstance(value, list):
        return False
    for entry in value:
        if not isinstance(entry, dict):
            return False
        if not isinstance(entry.get("decoder"), str):
            return False
        groups = entry.get("groups")
        if not _is_str_list(groups) or not groups:
            return False
    return True


_VALIDATORS: dict[str, Any] = {
    "known_fp_rule_ids": _is_str_list,
    "informational_groups": _is_str_list,
    "internal_movement_groups": _is_str_list,
    "public_attack_signatures": _is_signature_list,
}


def _load_patterns(path: Path | None = None) -> dict:
    """Load classification patterns from JSON, falling back to ``_DEFAULTS``.

    Reads ``path`` (or the resolved config path), then for EACH key validates
    the expected shape and falls back to the built-in default if the key is
    absent or malformed, logging one warning per fallback.  Never raises: a
    missing or corrupt file yields a fully-defaulted result, so the pipeline
    keeps running (per CONVENTIONS.md).

    Returns:
        Dict with the same keys as ``_DEFAULTS``; values are validated.
    """
    target = path if path is not None else _config_path()

    raw: dict = {}
    try:
        with open(target, encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded, dict):
            raw = loaded
        else:
            logger.warning(
                "known_patterns: %s is not a JSON object; using all defaults", target
            )
    except FileNotFoundError:
        logger.warning(
            "known_patterns: %s not found; using built-in defaults", target
        )
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "known_patterns: failed to read %s (%s); using built-in defaults",
            target,
            exc,
        )

    result: dict[str, Any] = {}
    for key, default in _DEFAULTS.items():
        value = raw.get(key)
        if value is not None and _VALIDATORS[key](value):
            result[key] = value
        else:
            if value is not None:
                logger.warning(
                    "known_patterns: key %r is malformed; using default", key
                )
            result[key] = default
    return result


_patterns = _load_patterns()

PUBLIC_ATTACK_SIGNATURES: list[dict] = _patterns["public_attack_signatures"]
INFORMATIONAL_GROUPS: list[str] = _patterns["informational_groups"]
INTERNAL_MOVEMENT_GROUPS: list[str] = _patterns["internal_movement_groups"]
KNOWN_FP_RULE_IDS: set[str] = set(_patterns["known_fp_rule_ids"])


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
    if decoder_name == "apache-errorlog":
        return "apache"
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
    is_fp = rule_id in KNOWN_FP_RULE_IDS
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


def _extract_apache(src: dict) -> tuple[list[dict], dict, bool]:
    """Extract IOCs and context for Apache error-log alerts."""
    iocs: list[dict] = []
    srcip = _get(src, "data.srcip")
    if srcip:
        iocs.append({
            "value": str(srcip),
            "type": "ip",
            "external": _is_external_ip(str(srcip)),
        })
    context: dict = {
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
    "apache": _extract_apache,
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
