"""
tests/test_parser.py — Pytest suite for tools/parser.py.

All tests are deterministic; no network or server dependencies.
Fixtures are loaded from data/sample_alerts/ relative to this file.
"""

import copy
import json
import sys
from pathlib import Path

import pytest

# Ensure the repo root is on the path so tools.parser is importable.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.parser import (  # noqa: E402
    INFORMATIONAL_GROUPS,
    INTERNAL_MOVEMENT_GROUPS,
    PUBLIC_ATTACK_SIGNATURES,
    _is_external_ip,
    parse_alert,
)

FIXTURES_DIR = REPO_ROOT / "data" / "sample_alerts"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture by filename from the sample_alerts directory."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fw() -> dict:
    return load_fixture("firewall_block.json")


@pytest.fixture
def ssh() -> dict:
    return load_fixture("ssh_attack.json")


@pytest.fixture
def vt() -> dict:
    return load_fixture("virustotal.json")


@pytest.fixture
def vuln() -> dict:
    return load_fixture("vulnerability.json")


@pytest.fixture
def win_logon() -> dict:
    return load_fixture("windows_logon.json")


@pytest.fixture
def win_spp() -> dict:
    return load_fixture("windows_spp_error.json")


# ---------------------------------------------------------------------------
# 1. Classification — each fixture maps to the expected type
# ---------------------------------------------------------------------------

def test_classify_firewall(fw):
    assert parse_alert(fw)["alert_type"] == "network"


def test_classify_ssh(ssh):
    assert parse_alert(ssh)["alert_type"] == "ssh"


def test_classify_virustotal(vt):
    assert parse_alert(vt)["alert_type"] == "virustotal"


def test_classify_vulnerability(vuln):
    assert parse_alert(vuln)["alert_type"] == "vulnerability"


def test_classify_windows_logon(win_logon):
    assert parse_alert(win_logon)["alert_type"] == "windows_event"


def test_classify_windows_spp(win_spp):
    assert parse_alert(win_spp)["alert_type"] == "windows_event"


# ---------------------------------------------------------------------------
# 2. Wrapped format gives the same result as direct format
# ---------------------------------------------------------------------------

def test_wrapped_format_ssh(ssh):
    direct = parse_alert(ssh)
    wrapped = parse_alert({"_source": ssh})
    assert direct == wrapped


def test_wrapped_format_fw(fw):
    direct = parse_alert(fw)
    wrapped = parse_alert({"_source": fw})
    assert direct == wrapped


# ---------------------------------------------------------------------------
# 3. IOC extraction — specific known values
# ---------------------------------------------------------------------------

def test_ssh_extracts_external_ip(ssh):
    result = parse_alert(ssh)
    ip_iocs = [i for i in result["iocs"] if i["type"] == "ip"]
    assert any(i["value"] == "5.5.5.5" and i["external"] is True for i in ip_iocs)


def test_fw_extracts_external_ip(fw):
    result = parse_alert(fw)
    ip_iocs = [i for i in result["iocs"] if i["type"] == "ip"]
    assert any(i["value"] == "59.44.42.9" and i["external"] is True for i in ip_iocs)


# ---------------------------------------------------------------------------
# 4. No external IOCs for windows, vuln, and virustotal
# ---------------------------------------------------------------------------

def test_windows_logon_no_external_iocs(win_logon):
    assert parse_alert(win_logon)["has_external_iocs"] is False


def test_windows_spp_no_external_iocs(win_spp):
    assert parse_alert(win_spp)["has_external_iocs"] is False


def test_vuln_no_external_iocs(vuln):
    assert parse_alert(vuln)["has_external_iocs"] is False


def test_virustotal_no_external_iocs(vt):
    assert parse_alert(vt)["has_external_iocs"] is False


# ---------------------------------------------------------------------------
# 5. Private IP → IOC present but external=False
# ---------------------------------------------------------------------------

def test_private_ip_ssh():
    """Craft an SSH alert with a private srcip."""
    alert = {
        "decoder": {"name": "sshd"},
        "data": {"srcip": "192.168.1.5", "srcuser": "root"},
        "rule": {"id": "5710", "level": 5, "description": "SSH attempt", "firedtimes": 1},
        "location": "journald",
    }
    result = parse_alert(alert)
    ip_iocs = [i for i in result["iocs"] if i["type"] == "ip"]
    assert len(ip_iocs) == 1
    assert ip_iocs[0]["value"] == "192.168.1.5"
    assert ip_iocs[0]["external"] is False
    assert result["has_external_iocs"] is False


# ---------------------------------------------------------------------------
# 6. windows_spp (rule 60602) → is_known_fp_candidate == True
# ---------------------------------------------------------------------------

def test_windows_spp_fp_candidate(win_spp):
    assert parse_alert(win_spp)["is_known_fp_candidate"] is True


def test_windows_logon_not_fp_candidate(win_logon):
    assert parse_alert(win_logon)["is_known_fp_candidate"] is False


# ---------------------------------------------------------------------------
# 7. CVE and hash extraction
# ---------------------------------------------------------------------------

def test_vuln_extracts_cve(vuln):
    result = parse_alert(vuln)
    cve_iocs = [i for i in result["iocs"] if i["type"] == "cve"]
    assert any(i["value"] == "CVE-2023-24329" for i in cve_iocs)


def test_virustotal_extracts_md5_and_sha1(vt):
    result = parse_alert(vt)
    hashes = [i["value"] for i in result["iocs"] if i["type"] == "hash"]
    assert "ae783d86f4cbdf308690c3615e946f94" in hashes
    assert "8c8bdf9fb78dda6e14a5700f651c3ea7b50c03d4" in hashes


# ---------------------------------------------------------------------------
# 8. Empty / unknown alerts → "unknown", no crash
# ---------------------------------------------------------------------------

def test_empty_dict():
    result = parse_alert({})
    assert result["alert_type"] == "unknown"
    assert result["iocs"] == []
    assert result["has_external_iocs"] is False
    assert result["is_known_fp_candidate"] is False


def test_no_decoder_no_location():
    result = parse_alert({"rule": {"id": "999", "level": 1}})
    assert result["alert_type"] == "unknown"
    assert result["rule_id"] == "999"


def test_non_dict_input():
    """Parser must not crash on completely invalid input."""
    result = parse_alert(None)  # type: ignore[arg-type]
    assert result["alert_type"] == "unknown"


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------

def test_is_external_ip_public():
    assert _is_external_ip("5.5.5.5") is True
    assert _is_external_ip("59.44.42.9") is True
    assert _is_external_ip("8.8.8.8") is True


def test_is_external_ip_private():
    assert _is_external_ip("192.168.1.1") is False
    assert _is_external_ip("10.0.0.1") is False
    assert _is_external_ip("172.16.0.1") is False
    assert _is_external_ip("127.0.0.1") is False


def test_is_external_ip_invalid():
    assert _is_external_ip("not-an-ip") is False
    assert _is_external_ip("") is False


# ---------------------------------------------------------------------------
# 9. nature_category — public_attack detection
# ---------------------------------------------------------------------------

def test_public_attack_ar_log_json_fixture(fw):
    """firewall_block fixture: ar_log_json + active_response/ossec + public IP."""
    result = parse_alert(fw)
    assert result["nature_category"] == "public_attack"


def test_public_attack_apache_errorlog_inline():
    """Direct apache-errorlog alert with a public srcip is a public attack.

    NOTE: Python 3.11+ marks RFC 5737 TEST-NET ranges (203.0.113.x etc.) as
    is_private=True, so we use 8.8.8.8 — a universally public address that
    carries no real company data and is safe for test use.
    """
    alert = {
        "decoder": {"name": "apache-errorlog"},
        "data": {"srcip": "8.8.8.8"},
        "rule": {
            "id": "30315",
            "level": 5,
            "description": "Apache: Invalid URI (bad client request).",
            "groups": ["apache", "web", "invalid_request"],
        },
        "location": "/var/log/apache2/error.log",
    }
    result = parse_alert(alert)
    assert result["nature_category"] == "public_attack"


def test_public_attack_partial_group_match():
    """A single matching group is enough; not all groups need to be present."""
    alert = {
        "decoder": {"name": "apache-errorlog"},
        "data": {"srcip": "1.1.1.1"},
        "rule": {
            "id": "30300",
            "level": 4,
            "description": "Apache error.",
            "groups": ["apache"],          # only one of the configured groups
        },
        "location": "/var/log/apache2/error.log",
    }
    result = parse_alert(alert)
    assert result["nature_category"] == "public_attack"


def test_public_attack_private_ip_is_unknown():
    """ar_log_json + matching groups but srcip is private → not a public attack.

    Groups ['ossec', 'active_response'] are not in INTERNAL_MOVEMENT_GROUPS or
    INFORMATIONAL_GROUPS, so the alert falls through to "unknown".
    """
    alert = {
        "decoder": {"name": "ar_log_json"},
        "data": {
            "srcip": "192.168.10.50",
            "parameters": {"alert": {"data": {"srcip": "192.168.10.50"}}},
        },
        "rule": {
            "id": "651",
            "level": 3,
            "description": "Host blocked by active response.",
            "groups": ["ossec", "active_response"],
        },
        "location": "/var/ossec/logs/active-responses.log",
    }
    result = parse_alert(alert)
    assert result["nature_category"] == "unknown"


def test_public_attack_unknown_decoder_is_unknown():
    """Unknown decoder + public IP → unknown (no matching signature, no known groups)."""
    alert = {
        "decoder": {"name": "some-other-decoder"},
        "data": {"srcip": "8.8.8.8"},
        "rule": {
            "id": "9999",
            "level": 6,
            "description": "Unknown alert.",
            "groups": ["generic"],
        },
        "location": "/var/log/something.log",
    }
    result = parse_alert(alert)
    assert result["nature_category"] == "unknown"


def test_public_attack_matching_decoder_wrong_groups_is_unknown():
    """ar_log_json decoder but groups don't match any configured group → unknown."""
    alert = {
        "decoder": {"name": "ar_log_json"},
        "data": {"srcip": "8.8.8.8"},
        "rule": {
            "id": "1234",
            "level": 3,
            "description": "Some ar_log_json alert.",
            "groups": ["unrelated_group"],   # not in any configured list
        },
        "location": "/var/ossec/logs/active-responses.log",
    }
    result = parse_alert(alert)
    assert result["nature_category"] == "unknown"


def test_public_attack_no_srcip_is_unknown():
    """Matching decoder + groups but no srcip → signature matched, no public IP.

    Groups ['ossec', 'active_response'] are not in INTERNAL_MOVEMENT_GROUPS or
    INFORMATIONAL_GROUPS, so the result is "unknown".
    """
    alert = {
        "decoder": {"name": "ar_log_json"},
        "data": {},          # no srcip anywhere
        "rule": {
            "id": "651",
            "level": 3,
            "description": "Host blocked.",
            "groups": ["ossec", "active_response"],
        },
        "location": "/var/ossec/logs/active-responses.log",
    }
    result = parse_alert(alert)
    assert result["nature_category"] == "unknown"


def test_public_attack_nested_srcip_public(fw):
    """data.parameters.alert.data.srcip is also checked for ar_log_json blocks.

    Craft a variant where only the nested IP is public and data.srcip is absent.
    Uses 1.1.1.1 — Python 3.11+ marks RFC 5737 TEST-NET ranges as private.
    """
    alert = {
        "decoder": {"name": "ar_log_json"},
        "data": {
            # no top-level srcip
            "parameters": {
                "alert": {
                    "data": {"srcip": "1.1.1.1"},
                }
            },
        },
        "rule": {
            "id": "651",
            "level": 3,
            "description": "Host blocked by active response.",
            "groups": ["ossec", "active_response"],
        },
        "location": "/var/ossec/logs/active-responses.log",
    }
    result = parse_alert(alert)
    assert result["nature_category"] == "public_attack"


# ---------------------------------------------------------------------------
# 10. nature_category for fixture alerts (data-driven, verified against corpus)
# ---------------------------------------------------------------------------

def test_nature_category_windows_logon_is_internal_movement(win_logon):
    """windows_logon has rule.groups=['windows','windows_security','authentication_success'].
    'authentication_success' is in INTERNAL_MOVEMENT_GROUPS → internal_movement.
    """
    assert parse_alert(win_logon)["nature_category"] == "internal_movement"


def test_nature_category_windows_spp_is_informational(win_spp):
    """windows_spp_error has rule.groups=['windows','windows_application','system_error'].
    'windows_application' and 'system_error' are in INFORMATIONAL_GROUPS → informational.
    """
    assert parse_alert(win_spp)["nature_category"] == "informational"


def test_nature_category_vulnerability_is_internal_movement(vuln):
    """vulnerability has rule.groups=['vulnerability-detector'].
    'vulnerability-detector' is in INTERNAL_MOVEMENT_GROUPS → internal_movement.
    """
    assert parse_alert(vuln)["nature_category"] == "internal_movement"


def test_nature_category_virustotal_is_internal_movement(vt):
    """virustotal has rule.groups=['virustotal'].
    'virustotal' is in INTERNAL_MOVEMENT_GROUPS → internal_movement.
    """
    assert parse_alert(vt)["nature_category"] == "internal_movement"


def test_nature_category_ssh_attack_is_internal_movement(ssh):
    """ssh_attack has rule.groups=['syslog','sshd','authentication_failed','invalid_login'].
    'authentication_failed' is in INTERNAL_MOVEMENT_GROUPS → internal_movement.
    """
    assert parse_alert(ssh)["nature_category"] == "internal_movement"


def test_nature_category_empty_dict_is_unknown():
    """Empty alert has no groups at all → falls through to 'unknown'."""
    assert parse_alert({})["nature_category"] == "unknown"


# ---------------------------------------------------------------------------
# 11. nature_category — new categories with representative inline groups
# ---------------------------------------------------------------------------

def test_informational_system_error_inline():
    """An alert whose only group is 'system_error' → informational."""
    alert = {
        "decoder": {"name": "windows_eventchannel"},
        "rule": {
            "id": "18602",
            "level": 3,
            "description": "Windows service error.",
            "groups": ["system_error"],
        },
        "location": "EventChannel",
    }
    assert parse_alert(alert)["nature_category"] == "informational"


def test_informational_dpkg_inline():
    """An alert whose only group is 'dpkg' → informational."""
    alert = {
        "decoder": {"name": "dpkg"},
        "rule": {
            "id": "2900",
            "level": 3,
            "description": "dpkg half-configured package.",
            "groups": ["dpkg"],
        },
        "location": "/var/log/dpkg.log",
    }
    assert parse_alert(alert)["nature_category"] == "informational"


def test_internal_movement_authentication_failed_inline():
    """An alert with 'authentication_failed' in groups → internal_movement."""
    alert = {
        "decoder": {"name": "sshd"},
        "data": {"srcip": "10.0.0.5", "srcuser": "admin"},
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "SSH failed login.",
            "groups": ["sshd", "authentication_failed"],
        },
        "location": "journald",
    }
    assert parse_alert(alert)["nature_category"] == "internal_movement"


def test_internal_movement_syscheck_inline():
    """An alert with 'syscheck_entry_modified' → internal_movement."""
    alert = {
        "decoder": {"name": "syscheck"},
        "rule": {
            "id": "550",
            "level": 7,
            "description": "File modified.",
            "groups": ["syscheck", "syscheck_entry_modified"],
        },
        "location": "syscheck",
    }
    assert parse_alert(alert)["nature_category"] == "internal_movement"


def test_precedence_public_attack_over_internal_movement():
    """An alert that matches public_attack signature AND carries an internal_movement
    group must resolve to 'public_attack' (public_attack evaluated first).
    """
    alert = {
        "decoder": {"name": "ar_log_json"},
        "data": {"srcip": "8.8.8.8"},
        "rule": {
            "id": "651",
            "level": 3,
            "description": "Host blocked — also carries auth group.",
            # active_response triggers public_attack; authentication_failed
            # would trigger internal_movement if evaluated alone.
            "groups": ["active_response", "authentication_failed"],
        },
        "location": "/var/ossec/logs/active-responses.log",
    }
    result = parse_alert(alert)
    assert result["nature_category"] == "public_attack"


def test_no_match_is_unknown():
    """Groups that appear in no configured list → 'unknown'."""
    alert = {
        "decoder": {"name": "custom-decoder"},
        "rule": {
            "id": "7777",
            "level": 4,
            "description": "Completely unrecognised alert.",
            "groups": ["some_random_group", "another_unknown_group"],
        },
        "location": "/var/log/custom.log",
    }
    assert parse_alert(alert)["nature_category"] == "unknown"


# ---------------------------------------------------------------------------
# 12. Constant sanity checks
# ---------------------------------------------------------------------------

def test_informational_groups_constant_contains_expected_entries():
    """Spot-check that corpus-derived groups are present in the constant."""
    for group in ("system_error", "windows_application", "dpkg"):
        assert group in INFORMATIONAL_GROUPS, f"Missing expected group: {group}"


def test_internal_movement_groups_constant_contains_expected_entries():
    """Spot-check that corpus-derived groups are present in the constant."""
    for group in ("authentication_success", "authentication_failed",
                  "vulnerability-detector", "virustotal", "syscheck"):
        assert group in INTERNAL_MOVEMENT_GROUPS, f"Missing expected group: {group}"


def test_public_attack_signatures_constant_structure():
    """Each PUBLIC_ATTACK_SIGNATURES entry has 'decoder' (str) and 'groups' (list)."""
    for sig in PUBLIC_ATTACK_SIGNATURES:
        assert isinstance(sig.get("decoder"), str)
        assert isinstance(sig.get("groups"), list)
        assert len(sig["groups"]) > 0
