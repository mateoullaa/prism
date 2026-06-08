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

from tools.parser import _is_external_ip, parse_alert  # noqa: E402

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
