"""
tests/test_main.py — Deterministic tests for the FastAPI triage pipeline service.

All tests are deterministic: no network or server dependencies.
External calls (VirusTotal, AbuseIPDB, Ollama) are fully mocked via
FastAPI dependency overrides and MagicMock objects.

Test map:
  1. test_happy_path_true_positive  — full TP pipeline, verify all keys present
  2. test_false_positive_discarded  — FP discard path + CSV row still written
  3. test_no_external_iocs_skips_enrichment — windows_event, enrichment == {}
  4. test_external_ioc_triggers_enrichment  — firewall_block, enricher queried
  5. test_ollama_failure_returns_needs_review — Ollama error → NEEDS_REVIEW fallback
  6. test_every_alert_logged         — N requests → N CSV rows (incl. discards)
  7. test_malformed_body_returns_422 — JSON array body → 422
  8. test_defensive_escalation       — parse_alert patched to raise → 200 + create_case
  9. test_health                     — GET /health → 200 {"status": "ok"}
 10. test_endpoint_observables_in_final_json — firewall_block, observables in body,
                                               observable.verdict independent of alert.verdict
"""

import csv
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

# Ensure the repo root is on the path so main and tools.* are importable.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from main import _build_observables, app, get_pipeline  # noqa: E402
from tools.reasoner import OllamaClient  # noqa: E402

FIXTURES_DIR = REPO_ROOT / "data" / "sample_alerts"


# ---------------------------------------------------------------------------
# Fixture data helpers
# ---------------------------------------------------------------------------


def load_fixture(name: str) -> dict:
    """Load a JSON fixture by filename from the sample_alerts directory."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Canned verdict dicts
# ---------------------------------------------------------------------------

_TP_VERDICT = {
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "justification": (
        "External IP with high malicious reputation performed repeated SSH "
        "login attempts. Pattern matches brute-force credential stuffing."
    ),
    "mitre": {"id": "T1110", "name": "Brute Force"},
    "next_action": "Block source IP at perimeter firewall and review auth logs.",
    "risk_score": 9,
}

_FP_VERDICT = {
    "verdict": "FALSE_POSITIVE",
    "confidence": "HIGH",
    "justification": (
        "Rule 60602 matches a known benign Windows SPP service scheduling "
        "error. No external IOCs or suspicious indicators are present."
    ),
    "mitre": None,
    "next_action": "No action required; suppress this rule if noise is excessive.",
    "risk_score": 1,
}

_NEEDS_REVIEW_VERDICT = {
    "verdict": "NEEDS_REVIEW",
    "confidence": "MEDIUM",
    "justification": "Context is ambiguous; manual triage is recommended.",
    "mitre": None,
    "next_action": "Escalate to analyst for manual review.",
    "risk_score": 5,
}


# ---------------------------------------------------------------------------
# Mock factories
# ---------------------------------------------------------------------------


def _make_ollama_client(verdict_dict: dict) -> OllamaClient:
    """Return an OllamaClient backed by a mock session that returns a canned verdict.

    Args:
        verdict_dict: The dict to serialize as the LLM JSON response.

    Returns:
        A real OllamaClient wired to a MagicMock session; no network calls.
    """
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"response": json.dumps(verdict_dict)}
    session.post.return_value = resp
    return OllamaClient(
        session=session,
        host="http://mock-ollama:11434",
        model="mock-model",
        timeout=5.0,
    )


def _make_ollama_client_error() -> OllamaClient:
    """Return an OllamaClient whose session returns HTTP 500 (non-200 error).

    The OllamaClient.generate() method returns {"status": "error", ...};
    the reasoner then produces a conservative NEEDS_REVIEW fallback.
    """
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 500
    resp.json.return_value = {}
    session.post.return_value = resp
    return OllamaClient(
        session=session,
        host="http://mock-ollama:11434",
        model="mock-model",
        timeout=5.0,
    )


def _make_enricher_clients() -> tuple:
    """Return (vt_mock, abuse_mock, otx_mock) whose .query() returns canned 'ok' results.

    Returns:
        Tuple of (VirusTotalClient mock, AbuseIPDBClient mock, OTXClient mock) with
        pre-set return values for .query().
    """
    vt = MagicMock()
    vt.query.return_value = {
        "status": "ok",
        "malicious": 10,
        "suspicious": 2,
        "reputation": -50,
    }
    abuse = MagicMock()
    abuse.query.return_value = {
        "status": "ok",
        "abuse_confidence_score": 90,
        "total_reports": 50,
        "country_code": "CN",
        "is_whitelisted": False,
    }
    otx = MagicMock()
    otx.query.return_value = {
        "status": "ok",
        "pulse_count": 0,
        "reputation": 0,
    }
    return vt, abuse, otx


# ---------------------------------------------------------------------------
# Dependency override helper
# ---------------------------------------------------------------------------


def _pipeline_override(
    ollama_client: OllamaClient,
    enricher_clients: tuple,
):
    """Return a callable suitable for app.dependency_overrides[get_pipeline].

    Args:
        ollama_client: Mock OllamaClient to inject.
        enricher_clients: (vt_mock, abuse_mock) tuple to inject.

    Returns:
        Zero-argument callable that returns the deps dict.
    """

    def _override() -> dict:
        return {
            "enricher_clients": enricher_clients,
            "ollama_client": ollama_client,
        }

    return _override


# ---------------------------------------------------------------------------
# Test 9: GET /health
# ---------------------------------------------------------------------------


def test_health() -> None:
    """GET /health returns 200 with {"status": "ok"}."""
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Test 1: Happy path — TRUE_POSITIVE
# ---------------------------------------------------------------------------


def test_happy_path_true_positive(monkeypatch, tmp_path) -> None:
    """Full TP pipeline: firewall_block fixture → 200, all expected keys present.

    Asserts:
    - HTTP 200 with full response body.
    - Body contains ``verdict``, ``routing``, ``enrichment``, ``reasoner_meta``.
    - ``routing.action == "create_case"``, ``send_to_shuffle is True``.
    - ``verdict.verdict == "TRUE_POSITIVE"``.
    """
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))

    ollama = _make_ollama_client(_TP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx))

    try:
        client = TestClient(app)
        resp = client.post("/analyze", json=load_fixture("firewall_block.json"))

        assert resp.status_code == 200
        body = resp.json()

        # All top-level pipeline keys present
        for key in ("verdict", "routing", "enrichment", "reasoner_meta", "iocs"):
            assert key in body, f"missing key: {key}"

        assert body["routing"]["action"] == "create_case"
        assert body["routing"]["send_to_shuffle"] is True
        assert body["verdict"]["verdict"] == "TRUE_POSITIVE"
        assert body["reasoner_meta"]["status"] == "ok"

    finally:
        app.dependency_overrides.pop(get_pipeline, None)


# ---------------------------------------------------------------------------
# Test 2: FALSE_POSITIVE — discarded + CSV row still written
# ---------------------------------------------------------------------------


def test_false_positive_discarded(monkeypatch, tmp_path) -> None:
    """FP HIGH path: windows_spp_error → discard, send_to_shuffle=False, CSV written.

    Even discarded (FALSE_POSITIVE) alerts must produce a CSV row — mandatory
    audit trail per ARCHITECTURE.md.
    """
    log_path = tmp_path / "triage.csv"
    monkeypatch.setenv("LOG_PATH", str(log_path))

    ollama = _make_ollama_client(_FP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx))

    try:
        client = TestClient(app)
        resp = client.post("/analyze", json=load_fixture("windows_spp_error.json"))

        assert resp.status_code == 200
        body = resp.json()

        assert body["routing"]["action"] == "discard"
        assert body["routing"]["send_to_shuffle"] is False

        # CSV row must have been written despite discard
        assert log_path.exists(), "CSV log must be created even for discarded alerts"
        with log_path.open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 1
        assert rows[0]["action"] == "discard"
        assert rows[0]["send_to_shuffle"] == "False"

    finally:
        app.dependency_overrides.pop(get_pipeline, None)


# ---------------------------------------------------------------------------
# Test 3: No external IOCs — enrichment skipped
# ---------------------------------------------------------------------------


def test_no_external_iocs_skips_enrichment(monkeypatch, tmp_path) -> None:
    """Windows logon alert (no external IPs) → enrichment == {}, clients not queried.

    Uses windows_logon.json (a Windows EventChannel alert with no srcip).
    Enricher mock clients must have their .query() method never called.
    """
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))

    ollama = _make_ollama_client(_NEEDS_REVIEW_VERDICT)
    vt = MagicMock()
    abuse = MagicMock()
    otx = MagicMock()
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx))

    try:
        client = TestClient(app)
        resp = client.post("/analyze", json=load_fixture("windows_logon.json"))

        assert resp.status_code == 200
        body = resp.json()

        # Enrichment must be empty — no external IPs in the fixture
        assert body["enrichment"] == {}, (
            f"Expected empty enrichment, got: {body['enrichment']}"
        )
        # Enricher API clients must never be queried
        vt.query.assert_not_called()
        abuse.query.assert_not_called()

    finally:
        app.dependency_overrides.pop(get_pipeline, None)


# ---------------------------------------------------------------------------
# Test 4: External IOC — enrichment populated
# ---------------------------------------------------------------------------


def test_external_ioc_triggers_enrichment(monkeypatch, tmp_path) -> None:
    """Firewall block fixture (srcip=59.44.42.9, public) → enricher queried.

    Asserts that:
    - ``enrichment`` is non-empty (at least one IP entry).
    - Both vt.query and abuse.query were called at least once.
    """
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))

    ollama = _make_ollama_client(_TP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx))

    try:
        client = TestClient(app)
        resp = client.post("/analyze", json=load_fixture("firewall_block.json"))

        assert resp.status_code == 200
        body = resp.json()

        assert body["enrichment"], "Enrichment must be non-empty for a public srcip"
        assert vt.query.call_count >= 1, "VirusTotal must have been queried"
        assert abuse.query.call_count >= 1, "AbuseIPDB must have been queried"

    finally:
        app.dependency_overrides.pop(get_pipeline, None)


# ---------------------------------------------------------------------------
# Test 5: Ollama failure → NEEDS_REVIEW fallback
# ---------------------------------------------------------------------------


def test_ollama_failure_returns_needs_review(monkeypatch, tmp_path) -> None:
    """Ollama HTTP 500 → NEEDS_REVIEW, reasoner_meta.status=fallback, create_case.

    The reasoner catches the error internally and produces the conservative
    fallback verdict; the router then escalates to create_case.
    """
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))

    ollama = _make_ollama_client_error()
    vt, abuse, otx = _make_enricher_clients()
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx))

    try:
        client = TestClient(app)
        resp = client.post("/analyze", json=load_fixture("ssh_attack.json"))

        assert resp.status_code == 200
        body = resp.json()

        assert body["verdict"]["verdict"] == "NEEDS_REVIEW"
        assert body["reasoner_meta"]["status"] == "fallback"
        assert body["routing"]["action"] == "create_case"
        assert body["routing"]["send_to_shuffle"] is True

    finally:
        app.dependency_overrides.pop(get_pipeline, None)


# ---------------------------------------------------------------------------
# Test 6: Every alert logged — N requests → N CSV rows
# ---------------------------------------------------------------------------


def test_every_alert_logged(monkeypatch, tmp_path) -> None:
    """After N requests (including discards), the CSV must contain exactly N rows.

    Sends 3 requests with different fixtures and verdicts (TP, FP, TP).
    The FP alert is discarded but must still produce a CSV row.
    """
    log_path = tmp_path / "triage.csv"
    monkeypatch.setenv("LOG_PATH", str(log_path))

    vt, abuse, otx = _make_enricher_clients()

    requests_plan = [
        ("firewall_block.json", _TP_VERDICT),    # create_case
        ("windows_spp_error.json", _FP_VERDICT), # discard (but still logged)
        ("ssh_attack.json", _TP_VERDICT),         # create_case
    ]

    for fixture_name, verdict in requests_plan:
        ollama = _make_ollama_client(verdict)
        app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx))
        client = TestClient(app)
        resp = client.post("/analyze", json=load_fixture(fixture_name))
        assert resp.status_code == 200

    app.dependency_overrides.pop(get_pipeline, None)

    assert log_path.exists(), "CSV file must exist after all requests"
    with log_path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    assert len(rows) == 3, (
        f"Expected 3 CSV rows (1 per request), got {len(rows)}"
    )
    # Verify that the discard row is present
    actions = [row["action"] for row in rows]
    assert "discard" in actions, "Discarded alert must still appear in the CSV"
    assert actions.count("create_case") == 2


# ---------------------------------------------------------------------------
# Test 7: Malformed body → 422
# ---------------------------------------------------------------------------


def test_malformed_body_returns_422() -> None:
    """A JSON array body (non-object) must be rejected with HTTP 422.

    FastAPI validates that the body matches ``dict`` (the ``payload`` type hint);
    arrays and scalars are rejected before the endpoint logic runs.
    """
    client = TestClient(app)
    resp = client.post("/analyze", json=[1, 2, 3])
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Test 8: Defensive escalation — unexpected crash → 200 + create_case
# ---------------------------------------------------------------------------


def test_defensive_escalation_on_unexpected_error(monkeypatch, tmp_path) -> None:
    """Patching parse_alert to raise forces the last-resort try/except.

    The endpoint must return HTTP 200 with create_case + send_to_shuffle=True,
    NOT HTTP 500.  No alert is ever silently lost.
    """
    log_path = tmp_path / "triage.csv"
    monkeypatch.setenv("LOG_PATH", str(log_path))

    import main as main_module  # noqa: PLC0415 — local import for patching

    def _crash(payload: dict) -> dict:
        raise RuntimeError("Simulated unexpected crash in parse_alert")

    monkeypatch.setattr(main_module, "parse_alert", _crash)

    ollama = _make_ollama_client(_TP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx))

    try:
        # raise_server_exceptions=False prevents TestClient from re-raising
        # framework-level exceptions during the test; our code never raises
        # past the endpoint boundary, but this is belt-and-suspenders.
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/analyze", json={"test": "data"})

        assert resp.status_code == 200, (
            f"Expected 200 (defensive escalation), got {resp.status_code}"
        )
        body = resp.json()
        assert body["routing"]["action"] == "create_case"
        assert body["routing"]["send_to_shuffle"] is True
        assert "defensive escalation" in body["routing"]["reason"].lower()

        # Mandatory audit trail: even the catastrophic-failure path must write
        # a CSV row recording the escalation.
        assert log_path.exists(), (
            "CSV audit row must be written even on catastrophic pipeline failure"
        )
        with log_path.open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 1, "Exactly one audit row expected for the escalation"
        assert rows[0]["action"] == "create_case"

    finally:
        app.dependency_overrides.pop(get_pipeline, None)


# ---------------------------------------------------------------------------
# Test 10: End-to-end observables in final JSON — firewall_block.json
# ---------------------------------------------------------------------------


def test_endpoint_observables_in_final_json(monkeypatch, tmp_path) -> None:
    """firewall_block.json (IP 59.44.42.9) → observables present in final JSON.

    Validates that the /analyze endpoint embeds a populated ``observables``
    list in its response body, and that the observable verdict is derived
    independently from the enrichment data — not from the LLM output.

    Mocks:
    - Ollama → NEEDS_REVIEW (deliberately non-malicious)
    - VT     → malicious=16, suspicious=4  (strong signal)
    - Abuse  → score=100, reports=992      (strong signal)
    - OTX    → error / Read timed out      (simulates production timeout)

    # observable.verdict="malicious" while alert.verdict="NEEDS_REVIEW" → independently derived
    """
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))

    ollama = _make_ollama_client(_NEEDS_REVIEW_VERDICT)

    vt = MagicMock()
    vt.query.return_value = {
        "status": "ok",
        "malicious": 16,
        "suspicious": 4,
        "reputation": -4,
    }
    abuse = MagicMock()
    abuse.query.return_value = {
        "status": "ok",
        "abuse_confidence_score": 100,
        "total_reports": 992,
        "country_code": "CN",
        "is_whitelisted": False,
    }
    otx = MagicMock()
    otx.query.return_value = {
        "status": "error",
        "message": "Read timed out",
    }

    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx))

    try:
        client = TestClient(app)
        resp = client.post("/analyze", json=load_fixture("firewall_block.json"))

        assert resp.status_code == 200
        body = resp.json()

        # observables key is present in the final JSON
        assert "observables" in body

        # exactly one external IP → one observable
        assert len(body["observables"]) == 1

        obs = body["observables"][0]

        assert obs["type"] == "ip"
        assert obs["value"] == "59.44.42.9"
        assert obs["is_public"] is True

        # verdict is derived from enrichment (2 strong signals), NOT from LLM
        assert obs["verdict"] == "malicious"

        # 2 strong signals (VT malicious=16≥5, AbuseIPDB score=100≥80 AND reports=992≥10)
        assert obs["confidence"] == 95

        assert isinstance(obs["sources"], dict)
        assert "virustotal" in obs["sources"]   # VT ok → included in sources
        assert "abuseipdb" in obs["sources"]    # AbuseIPDB ok → included in sources
        assert "otx" not in obs["sources"]      # OTX error → excluded from sources

        assert isinstance(obs["reasons"], list) and len(obs["reasons"]) >= 1
        # OTX appears in reasons even though it is in error (as "unavailable")
        assert any("OTX" in r for r in obs["reasons"])

        # alert.verdict is from the LLM mock (NEEDS_REVIEW), independent of observable.verdict
        # observable.verdict="malicious" while alert.verdict="NEEDS_REVIEW" → independently derived
        assert body["verdict"]["verdict"] == "NEEDS_REVIEW"

    finally:
        app.dependency_overrides.pop(get_pipeline, None)


# ---------------------------------------------------------------------------
# TestObservables — unit tests for _build_observables()
# ---------------------------------------------------------------------------


class TestObservables:
    """Unit tests for the _build_observables() orchestration helper.

    All tests call _build_observables() directly (no HTTP layer) so they are
    fast, deterministic, and require no network or server setup.
    """

    # ------------------------------------------------------------------
    # Test A — IP with VT + AbuseIPDB ok (strong malicious, OTX error)
    # ------------------------------------------------------------------

    def test_malicious_ip_two_strong_signals(self) -> None:
        """VT malicious>=5 + AbuseIPDB score>=80 → verdict=malicious, confidence=95.

        OTX is in error status, so it must be absent from sources but present
        in reasons as an 'unavailable' message.
        """
        parsed = {
            "iocs": [{"value": "1.2.3.4", "type": "ip", "external": True}],
            "enrichment": {
                "1.2.3.4": {
                    "virustotal": {
                        "status": "ok",
                        "malicious": 16,
                        "suspicious": 4,
                        "reputation": -4,
                    },
                    "abuseipdb": {
                        "status": "ok",
                        "abuse_confidence_score": 100,
                        "total_reports": 992,
                        "country_code": "CN",
                        "is_whitelisted": False,
                    },
                    "otx": {"status": "error", "message": "timeout"},
                }
            },
        }

        observables = _build_observables(parsed)

        assert len(observables) == 1
        obs = observables[0]

        assert obs["type"] == "ip"
        assert obs["value"] == "1.2.3.4"
        assert obs["is_public"] is True
        assert obs["verdict"] == "malicious"
        assert obs["confidence"] == 95, (
            "Two strong signals (VT + AbuseIPDB) must yield confidence 95"
        )

        # VT and AbuseIPDB are ok → must appear in sources
        assert "virustotal" in obs["sources"], "VT ok must be included in sources"
        assert "abuseipdb" in obs["sources"], "AbuseIPDB ok must be included in sources"
        # OTX is error → must be excluded from sources
        assert "otx" not in obs["sources"], "OTX error must be excluded from sources"

        assert len(obs["reasons"]) >= 2, (
            "At least VT reason and OTX-unavailable reason expected"
        )
        assert any("OTX: unavailable" in r for r in obs["reasons"]), (
            "OTX error must produce an 'OTX: unavailable' reason string"
        )

    # ------------------------------------------------------------------
    # Test B — all providers in error, no signals at all
    # ------------------------------------------------------------------

    def test_all_providers_error_yields_unknown(self) -> None:
        """When every provider returns error, verdict must be unknown, confidence 0.

        sources must be empty (no ok/cached data).
        reasons must mention at least one provider as unavailable.
        """
        parsed = {
            "iocs": [{"value": "5.5.5.5", "type": "ip", "external": True}],
            "enrichment": {
                "5.5.5.5": {
                    "virustotal": {"status": "error", "message": "timeout"},
                    "abuseipdb": {"status": "error", "message": "timeout"},
                    "otx": {"status": "error", "message": "timeout"},
                }
            },
        }

        observables = _build_observables(parsed)

        assert len(observables) == 1
        obs = observables[0]

        assert obs["verdict"] == "unknown"
        assert obs["confidence"] == 0
        assert obs["sources"] == {}, (
            "All providers in error → sources must be empty dict"
        )
        assert any("unavailable" in r for r in obs["reasons"]), (
            "At least one reason must mention 'unavailable'"
        )

    # ------------------------------------------------------------------
    # Test C — hash IOC with no enrichment entry
    # ------------------------------------------------------------------

    def test_hash_ioc_no_enrichment_entry(self) -> None:
        """A hash IOC with no enrichment entry produces the 'no enrichment' sentinel.

        is_public must reflect the IOC's external field (False for a hash).
        sources and reasons must carry the safe fallback values.
        """
        parsed = {
            "iocs": [{"value": "abc123", "type": "hash", "external": False}],
            "enrichment": {},
        }

        observables = _build_observables(parsed)

        assert len(observables) == 1
        obs = observables[0]

        assert obs["verdict"] == "unknown"
        assert obs["is_public"] is False
        assert obs["sources"] == {}
        assert obs["reasons"] == ["No enrichment available for this IOC type"]
