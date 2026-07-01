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

from main import (  # noqa: E402
    _build_case_description,
    _build_key_factors,
    _build_observables,
    _build_severity_num,
    _build_tags,
    app,
    get_pipeline,
)
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
    retriever=None,
):
    """Return a callable suitable for app.dependency_overrides[get_pipeline].

    Args:
        ollama_client: Mock OllamaClient to inject.
        enricher_clients: (vt_mock, abuse_mock) tuple to inject.
        retriever: Optional mock RAG retriever (None → RAG disabled, v2.1 behavior).

    Returns:
        Zero-argument callable that returns the deps dict.
    """

    def _override() -> dict:
        return {
            "enricher_clients": enricher_clients,
            "ollama_client": ollama_client,
            "retriever": retriever,
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


def test_metrics_endpoint_returns_valid_shape(monkeypatch, tmp_path) -> None:
    """GET /metrics returns 200 with the expected metrics keys."""
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "empty.csv"))
    resp = TestClient(app).get("/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert "total" in body
    assert "verdicts" in body
    assert "per_day" in body
    assert "top_rules" in body
    assert body["total"] == 0  # empty log → zero metrics


def test_dashboard_endpoint_returns_html(monkeypatch, tmp_path) -> None:
    """GET /dashboard returns 200 HTML containing Chart.js and key elements."""
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "empty.csv"))
    resp = TestClient(app).get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Chart.js" in resp.text or "chart.js" in resp.text
    assert "Prism SOC Dashboard" in resp.text
    assert "chartVerdict" in resp.text


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


# ---------------------------------------------------------------------------
# Test 11: Tags — TRUE_POSITIVE + MITRE + network/public_attack fixture
# ---------------------------------------------------------------------------


def test_tags_true_positive_with_mitre(monkeypatch, tmp_path) -> None:
    """firewall_block.json + _TP_VERDICT → tags list contains all expected values.

    firewall_block.json produces:
      alert_type       = "network"
      nature_category  = "public_attack"

    _TP_VERDICT has:
      verdict = "TRUE_POSITIVE"
      mitre   = {"id": "T1110", "name": "Brute Force"}

    Expected tags (order-independent):
      "true_positive", "public_attack", "network",
      "mitre:T1110", "tactic:brute_force"
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

        assert "tags" in body, "Response must contain a 'tags' key"
        tags: list = body["tags"]

        assert "true_positive" in tags, f"Expected 'true_positive' in tags: {tags}"
        assert "public_attack" in tags, f"Expected 'public_attack' in tags: {tags}"
        assert "network" in tags, f"Expected 'network' in tags: {tags}"
        assert "mitre:T1110" in tags, f"Expected 'mitre:T1110' in tags: {tags}"
        assert "tactic:brute_force" in tags, (
            f"Expected 'tactic:brute_force' in tags: {tags}"
        )

    finally:
        app.dependency_overrides.pop(get_pipeline, None)


# ---------------------------------------------------------------------------
# Test 12: Tags — FALSE_POSITIVE, no MITRE, windows_event fixture
# ---------------------------------------------------------------------------


def test_tags_false_positive_no_mitre(monkeypatch, tmp_path) -> None:
    """windows_spp_error.json + _FP_VERDICT → tags list has FP + type, no MITRE tags.

    windows_spp_error.json produces:
      alert_type       = "windows_event"
      nature_category  = "informational"

    _FP_VERDICT has:
      verdict = "FALSE_POSITIVE"
      mitre   = None

    Expected:
      "false_positive" in tags
      "windows_event" in tags
      no tag starting with "mitre:" or "tactic:"
    """
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))

    ollama = _make_ollama_client(_FP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx))

    try:
        client = TestClient(app)
        resp = client.post("/analyze", json=load_fixture("windows_spp_error.json"))

        assert resp.status_code == 200
        body = resp.json()

        assert "tags" in body, "Response must contain a 'tags' key"
        tags: list = body["tags"]

        assert "false_positive" in tags, f"Expected 'false_positive' in tags: {tags}"
        assert "windows_event" in tags, f"Expected 'windows_event' in tags: {tags}"

        mitre_tags = [t for t in tags if t.startswith("mitre:") or t.startswith("tactic:")]
        assert not mitre_tags, (
            f"No MITRE/tactic tags expected when mitre=None, got: {mitre_tags}"
        )

    finally:
        app.dependency_overrides.pop(get_pipeline, None)


# ---------------------------------------------------------------------------
# TestTags — unit tests for _build_tags()
# ---------------------------------------------------------------------------


class TestTags:
    """Unit tests for the _build_tags() orchestration helper.

    All tests call _build_tags() directly (no HTTP layer) so they are fast
    and deterministic.
    """

    def test_true_positive_with_full_mitre(self) -> None:
        """TRUE_POSITIVE + MITRE dict → five distinct tags produced."""
        parsed = {
            "verdict": {
                "verdict": "TRUE_POSITIVE",
                "mitre": {"id": "T1078", "name": "Valid Accounts"},
            },
            "nature_category": "internal_movement",
            "alert_type": "ssh",
        }
        tags = _build_tags(parsed)
        assert "true_positive" in tags
        assert "internal_movement" in tags
        assert "ssh" in tags
        assert "mitre:T1078" in tags
        assert "tactic:valid_accounts" in tags

    def test_false_positive_no_mitre(self) -> None:
        """FALSE_POSITIVE with mitre=None → no mitre/tactic tags."""
        parsed = {
            "verdict": {"verdict": "FALSE_POSITIVE", "mitre": None},
            "nature_category": "informational",
            "alert_type": "windows_event",
        }
        tags = _build_tags(parsed)
        assert "false_positive" in tags
        assert "informational" in tags
        assert "windows_event" in tags
        assert not any(t.startswith("mitre:") or t.startswith("tactic:") for t in tags)

    def test_needs_review_fallback_for_unknown_verdict(self) -> None:
        """Unknown verdict string → 'needs_review' tag (not a KeyError)."""
        parsed = {
            "verdict": {"verdict": "SOMETHING_UNEXPECTED", "mitre": None},
            "nature_category": "unknown",
            "alert_type": "unknown",
        }
        tags = _build_tags(parsed)
        assert "needs_review" in tags

    def test_missing_nature_category_skipped(self) -> None:
        """Missing nature_category key → tag list does NOT include any nature tag."""
        parsed = {
            "verdict": {"verdict": "TRUE_POSITIVE", "mitre": None},
            "alert_type": "network",
            # no nature_category key
        }
        tags = _build_tags(parsed)
        assert "true_positive" in tags
        assert "network" in tags
        nature_tags = {"public_attack", "internal_movement", "informational"}
        assert not nature_tags.intersection(tags), (
            f"No nature tag expected when key is absent, got: {tags}"
        )

    def test_empty_alert_type_skipped(self) -> None:
        """Empty string alert_type → not added to tags."""
        parsed = {
            "verdict": {"verdict": "FALSE_POSITIVE", "mitre": None},
            "alert_type": "",
        }
        tags = _build_tags(parsed)
        assert "" not in tags

    def test_missing_verdict_dict_returns_needs_review(self) -> None:
        """Missing verdict key entirely → 'needs_review' tag, no crash."""
        parsed = {"alert_type": "network"}
        tags = _build_tags(parsed)
        assert "needs_review" in tags

    def test_malformed_parsed_returns_empty_list(self) -> None:
        """Passing a non-dict (None) returns [] without raising."""
        # _build_tags is defensive: catches all exceptions
        tags = _build_tags(None)  # type: ignore[arg-type]
        assert tags == []


# ---------------------------------------------------------------------------
# TestKeyFactors — unit tests for _build_key_factors()
# ---------------------------------------------------------------------------


class TestKeyFactors:
    """Unit tests for the _build_key_factors() orchestration helper.

    All tests call _build_key_factors() directly (no HTTP layer) so they are
    fast and deterministic.
    """

    # ------------------------------------------------------------------
    # Test A — two enriched malicious IPs with multiple providers
    # ------------------------------------------------------------------

    def test_two_malicious_ips_all_sources(self) -> None:
        """Two malicious IPs with VT + AbuseIPDB → all provider strings produced.

        Also checks rule_description, public_attack nature, and justification
        extract are all present in the returned factors list.
        """
        parsed = {
            "observables": [
                {
                    "value": "59.44.42.9",
                    "verdict": "malicious",
                    "sources": {
                        "virustotal": {"malicious": 16},
                        "abuseipdb": {"abuse_confidence_score": 100, "total_reports": 992},
                    },
                },
                {
                    "value": "1.2.3.4",
                    "verdict": "malicious",
                    "sources": {
                        "virustotal": {"malicious": 3},
                    },
                },
            ],
            "rule_description": "Firewall rule 651 blocked the traffic",
            "nature_category": "public_attack",
            "verdict": {
                "justification": (
                    "External IP with high malicious reputation. "
                    "Pattern matches brute-force."
                )
            },
        }
        factors = _build_key_factors(parsed)

        assert "IP 59.44.42.9 flagged by VirusTotal (16 malicious detections)" in factors
        assert (
            "IP 59.44.42.9 flagged by AbuseIPDB (confidence 100, 992 reports)" in factors
        )
        assert "IP 1.2.3.4 flagged by VirusTotal (3 malicious detections)" in factors
        assert "Firewall rule 651 blocked the traffic" in factors
        assert "External IP targeting exposed asset" in factors
        assert any(
            "External IP with high malicious reputation" in f for f in factors
        ), f"Expected justification extract in factors, got: {factors}"

    # ------------------------------------------------------------------
    # Test B — no enrichment, non-public-attack nature
    # ------------------------------------------------------------------

    def test_no_malicious_ips_informational(self) -> None:
        """Clean observable + informational category → no flagged-by or public-attack factor.

        rule_description must still be included; justification extract is added
        but must not contain any enrichment-derived string.
        """
        parsed = {
            "observables": [
                {"value": "10.0.0.1", "verdict": "clean", "sources": {}},
            ],
            "rule_description": "Windows SPP service error",
            "nature_category": "informational",
            "verdict": {"justification": "No indicators of compromise detected."},
        }
        factors = _build_key_factors(parsed)

        # No enrichment factors for any provider
        assert not any("flagged by" in f for f in factors), (
            f"No provider-flagged factor expected for a clean observable, got: {factors}"
        )
        # Rule description is always included when present
        assert "Windows SPP service error" in factors
        # Public-attack factor must be absent for informational nature
        assert "External IP targeting exposed asset" not in factors, (
            f"Public-attack factor must not appear for informational alerts: {factors}"
        )

    # ------------------------------------------------------------------
    # Test C — multi-sentence justification → only first sentence
    # ------------------------------------------------------------------

    def test_justification_first_sentence_only(self) -> None:
        """Multi-sentence justification → first sentence appended, no trailing fragment.

        Old behaviour (15-word cap) could produce a garbage mid-sentence fragment
        when the first sentence exceeded 15 words.  The new behaviour splits on
        sentence boundaries (. ! ? followed by whitespace), so the period is
        retained as part of the returned sentence and subsequent sentences are
        not included.
        """
        long_first = (
            "The source IP address has been identified as a known malicious actor "
            "by multiple threat intelligence providers"
        )
        parsed = {
            "observables": [],
            "rule_description": None,
            "nature_category": "public_attack",
            "verdict": {
                "justification": f"{long_first}. Secondary sentence follows. And a third."
            },
        }
        factors = _build_key_factors(parsed)

        # The first sentence is retained with its trailing period (regex boundary split)
        assert (long_first + ".") in factors, (
            f"Expected first sentence (with period) in factors, got: {factors}"
        )
        # No second sentence must bleed in
        assert not any("Secondary sentence" in f for f in factors), (
            f"Second sentence must not appear in factors: {factors}"
        )

    # ------------------------------------------------------------------
    # Test D — long single sentence > 150 chars → truncated at last space
    # ------------------------------------------------------------------

    def test_justification_long_no_period_truncated_at_space(self) -> None:
        """Justification with no period and length >150 chars → 150-char slice at last space.

        Ensures there is no mid-word cut and the result is non-empty.
        """
        # 200-char sentence with no period — words are separated by spaces
        sentence = (
            "This alert was generated because the external scanning host repeatedly "
            "probed multiple high-numbered ports in a pattern consistent with automated "
            "reconnaissance tooling against the target subnet"
        )
        assert len(sentence) > 150, "Fixture must be longer than 150 chars"
        parsed = {
            "observables": [],
            "rule_description": None,
            "nature_category": "informational",
            "verdict": {"justification": sentence},
        }
        factors = _build_key_factors(parsed)

        assert len(factors) == 1, f"Expected exactly one factor, got: {factors}"
        result = factors[0]
        # Must not exceed 150 chars
        assert len(result) <= 150, f"Result exceeds 150 chars: {result!r}"
        # Must not end mid-word (next char after result, if any, must be a space or end)
        remainder = sentence[len(result):]
        assert remainder == "" or remainder[0] == " ", (
            f"Mid-word cut detected. Result={result!r}, remainder starts={remainder[:10]!r}"
        )
        # Must be non-empty
        assert result.strip(), "Result must not be empty"

    # ------------------------------------------------------------------
    # Test E — regression: dotted IP in justification preserved intact
    # ------------------------------------------------------------------

    def test_justification_dotted_ip_preserved(self) -> None:
        """Justification with a dotted IP yields the full IP in the factor.

        Regression test for the bare-period split bug: ``just.split(".")[0]``
        on ``"The IP address 59.44.42.9 is flagged..."`` produced the fragment
        ``"The IP address 59"``.  The correct behaviour splits only on sentence
        boundaries (. ! ? followed by whitespace), keeping ``59.44.42.9`` whole.
        """
        just = (
            "The IP address 59.44.42.9 is flagged as malicious by VirusTotal. "
            "Second sentence here."
        )
        parsed = {
            "observables": [],
            "rule_description": None,
            "nature_category": "informational",
            "verdict": {"justification": just},
        }
        factors = _build_key_factors(parsed)

        expected_sentence = (
            "The IP address 59.44.42.9 is flagged as malicious by VirusTotal."
        )
        # The complete first sentence (with the full dotted IP) must be in factors
        assert expected_sentence in factors, (
            f"Expected full first sentence with dotted IP in factors, got: {factors}"
        )
        # No truncated fragment ("The IP address 59" without the rest of the IP)
        assert not any(
            f.startswith("The IP address 59") and "59.44.42.9" not in f
            for f in factors
        ), f"Truncated IP fragment must not appear in factors: {factors}"
        # The full dotted IP must appear verbatim in at least one factor
        assert any("59.44.42.9" in f for f in factors), (
            f"Full dotted IP '59.44.42.9' must be present in factors: {factors}"
        )

    # ------------------------------------------------------------------
    # Test F — empty / missing justification → no empty fragment appended
    # ------------------------------------------------------------------

    def test_justification_empty_appends_nothing(self) -> None:
        """Empty or missing justification must not append an empty string to factors."""
        base = {
            "observables": [],
            "rule_description": "Rule 60602 matched",
            "nature_category": "informational",
        }

        # Case 1: verdict key absent entirely
        factors = _build_key_factors({**base})
        assert "" not in factors, f"Empty string must not appear in factors: {factors}"
        assert "Rule 60602 matched" in factors

        # Case 2: justification is an empty string
        factors = _build_key_factors({**base, "verdict": {"justification": ""}})
        assert "" not in factors, f"Empty string must not appear in factors: {factors}"

        # Case 3: justification is None
        factors = _build_key_factors({**base, "verdict": {"justification": None}})
        assert "" not in factors, f"Empty string must not appear in factors: {factors}"


# ---------------------------------------------------------------------------
# TestCaseDescription — integration test for _build_case_description()
# ---------------------------------------------------------------------------


class TestCaseDescription:
    """Unit and integration tests for _build_case_description().

    Integration test uses firewall_block.json + _TP_VERDICT with enriched
    VT + AbuseIPDB data for 59.44.42.9 (mirrors the mock setup from
    test_endpoint_observables_in_final_json).
    Unit tests call _build_case_description() directly.
    """

    def test_case_description_end_to_end(self, monkeypatch, tmp_path) -> None:
        """firewall_block.json + TP verdict → case_description present and well-formed.

        Asserts:
        1.  ``case_description`` key exists in the response body.
        2.  Contains the agent name from the fixture (``"agent-web-01"``).
        3.  Contains the malicious IP (``"59.44.42.9"``).
        4.  Contains ``"VirusTotal"`` (provider enrichment line).
        5.  Contains ``"AbuseIPDB"`` (provider enrichment line).
        6.  Contains ``"TRUE_POSITIVE"`` (verdict paragraph).
        7.  Contains ``"HIGH"`` (confidence in verdict paragraph).
        8.  Has at least 3 ``"\\n\\n"`` separators (4 paragraphs).
        9.  English P1 opener: ``"An alert was received"``.
        10. English IP label: ``"IP involved:"`` (single malicious IP).
        11. English P2 enrichment phrase: ``"malicious reputation"``.
        12. English P4 labels: ``"Verdict:"`` and ``"Recommended action:"``.
        13. Output is ASCII-only: no mojibake characters (e.g. ``"Ã"``).
        """
        monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))

        ollama = _make_ollama_client(_TP_VERDICT)

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

        app.dependency_overrides[get_pipeline] = _pipeline_override(
            ollama, (vt, abuse, otx)
        )

        try:
            client = TestClient(app)
            resp = client.post("/analyze", json=load_fixture("firewall_block.json"))

            assert resp.status_code == 200
            body = resp.json()

            # 1. Key present
            assert "case_description" in body, (
                "Response must contain a 'case_description' key"
            )

            desc: str = body["case_description"]

            # 2. Agent name from fixture
            assert "agent-web-01" in desc, (
                f"Expected agent name 'agent-web-01' in case_description: {desc!r}"
            )

            # 3. Malicious IP from fixture
            assert "59.44.42.9" in desc, (
                f"Expected IP '59.44.42.9' in case_description: {desc!r}"
            )

            # 4. VirusTotal enrichment mentioned
            assert "VirusTotal" in desc, (
                f"Expected 'VirusTotal' in case_description: {desc!r}"
            )

            # 5. AbuseIPDB enrichment mentioned
            assert "AbuseIPDB" in desc, (
                f"Expected 'AbuseIPDB' in case_description: {desc!r}"
            )

            # 6. Verdict value in paragraph 4
            assert "TRUE_POSITIVE" in desc, (
                f"Expected 'TRUE_POSITIVE' in case_description: {desc!r}"
            )

            # 7. Confidence level in paragraph 4
            assert "HIGH" in desc, (
                f"Expected 'HIGH' in case_description: {desc!r}"
            )

            # 8. Four paragraphs → at least 3 double-newline separators
            assert desc.count("\n\n") >= 3, (
                f"Expected at least 3 '\\n\\n' separators (4 paragraphs), "
                f"got {desc.count(chr(10) + chr(10))}: {desc!r}"
            )

            # 9. English P1 opener
            assert "An alert was received" in desc, (
                f"Expected English opener 'An alert was received' in case_description: {desc!r}"
            )

            # 10. English IP label (single malicious IP → "IP involved:")
            assert "IP involved:" in desc, (
                f"Expected 'IP involved:' in case_description: {desc!r}"
            )

            # 11. English P2 enrichment phrase
            assert "malicious reputation" in desc, (
                f"Expected 'malicious reputation' in case_description: {desc!r}"
            )

            # 12. English P4 labels
            assert "Verdict:" in desc, (
                f"Expected 'Verdict:' in case_description: {desc!r}"
            )
            assert "Recommended action:" in desc, (
                f"Expected 'Recommended action:' in case_description: {desc!r}"
            )

            # 13. ASCII-only — no mojibake (e.g. "Ã" from double-encoded UTF-8)
            assert "Ã" not in desc, (
                f"Mojibake character 'Ã' found in case_description: {desc!r}"
            )
            assert desc == desc.encode("ascii", "ignore").decode(), (
                f"case_description contains non-ASCII characters: {desc!r}"
            )

        finally:
            app.dependency_overrides.pop(get_pipeline, None)

    def test_case_description_unit_english_fallbacks(self) -> None:
        """Direct call with minimal parsed dict → English fallback strings used.

        Verifies that missing agent, missing rule, no malicious IPs, no verdict
        all produce English-only fallback text with no accented characters.
        """
        parsed: dict = {}
        desc = _build_case_description(parsed)

        assert "unknown agent" in desc, (
            f"Expected 'unknown agent' fallback in case_description: {desc!r}"
        )
        assert "No rule description." in desc, (
            f"Expected 'No rule description.' fallback: {desc!r}"
        )
        assert "No IPs with malicious reputation found in external sources." in desc, (
            f"Expected no-malicious-IPs fallback: {desc!r}"
        )
        assert "No justification available." in desc, (
            f"Expected 'No justification available.' fallback: {desc!r}"
        )
        assert "Recommended action:" in desc, (
            f"Expected 'Recommended action:' label: {desc!r}"
        )
        # Strictly ASCII
        assert desc == desc.encode("ascii", "ignore").decode(), (
            f"Fallback case_description must be ASCII-only: {desc!r}"
        )


# ---------------------------------------------------------------------------
# TestSeverityNum — unit tests for _build_severity_num()
# ---------------------------------------------------------------------------


class TestSeverityNum:
    """Unit tests for the _build_severity_num() orchestration helper.

    All tests call _build_severity_num() directly (no HTTP layer) so they are
    fast and deterministic.
    """

    def test_risk_1_is_low(self):
        assert _build_severity_num({"verdict": {"risk_score": 1}}) == 1

    def test_risk_5_is_medium(self):
        assert _build_severity_num({"verdict": {"risk_score": 5}}) == 2

    def test_risk_8_is_high(self):
        assert _build_severity_num({"verdict": {"risk_score": 8}}) == 3

    def test_risk_10_is_critical(self):
        assert _build_severity_num({"verdict": {"risk_score": 10}}) == 4

    def test_missing_verdict_defaults_medium(self):
        assert _build_severity_num({}) == 2


# ---------------------------------------------------------------------------
# v2.2 RAG integration — retriever injected via the pipeline override
# ---------------------------------------------------------------------------


def _rag_hit(similarity: float, verdict: str = "FALSE_POSITIVE", confidence: str = "HIGH") -> dict:
    return {
        "similarity": similarity,
        "verdict": verdict,
        "confidence": confidence,
        "alert_type": "windows_event",
        "rule_id": "60602",
        "mitre_id": "",
        "timestamp": "2026-06-17T16:27:32+00:00",
    }


def _mock_retriever(hits: list) -> MagicMock:
    retriever = MagicMock()
    retriever.query.return_value = hits
    retriever.index.return_value = True
    return retriever


def test_rag_disabled_noop_preserves_v21_behavior(monkeypatch, tmp_path) -> None:
    """retriever=None (RAG disabled) → verdict comes from the LLM, no similar_cases."""
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))
    ollama = _make_ollama_client(_FP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx), None)
    try:
        resp = TestClient(app).post("/analyze", json=load_fixture("windows_spp_error.json"))
        body = resp.json()
        assert resp.status_code == 200
        assert body["verdict"]["verdict"] == "FALSE_POSITIVE"
        assert body["reasoner_meta"]["status"] == "ok"
        assert body.get("similar_cases") is None
    finally:
        app.dependency_overrides.pop(get_pipeline, None)


def test_rag_context_summary_injected(monkeypatch, tmp_path) -> None:
    """A retriever with hits puts a verdict aggregate into similar_cases."""
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))
    ollama = _make_ollama_client(_FP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    retriever = _mock_retriever([
        _rag_hit(0.99), _rag_hit(0.95), _rag_hit(0.90, "TRUE_POSITIVE"),
    ])
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx), retriever)
    try:
        resp = TestClient(app).post("/analyze", json=load_fixture("windows_spp_error.json"))
        body = resp.json()
        assert body["similar_cases"] == (
            "Of 3 similar past alerts: 2 FALSE_POSITIVE, 1 TRUE_POSITIVE, 0 NEEDS_REVIEW."
        )
    finally:
        app.dependency_overrides.pop(get_pipeline, None)


def test_rag_shadow_mode_does_not_auto_classify(monkeypatch, tmp_path) -> None:
    """In shadow mode, even unanimous HIGH-confidence FP precedents do NOT
    short-circuit the LLM: the verdict still comes from the reasoner."""
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))
    monkeypatch.setenv("RAG_SHADOW_MODE", "true")
    # LLM returns TP — if shadow wrongly auto-classified, we'd see FALSE_POSITIVE.
    ollama = _make_ollama_client(_TP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    retriever = _mock_retriever([_rag_hit(0.99) for _ in range(5)])
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx), retriever)
    try:
        resp = TestClient(app).post("/analyze", json=load_fixture("windows_spp_error.json"))
        body = resp.json()
        assert body["verdict"]["verdict"] == "TRUE_POSITIVE"
        assert body["reasoner_meta"]["status"] == "ok"  # LLM ran, not auto_fp
    finally:
        app.dependency_overrides.pop(get_pipeline, None)


def test_rag_live_auto_classifies_on_unanimous_fp(monkeypatch, tmp_path) -> None:
    """With shadow mode OFF, unanimous HIGH-confidence FP precedents auto-classify
    as FALSE_POSITIVE WITHOUT invoking the LLM (status=auto_fp)."""
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))
    monkeypatch.setenv("RAG_SHADOW_MODE", "false")
    # LLM is wired to TP; if it were (wrongly) consulted we'd see TRUE_POSITIVE.
    ollama = _make_ollama_client(_TP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    retriever = _mock_retriever([_rag_hit(0.99) for _ in range(5)])
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx), retriever)
    try:
        resp = TestClient(app).post("/analyze", json=load_fixture("windows_spp_error.json"))
        body = resp.json()
        assert body["verdict"]["verdict"] == "FALSE_POSITIVE"
        assert body["reasoner_meta"]["status"] == "auto_fp"
        assert body["reasoner_meta"]["model"].startswith("rag-similarity:")
        assert body["routing"]["action"] == "discard"
        # auto_fp verdicts must NOT be indexed back into the corpus (no feedback loop).
        retriever.index.assert_not_called()
    finally:
        app.dependency_overrides.pop(get_pipeline, None)


def test_correlation_summary_in_response(monkeypatch, tmp_path) -> None:
    """correlation_summary is present in the response when RAG has hits."""
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))
    ollama = _make_ollama_client(_FP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    retriever = _mock_retriever([
        _rag_hit(0.99), _rag_hit(0.97), _rag_hit(0.95),
        _rag_hit(0.93), _rag_hit(0.91),
    ])
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx), retriever)
    try:
        resp = TestClient(app).post("/analyze", json=load_fixture("windows_spp_error.json"))
        body = resp.json()
        assert "correlation_summary" in body
        assert body["correlation_summary"] is not None
        assert "FALSE_POSITIVE" in body["correlation_summary"]
    finally:
        app.dependency_overrides.pop(get_pipeline, None)


def test_correlation_summary_none_when_rag_disabled(monkeypatch, tmp_path) -> None:
    """correlation_summary is None when no retriever is injected (RAG disabled)."""
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))
    ollama = _make_ollama_client(_TP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx), None)
    try:
        resp = TestClient(app).post("/analyze", json=load_fixture("firewall_block.json"))
        body = resp.json()
        assert body.get("correlation_summary") is None
    finally:
        app.dependency_overrides.pop(get_pipeline, None)


def test_rag_indexes_only_real_llm_verdicts(monkeypatch, tmp_path) -> None:
    """A genuine LLM verdict (status=ok) is indexed into the corpus."""
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "triage.csv"))
    ollama = _make_ollama_client(_TP_VERDICT)
    vt, abuse, otx = _make_enricher_clients()
    retriever = _mock_retriever([])  # no precedents → LLM path
    app.dependency_overrides[get_pipeline] = _pipeline_override(ollama, (vt, abuse, otx), retriever)
    try:
        TestClient(app).post("/analyze", json=load_fixture("firewall_block.json"))
        retriever.index.assert_called_once()
    finally:
        app.dependency_overrides.pop(get_pipeline, None)
