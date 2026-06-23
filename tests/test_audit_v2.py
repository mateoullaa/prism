"""
tests/test_audit_v2.py — Live integration audit of the v2 output contract.

POSTs each of the 7 sample-alert fixtures to the real FastAPI ``/analyze``
endpoint TWICE and validates the full v2 response schema on every response.
Key fields are compared across the two runs; any discrepancies are *reported*
(printed) but never cause a test failure — the goal is detection, not blocking.

Design notes:
- This is a LIVE integration test: the real module-level singletons are used
  (remote Ollama at OLLAMA_HOST via VPN, VirusTotal, AbuseIPDB, OTX).
- The reasoner never crashes: on any Ollama failure it returns a conservative
  fallback (verdict=NEEDS_REVIEW, confidence=LOW, risk_score=5,
  reasoner_meta.status="fallback").  Both ``ok`` and ``fallback`` are valid;
  tests validate STRUCTURE only and merely report the status.
- LOG_PATH is overridden *before* importing main so test runs never pollute
  the production metrics/triage_log.csv.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Override LOG_PATH BEFORE importing main so the module-level logger singleton
# writes to a temp file instead of metrics/triage_log.csv.
# ---------------------------------------------------------------------------
os.environ["LOG_PATH"] = os.path.join(
    tempfile.gettempdir(), "prism_audit_v2_test_log.csv"
)

# Ensure repo root (parent of tests/) is on sys.path so main and tools.* are
# importable regardless of how pytest is invoked.
_REPO_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from main import app  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level singletons: one client shared across all tests (preserves the
# rate-limit token bucket and TTL cache of the real enricher clients).
# ---------------------------------------------------------------------------
client: TestClient = TestClient(app)

# ---------------------------------------------------------------------------
# Fixture paths — resolved relative to the repo root, not the CWD.
# ---------------------------------------------------------------------------
_FIXTURES_DIR: Path = _REPO_ROOT / "data" / "sample_alerts"

_FIXTURE_NAMES: list[str] = [
    "firewall_block.json",
    "ssh_attack.json",
    "virustotal.json",
    "vulnerability.json",
    "windows_logon.json",
    "windows_spp_error.json",
    "windows_spp_grouped.json",
]


# ---------------------------------------------------------------------------
# Contract validator
# ---------------------------------------------------------------------------


def _validate_contract(resp_json: dict) -> None:  # noqa: PLR0912,C901
    """Assert that *resp_json* satisfies the full v2 output contract.

    Validates every field required by the contract defined in ARCHITECTURE.md
    and the v2 enrichment helpers in main.py.  Raises ``AssertionError`` with
    a descriptive message on the first violation found.

    Args:
        resp_json: The parsed JSON body returned by ``POST /analyze``.
    """
    # ------------------------------------------------------------------
    # 1. Top-level keys
    # ------------------------------------------------------------------
    _required_top_keys: tuple[str, ...] = (
        "alert_type",
        "nature_category",
        "rule_id",
        "rule_level",
        "rule_description",
        "agent_name",
        "iocs",
        "has_external_iocs",
        "context",
        "is_known_fp_candidate",
        "enrichment",
        "verdict",
        "reasoner_meta",
        "routing",
        "observables",
        "tags",
        "key_factors",
        "case_description",
        "severity_num",
    )
    for key in _required_top_keys:
        assert key in resp_json, f"Missing required top-level key: {key!r}"

    # ------------------------------------------------------------------
    # 2. observables — list; each item has the full observable contract
    # ------------------------------------------------------------------
    obs_list: Any = resp_json["observables"]
    assert isinstance(obs_list, list), (
        f"'observables' must be a list, got {type(obs_list).__name__}"
    )
    _obs_keys: tuple[str, ...] = (
        "type", "value", "is_public", "verdict", "sources", "confidence", "reasons"
    )
    _obs_verdicts: frozenset[str] = frozenset({"malicious", "suspicious", "unknown"})
    for idx, obs in enumerate(obs_list):
        for k in _obs_keys:
            assert k in obs, (
                f"observables[{idx}] missing required key {k!r}"
            )
        assert obs["verdict"] in _obs_verdicts, (
            f"observables[{idx}].verdict must be one of {_obs_verdicts}, "
            f"got {obs['verdict']!r}"
        )
        assert isinstance(obs["is_public"], bool), (
            f"observables[{idx}].is_public must be bool, "
            f"got {type(obs['is_public']).__name__}"
        )
        conf: Any = obs["confidence"]
        assert isinstance(conf, int) and 0 <= conf <= 95, (
            f"observables[{idx}].confidence must be int 0..95, got {conf!r}"
        )
        assert isinstance(obs["sources"], dict), (
            f"observables[{idx}].sources must be dict, "
            f"got {type(obs['sources']).__name__}"
        )
        assert isinstance(obs["reasons"], list), (
            f"observables[{idx}].reasons must be list, "
            f"got {type(obs['reasons']).__name__}"
        )

    # ------------------------------------------------------------------
    # 3. tags — non-empty list of strings
    # ------------------------------------------------------------------
    tags: Any = resp_json["tags"]
    assert isinstance(tags, list), (
        f"'tags' must be a list, got {type(tags).__name__}"
    )
    assert len(tags) > 0, (
        "'tags' must be non-empty (always has at least the verdict-derived tag)"
    )
    for i, tag in enumerate(tags):
        assert isinstance(tag, str), (
            f"tags[{i}] must be str, got {type(tag).__name__}: {tag!r}"
        )

    # ------------------------------------------------------------------
    # 4. key_factors — non-empty list of strings
    # ------------------------------------------------------------------
    kf: Any = resp_json["key_factors"]
    assert isinstance(kf, list), (
        f"'key_factors' must be a list, got {type(kf).__name__}"
    )
    assert len(kf) > 0, (
        "'key_factors' must be non-empty"
    )
    for i, factor in enumerate(kf):
        assert isinstance(factor, str), (
            f"key_factors[{i}] must be str, got {type(factor).__name__}: {factor!r}"
        )

    # ------------------------------------------------------------------
    # 5. case_description — non-empty string
    # ------------------------------------------------------------------
    cd: Any = resp_json["case_description"]
    assert isinstance(cd, str), (
        f"'case_description' must be str, got {type(cd).__name__}"
    )
    assert cd.strip(), (
        "'case_description' must be non-empty (after strip)"
    )

    # ------------------------------------------------------------------
    # 6. severity_num — int in 1..4
    # ------------------------------------------------------------------
    sn: Any = resp_json["severity_num"]
    assert isinstance(sn, int), (
        f"'severity_num' must be int, got {type(sn).__name__}: {sn!r}"
    )
    assert 1 <= sn <= 4, (
        f"'severity_num' must be in range 1..4 (TheHive severity), got {sn}"
    )

    # ------------------------------------------------------------------
    # 7. verdict — dict with contract sub-fields
    # ------------------------------------------------------------------
    v_raw: Any = resp_json["verdict"]
    assert isinstance(v_raw, dict), (
        f"'verdict' must be dict, got {type(v_raw).__name__}"
    )
    _verdict_values: frozenset[str] = frozenset(
        {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"}
    )
    assert v_raw.get("verdict") in _verdict_values, (
        f"verdict.verdict must be one of {_verdict_values}, "
        f"got {v_raw.get('verdict')!r}"
    )
    _conf_values: frozenset[str] = frozenset({"HIGH", "MEDIUM", "LOW"})
    assert v_raw.get("confidence") in _conf_values, (
        f"verdict.confidence must be one of {_conf_values}, "
        f"got {v_raw.get('confidence')!r}"
    )
    just: Any = v_raw.get("justification")
    assert isinstance(just, str) and just.strip(), (
        f"verdict.justification must be a non-empty str, got {just!r}"
    )
    na: Any = v_raw.get("next_action")
    assert isinstance(na, str) and na.strip(), (
        f"verdict.next_action must be a non-empty str, got {na!r}"
    )
    risk: Any = v_raw.get("risk_score")
    assert isinstance(risk, int) and 1 <= risk <= 10, (
        f"verdict.risk_score must be int 1..10, got {risk!r}"
    )
    mitre: Any = v_raw.get("mitre")
    assert mitre is None or isinstance(mitre, dict), (
        f"verdict.mitre must be dict or None, got {type(mitre).__name__}"
    )
    if isinstance(mitre, dict):
        assert "id" in mitre and "name" in mitre, (
            f"verdict.mitre must contain 'id' and 'name', got {mitre!r}"
        )

    # ------------------------------------------------------------------
    # 8. reasoner_meta — dict with status/model/latency_ms
    # ------------------------------------------------------------------
    rm: Any = resp_json["reasoner_meta"]
    assert isinstance(rm, dict), (
        f"'reasoner_meta' must be dict, got {type(rm).__name__}"
    )
    assert rm.get("status") in {"ok", "fallback"}, (
        f"reasoner_meta.status must be 'ok' or 'fallback', got {rm.get('status')!r}"
    )
    assert isinstance(rm.get("model"), str), (
        f"reasoner_meta.model must be str, got {type(rm.get('model')).__name__}"
    )
    assert isinstance(rm.get("latency_ms"), int), (
        f"reasoner_meta.latency_ms must be int, got {type(rm.get('latency_ms')).__name__}"
    )

    # ------------------------------------------------------------------
    # 9. enrichment — dict; if non-empty, each IP entry must have all 3 providers
    # ------------------------------------------------------------------
    enr: Any = resp_json["enrichment"]
    assert isinstance(enr, dict), (
        f"'enrichment' must be dict, got {type(enr).__name__}"
    )
    for ip_key, ip_data in enr.items():
        assert isinstance(ip_data, dict), (
            f"enrichment[{ip_key!r}] must be dict, got {type(ip_data).__name__}"
        )
        for provider in ("virustotal", "abuseipdb", "otx"):
            assert provider in ip_data, (
                f"enrichment[{ip_key!r}] missing provider {provider!r}"
            )
            p_data: Any = ip_data[provider]
            assert isinstance(p_data, dict), (
                f"enrichment[{ip_key!r}][{provider!r}] must be dict, "
                f"got {type(p_data).__name__}"
            )
            assert "status" in p_data, (
                f"enrichment[{ip_key!r}][{provider!r}] missing required 'status' key"
            )

    # ------------------------------------------------------------------
    # 10. routing — dict with action/send_to_shuffle/reason + coherence checks
    # ------------------------------------------------------------------
    rt: Any = resp_json["routing"]
    assert isinstance(rt, dict), (
        f"'routing' must be dict, got {type(rt).__name__}"
    )
    action: Any = rt.get("action")
    sts: Any = rt.get("send_to_shuffle")
    rt_reason: Any = rt.get("reason")
    vv: str = v_raw.get("verdict", "")

    assert action in {"create_case", "discard"}, (
        f"routing.action must be 'create_case' or 'discard', got {action!r}"
    )
    assert isinstance(sts, bool), (
        f"routing.send_to_shuffle must be bool, got {type(sts).__name__}"
    )
    assert isinstance(rt_reason, str) and rt_reason.strip(), (
        f"routing.reason must be a non-empty str, got {rt_reason!r}"
    )

    # Coherence: discard <=> send_to_shuffle is False <=> FALSE_POSITIVE
    if action == "discard":
        assert sts is False, (
            f"routing.send_to_shuffle must be False when action=='discard', got {sts}"
        )
        assert vv == "FALSE_POSITIVE", (
            f"verdict.verdict must be 'FALSE_POSITIVE' when routing.action=='discard', "
            f"got {vv!r}"
        )
    if sts is False:
        assert action == "discard", (
            f"routing.action must be 'discard' when send_to_shuffle is False, "
            f"got {action!r}"
        )
    if vv == "FALSE_POSITIVE":
        assert action == "discard" and sts is False, (
            f"FALSE_POSITIVE verdict must have action='discard' and "
            f"send_to_shuffle=False, got action={action!r} sts={sts}"
        )

    # create_case => send_to_shuffle is True and verdict in {TP, NEEDS_REVIEW}
    if action == "create_case":
        assert sts is True, (
            f"routing.send_to_shuffle must be True when action=='create_case', got {sts}"
        )
        assert vv in {"TRUE_POSITIVE", "NEEDS_REVIEW"}, (
            f"verdict.verdict must be 'TRUE_POSITIVE' or 'NEEDS_REVIEW' when "
            f"routing.action=='create_case', got {vv!r}"
        )


# ---------------------------------------------------------------------------
# Parametrized live integration test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name", _FIXTURE_NAMES)
def test_live_contract(fixture_name: str) -> None:
    """Live v2 contract audit: POST each fixture twice, validate schema both times.

    Both runs must return HTTP 200 and pass ``_validate_contract``.  Key fields
    are compared across the two runs; differences are printed as
    ``INCONSISTENCY [fixture]: <field> run1=.. run2=..`` lines but do NOT fail
    the test — detection only (temperature=0 LLM should be stable, but network
    variance may occur).

    Args:
        fixture_name: Filename of the alert fixture in data/sample_alerts/.
    """
    fixture_path: Path = _FIXTURES_DIR / fixture_name
    payload: dict = json.loads(fixture_path.read_text(encoding="utf-8"))

    responses: list[dict] = []

    for run_n in (1, 2):
        resp = client.post("/analyze", json=payload)

        assert resp.status_code == 200, (
            f"[{fixture_name}] run{run_n}: expected HTTP 200, got {resp.status_code}"
        )

        body: dict = resp.json()
        _validate_contract(body)
        responses.append(body)

        # Per-run summary line (visible with pytest -s)
        v: dict = body.get("verdict") or {}
        rm: dict = body.get("reasoner_meta") or {}
        rt: dict = body.get("routing") or {}
        print(
            f"\n[{fixture_name}] run{run_n} | "
            f"verdict={v.get('verdict')} | "
            f"conf={v.get('confidence')} | "
            f"risk={v.get('risk_score')} | "
            f"sev={body.get('severity_num')} | "
            f"action={rt.get('action')} | "
            f"status={rm.get('status')} | "
            f"latency={rm.get('latency_ms')}ms"
        )

    # ------------------------------------------------------------------
    # Cross-run consistency check (report only — do not fail)
    # ------------------------------------------------------------------
    run1: dict = responses[0]
    run2: dict = responses[1]

    _fields_to_compare: list[tuple[str, Any, Any]] = [
        (
            "verdict.verdict",
            (run1.get("verdict") or {}).get("verdict"),
            (run2.get("verdict") or {}).get("verdict"),
        ),
        (
            "verdict.confidence",
            (run1.get("verdict") or {}).get("confidence"),
            (run2.get("verdict") or {}).get("confidence"),
        ),
        (
            "verdict.risk_score",
            (run1.get("verdict") or {}).get("risk_score"),
            (run2.get("verdict") or {}).get("risk_score"),
        ),
        (
            "severity_num",
            run1.get("severity_num"),
            run2.get("severity_num"),
        ),
        (
            "routing.action",
            (run1.get("routing") or {}).get("action"),
            (run2.get("routing") or {}).get("action"),
        ),
    ]

    diffs: list[tuple[str, Any, Any]] = [
        (field, v1, v2)
        for field, v1, v2 in _fields_to_compare
        if v1 != v2
    ]

    for field, v1, v2 in diffs:
        print(f"INCONSISTENCY [{fixture_name}]: {field} run1={v1} run2={v2}")
