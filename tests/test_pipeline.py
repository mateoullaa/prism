"""
tests/test_pipeline.py — End-to-end pipeline tests.

Exercises the full chain parse_alert -> enrich -> reason as a single integrated
unit, locking the cross-stage data contract: what one stage produces is exactly
what the next stage consumes. All external calls (enrichment APIs, Ollama) are
mocked; the suite is deterministic with no network or server dependencies.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Ensure the repo root is on the path so tools.* is importable.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.enricher import enrich  # noqa: E402
from tools.parser import parse_alert  # noqa: E402
from tools.reasoner import OllamaClient, reason  # noqa: E402

FIXTURES_DIR = REPO_ROOT / "data" / "sample_alerts"

VALID_VERDICT_JSON = {
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "justification": "External IP with malicious reputation and an attack signature.",
    "mitre": {"id": "T1110", "name": "Brute Force"},
    "next_action": "Block the source IP and review authentication logs.",
    "risk_score": 8,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_fixture(name: str) -> dict:
    """Load a JSON fixture by filename from the sample_alerts directory."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _ollama_client() -> OllamaClient:
    """OllamaClient backed by a mock session that returns a fixed valid verdict."""
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"response": json.dumps(VALID_VERDICT_JSON)}
    session.post.return_value = resp
    return OllamaClient(
        session=session,
        host="http://test-ollama:11434",
        model="qwen2.5:3b",
        timeout=5.0,
    )


def _enrich_clients() -> tuple:
    """(vt, abuse) mock clients whose query() returns canned 'ok' results."""
    vt = MagicMock()
    vt.query.return_value = {"status": "ok", "malicious": 8, "reputation": -40}
    abuse = MagicMock()
    abuse.query.return_value = {"status": "ok", "abuse_confidence_score": 100}
    return (vt, abuse)


def _assert_contract(result: dict) -> None:
    """Assert the final pipeline output satisfies the verdict + meta contract."""
    assert "verdict" in result and "reasoner_meta" in result

    verdict = result["verdict"]
    for key in ("verdict", "confidence", "justification", "mitre",
                "next_action", "risk_score"):
        assert key in verdict, f"missing verdict field: {key}"
    assert verdict["verdict"] in {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"}
    assert verdict["confidence"] in {"HIGH", "MEDIUM", "LOW"}
    assert isinstance(verdict["risk_score"], int)
    assert 1 <= verdict["risk_score"] <= 10

    meta = result["reasoner_meta"]
    assert meta["status"] in {"ok", "fallback"}
    assert isinstance(meta["latency_ms"], int)
    assert meta["model"] == "qwen2.5:3b"


# ---------------------------------------------------------------------------
# End-to-end paths
# ---------------------------------------------------------------------------


def test_pipeline_external_ip_runs_enrichment_end_to_end():
    """ssh_attack: parse -> enrich (external IP, mocked APIs) -> reason (mocked LLM).

    The external IP must flow into enrichment, the enrichment must be present,
    and the final verdict must honor the contract. All three stages mutate the
    same dict in place.
    """
    parsed = parse_alert(load_fixture("ssh_attack.json"))
    assert any(
        ioc.get("type") == "ip" and ioc.get("external") is True
        for ioc in parsed["iocs"]
    )

    enriched = enrich(parsed, clients=_enrich_clients())
    assert enriched is parsed              # in-place mutation contract
    assert enriched["enrichment"]          # at least one IP enriched

    result = reason(enriched, client=_ollama_client())
    assert result is parsed                # still the same dict
    _assert_contract(result)
    assert result["reasoner_meta"]["status"] == "ok"
    assert result["verdict"]["verdict"] == "TRUE_POSITIVE"


def test_pipeline_no_external_ip_skips_enrichment_end_to_end():
    """windows_spp_error: no external IOCs -> enrichment skipped ({}) but the
    chain still produces a valid, contract-conforming verdict.
    """
    parsed = parse_alert(load_fixture("windows_spp_error.json"))
    assert not any(ioc.get("external") is True for ioc in parsed["iocs"])

    enriched = enrich(parsed, clients=_enrich_clients())
    assert enriched["enrichment"] == {}

    result = reason(enriched, client=_ollama_client())
    _assert_contract(result)
