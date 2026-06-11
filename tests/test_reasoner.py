"""
tests/test_reasoner.py — Pytest suite for tools/reasoner.py.

All tests are deterministic; no network or server dependencies.
All calls to the Ollama server are replaced by injected mock sessions/clients.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

# Ensure the repo root is on the path so tools.* is importable.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.reasoner import (  # noqa: E402
    OllamaClient,
    _parse_llm_json,
    _validate_verdict,
    build_prompt,
    fallback_verdict,
    reason,
)
from tools.parser import parse_alert  # noqa: E402

FIXTURES_DIR = REPO_ROOT / "data" / "sample_alerts"

FIXTURE_NAMES = [
    "ssh_attack.json",
    "firewall_block.json",
    "virustotal.json",
    "vulnerability.json",
    "windows_logon.json",
    "windows_spp_error.json",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_fixture(name: str) -> dict:
    """Load a JSON fixture by filename from the sample_alerts directory."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    """Build a mock requests.Response with given JSON body and status."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    return resp


def _make_client(session: MagicMock) -> OllamaClient:
    """Build an OllamaClient with a mock session for testing."""
    return OllamaClient(
        session=session,
        host="http://test-ollama:11434",
        model="qwen2.5:3b",
        timeout=5.0,
    )


# ---------------------------------------------------------------------------
# Canonical valid verdict for mocking
# ---------------------------------------------------------------------------

VALID_VERDICT_JSON = {
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "justification": (
        "External IP performed repeated SSH login attempts with invalid usernames. "
        "Pattern matches brute-force credential stuffing. "
        "Source country has no known business relationship."
    ),
    "mitre": {"id": "T1110", "name": "Brute Force"},
    "next_action": "Block source IP at perimeter firewall and investigate targeted account.",
    "risk_score": 7,
}


# ---------------------------------------------------------------------------
# 1. OK response — clean 200 with valid JSON verdict
# ---------------------------------------------------------------------------


def test_reason_ok_response_returns_validated_verdict():
    """A clean 200 response with valid JSON produces status='ok' and the correct verdict."""
    session = MagicMock()
    session.post.return_value = _mock_response(
        {"response": json.dumps(VALID_VERDICT_JSON)}
    )
    client = _make_client(session)

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    result = reason(parsed, client=client)

    assert "verdict" in result
    assert "reasoner_meta" in result
    assert result["reasoner_meta"]["status"] == "ok"
    assert result["verdict"]["verdict"] == "TRUE_POSITIVE"
    assert result["verdict"]["confidence"] == "HIGH"
    assert result["verdict"]["risk_score"] == 7
    assert isinstance(result["reasoner_meta"]["latency_ms"], int)
    assert result["reasoner_meta"]["model"] == "qwen2.5:3b"


# ---------------------------------------------------------------------------
# 2. Invalid JSON from LLM → fallback
# ---------------------------------------------------------------------------


def test_reason_invalid_json_produces_fallback():
    """Non-JSON LLM response triggers NEEDS_REVIEW fallback with status='fallback'."""
    session = MagicMock()
    session.post.return_value = _mock_response(
        {"response": "I cannot analyze this alert right now."}
    )
    client = _make_client(session)

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    result = reason(parsed, client=client)

    assert result["reasoner_meta"]["status"] == "fallback"
    assert result["verdict"]["verdict"] == "NEEDS_REVIEW"
    assert result["verdict"]["confidence"] == "LOW"


# ---------------------------------------------------------------------------
# 3. JSON with surrounding text — defensive extraction
# ---------------------------------------------------------------------------


def test_reason_json_with_surrounding_text_is_extracted():
    """LLM response with surrounding text still yields a valid verdict via defensive extraction."""
    surrounding = (
        "Here is my analysis:\n"
        + json.dumps(VALID_VERDICT_JSON)
        + "\nI hope this helps."
    )
    session = MagicMock()
    session.post.return_value = _mock_response({"response": surrounding})
    client = _make_client(session)

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    result = reason(parsed, client=client)

    assert result["reasoner_meta"]["status"] == "ok"
    assert result["verdict"]["verdict"] == "TRUE_POSITIVE"


# ---------------------------------------------------------------------------
# 4. Valid JSON but violating the contract → fallback
# ---------------------------------------------------------------------------


def test_reason_invalid_verdict_enum_produces_fallback():
    """JSON with an unrecognised verdict enum fails validation and triggers fallback."""
    bad_verdict = {**VALID_VERDICT_JSON, "verdict": "MAYBE_POSITIVE"}
    session = MagicMock()
    session.post.return_value = _mock_response({"response": json.dumps(bad_verdict)})
    client = _make_client(session)

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    result = reason(parsed, client=client)

    assert result["reasoner_meta"]["status"] == "fallback"
    assert result["verdict"]["verdict"] == "NEEDS_REVIEW"


def test_reason_missing_justification_produces_fallback():
    """JSON missing the required 'justification' field triggers fallback."""
    bad_verdict = {k: v for k, v in VALID_VERDICT_JSON.items() if k != "justification"}
    session = MagicMock()
    session.post.return_value = _mock_response({"response": json.dumps(bad_verdict)})
    client = _make_client(session)

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    result = reason(parsed, client=client)

    assert result["reasoner_meta"]["status"] == "fallback"
    assert result["verdict"]["verdict"] == "NEEDS_REVIEW"


def test_reason_missing_next_action_produces_fallback():
    """JSON missing the required 'next_action' field triggers fallback."""
    bad_verdict = {k: v for k, v in VALID_VERDICT_JSON.items() if k != "next_action"}
    session = MagicMock()
    session.post.return_value = _mock_response({"response": json.dumps(bad_verdict)})
    client = _make_client(session)

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    result = reason(parsed, client=client)

    assert result["reasoner_meta"]["status"] == "fallback"


# ---------------------------------------------------------------------------
# 5. Normalization
# ---------------------------------------------------------------------------


def test_validate_verdict_normalizes_lowercase_verdict_and_confidence():
    """Lowercase verdict/confidence strings are upper-cased during normalization."""
    obj = {**VALID_VERDICT_JSON, "verdict": "true_positive", "confidence": "high"}
    result = _validate_verdict(obj)
    assert result is not None
    assert result["verdict"] == "TRUE_POSITIVE"
    assert result["confidence"] == "HIGH"


def test_validate_verdict_normalizes_string_risk_score_seven():
    """risk_score as string '7' is coerced to int 7."""
    obj = {**VALID_VERDICT_JSON, "risk_score": "7"}
    result = _validate_verdict(obj)
    assert result is not None
    assert result["risk_score"] == 7
    assert isinstance(result["risk_score"], int)


def test_validate_verdict_clamps_risk_score_above_10():
    """risk_score of 15 is clamped down to 10."""
    obj = {**VALID_VERDICT_JSON, "risk_score": 15}
    result = _validate_verdict(obj)
    assert result is not None
    assert result["risk_score"] == 10


def test_validate_verdict_clamps_risk_score_below_1():
    """risk_score of -3 is clamped up to 1."""
    obj = {**VALID_VERDICT_JSON, "risk_score": -3}
    result = _validate_verdict(obj)
    assert result is not None
    assert result["risk_score"] == 1


def test_validate_verdict_normalizes_malformed_mitre_to_none():
    """Malformed mitre dict (missing 'name') is normalized to None without invalidating verdict."""
    obj = {**VALID_VERDICT_JSON, "mitre": {"id": "T1110"}}  # missing 'name'
    result = _validate_verdict(obj)
    assert result is not None
    assert result["mitre"] is None
    assert result["verdict"] == "TRUE_POSITIVE"  # verdict still valid


def test_validate_verdict_normalizes_mitre_wrong_type_to_none():
    """mitre as a plain string is normalized to None without invalidating verdict."""
    obj = {**VALID_VERDICT_JSON, "mitre": "T1110"}
    result = _validate_verdict(obj)
    assert result is not None
    assert result["mitre"] is None


def test_validate_verdict_non_numeric_risk_score_returns_none():
    """Non-numeric risk_score (unparseable string) causes validation to return None."""
    obj = {**VALID_VERDICT_JSON, "risk_score": "not-a-number"}
    result = _validate_verdict(obj)
    assert result is None


# ---------------------------------------------------------------------------
# 6. FP guardrail: FALSE_POSITIVE + non-HIGH confidence → forced NEEDS_REVIEW
# ---------------------------------------------------------------------------


def test_reason_fp_guardrail_downgrades_medium_confidence():
    """FALSE_POSITIVE with MEDIUM confidence is downgraded to NEEDS_REVIEW with meta note."""
    fp_verdict = {**VALID_VERDICT_JSON, "verdict": "FALSE_POSITIVE", "confidence": "MEDIUM"}
    session = MagicMock()
    session.post.return_value = _mock_response({"response": json.dumps(fp_verdict)})
    client = _make_client(session)

    parsed = parse_alert(load_fixture("windows_spp_error.json"))
    result = reason(parsed, client=client)

    # Guardrail fires: verdict is NEEDS_REVIEW but meta.status stays "ok"
    assert result["verdict"]["verdict"] == "NEEDS_REVIEW"
    assert result["reasoner_meta"]["status"] == "ok"
    assert "downgrade_note" in result["reasoner_meta"]
    assert "FALSE_POSITIVE" in result["reasoner_meta"]["downgrade_note"]
    assert "NEEDS_REVIEW" in result["reasoner_meta"]["downgrade_note"]


def test_reason_fp_guardrail_downgrades_low_confidence():
    """FALSE_POSITIVE with LOW confidence is also downgraded to NEEDS_REVIEW."""
    fp_verdict = {**VALID_VERDICT_JSON, "verdict": "FALSE_POSITIVE", "confidence": "LOW"}
    session = MagicMock()
    session.post.return_value = _mock_response({"response": json.dumps(fp_verdict)})
    client = _make_client(session)

    parsed = parse_alert(load_fixture("windows_logon.json"))
    result = reason(parsed, client=client)

    assert result["verdict"]["verdict"] == "NEEDS_REVIEW"
    assert "downgrade_note" in result["reasoner_meta"]
    assert "LOW" in result["reasoner_meta"]["downgrade_note"]


def test_reason_fp_high_confidence_is_not_downgraded():
    """FALSE_POSITIVE with HIGH confidence passes the guardrail unchanged."""
    fp_verdict = {**VALID_VERDICT_JSON, "verdict": "FALSE_POSITIVE", "confidence": "HIGH"}
    session = MagicMock()
    session.post.return_value = _mock_response({"response": json.dumps(fp_verdict)})
    client = _make_client(session)

    parsed = parse_alert(load_fixture("windows_spp_error.json"))
    result = reason(parsed, client=client)

    assert result["verdict"]["verdict"] == "FALSE_POSITIVE"
    assert result["reasoner_meta"]["status"] == "ok"
    assert "downgrade_note" not in result["reasoner_meta"]


# ---------------------------------------------------------------------------
# 7. Timeout → fallback
# ---------------------------------------------------------------------------


def test_reason_timeout_produces_fallback():
    """requests.Timeout from Ollama triggers NEEDS_REVIEW fallback."""
    session = MagicMock()
    session.post.side_effect = requests.Timeout("timed out after 30s")
    client = _make_client(session)

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    result = reason(parsed, client=client)

    assert result["reasoner_meta"]["status"] == "fallback"
    assert "timeout" in result["reasoner_meta"]["fallback_reason"].lower()
    assert result["verdict"]["verdict"] == "NEEDS_REVIEW"
    assert result["verdict"]["confidence"] == "LOW"


# ---------------------------------------------------------------------------
# 8. Connection error → fallback
# ---------------------------------------------------------------------------


def test_reason_connection_error_produces_fallback():
    """requests.ConnectionError from Ollama triggers NEEDS_REVIEW fallback."""
    session = MagicMock()
    session.post.side_effect = requests.ConnectionError("connection refused")
    client = _make_client(session)

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    result = reason(parsed, client=client)

    assert result["reasoner_meta"]["status"] == "fallback"
    assert result["verdict"]["verdict"] == "NEEDS_REVIEW"
    assert result["verdict"]["confidence"] == "LOW"


# ---------------------------------------------------------------------------
# 9. HTTP 500 → fallback
# ---------------------------------------------------------------------------


def test_reason_http_500_produces_fallback():
    """HTTP 500 response from Ollama triggers NEEDS_REVIEW fallback with code in reason."""
    session = MagicMock()
    session.post.return_value = _mock_response({}, status_code=500)
    client = _make_client(session)

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    result = reason(parsed, client=client)

    assert result["reasoner_meta"]["status"] == "fallback"
    assert "500" in result["reasoner_meta"]["fallback_reason"]
    assert result["verdict"]["verdict"] == "NEEDS_REVIEW"


# ---------------------------------------------------------------------------
# 10. build_prompt against all 6 fixtures — with and without enrichment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name", FIXTURE_NAMES)
def test_build_prompt_all_fixtures_no_crash(fixture_name: str):
    """build_prompt() does not raise for any of the 6 sample fixtures (no enrichment)."""
    parsed = parse_alert(load_fixture(fixture_name))
    prompt = build_prompt(parsed)

    assert isinstance(prompt, str)
    assert len(prompt) > 0
    # Must contain the schema enums so the LLM knows valid values
    assert "TRUE_POSITIVE" in prompt
    assert "FALSE_POSITIVE" in prompt
    assert "NEEDS_REVIEW" in prompt
    # Must contain the nature category field
    assert "Nature category" in prompt


@pytest.mark.parametrize("fixture_name", FIXTURE_NAMES)
def test_build_prompt_with_ok_enrichment_includes_provider_data(fixture_name: str):
    """build_prompt() includes VirusTotal and AbuseIPDB data when enrichment status is 'ok'."""
    parsed = parse_alert(load_fixture(fixture_name))
    # Inject mock enrichment for all fixtures
    parsed["enrichment"] = {
        "5.5.5.5": {
            "virustotal": {
                "status": "ok",
                "malicious": 3,
                "suspicious": 1,
                "reputation": -12,
            },
            "abuseipdb": {
                "status": "ok",
                "abuse_confidence_score": 100,
                "total_reports": 42,
                "country_code": "DE",
            },
        }
    }
    prompt = build_prompt(parsed)

    assert "VirusTotal" in prompt
    assert "AbuseIPDB" in prompt


@pytest.mark.parametrize("fixture_name", FIXTURE_NAMES)
def test_build_prompt_skips_error_and_rate_limited_enrichment(fixture_name: str):
    """build_prompt() omits error/rate_limited enrichment entries and notes unavailable."""
    parsed = parse_alert(load_fixture(fixture_name))
    parsed["enrichment"] = {
        "5.5.5.5": {
            "virustotal": {"status": "error", "message": "API key invalid"},
            "abuseipdb": {"status": "rate_limited", "message": "too many requests"},
        }
    }
    prompt = build_prompt(parsed)

    # Neither provider data should appear; unavailable note must be present
    assert "malicious=" not in prompt
    assert "confidence=" not in prompt
    assert "unavailable" in prompt.lower()


# ---------------------------------------------------------------------------
# 11. Pipeline never breaks — reason({}) must not raise
# ---------------------------------------------------------------------------


def test_reason_empty_dict_never_raises():
    """reason({}) with an empty input dict must not raise; must return verdict and meta."""
    session = MagicMock()
    session.post.return_value = _mock_response(
        {"response": json.dumps(VALID_VERDICT_JSON)}
    )
    client = _make_client(session)

    result = reason({}, client=client)

    assert "verdict" in result
    assert "reasoner_meta" in result


def test_reason_completely_broken_client_never_raises():
    """Even when the session raises RuntimeError, reason() returns a fallback without raising."""
    session = MagicMock()
    session.post.side_effect = RuntimeError("catastrophic failure")
    client = _make_client(session)

    result = reason({"alert_type": "ssh", "iocs": []}, client=client)

    assert "verdict" in result
    assert "reasoner_meta" in result
    assert result["reasoner_meta"]["status"] == "fallback"
    assert result["verdict"]["verdict"] == "NEEDS_REVIEW"


# ---------------------------------------------------------------------------
# Unit tests for _parse_llm_json
# ---------------------------------------------------------------------------


def test_parse_llm_json_clean_valid_json():
    """_parse_llm_json returns dict for a clean JSON string."""
    obj = {"verdict": "TRUE_POSITIVE", "risk_score": 7}
    assert _parse_llm_json(json.dumps(obj)) == obj


def test_parse_llm_json_returns_none_for_plain_text():
    """_parse_llm_json returns None when the input contains no JSON object."""
    assert _parse_llm_json("I cannot analyze this.") is None


def test_parse_llm_json_extracts_from_preamble_and_postamble():
    """_parse_llm_json extracts valid JSON from text with a preamble and postamble."""
    payload = {"x": 1, "y": 2}
    text = f"Some preamble text\n{json.dumps(payload)}\nSome postamble text."
    assert _parse_llm_json(text) == payload


def test_parse_llm_json_returns_none_for_non_string():
    """_parse_llm_json returns None for non-string input (type safety guard)."""
    assert _parse_llm_json(None) is None  # type: ignore[arg-type]


def test_parse_llm_json_returns_none_for_empty_string():
    """_parse_llm_json returns None for an empty string."""
    assert _parse_llm_json("") is None


# ---------------------------------------------------------------------------
# Unit tests for fallback_verdict
# ---------------------------------------------------------------------------


def test_fallback_verdict_has_correct_structure():
    """fallback_verdict() returns the exact contract-compliant structure."""
    fv = fallback_verdict("test reason")

    assert fv["verdict"] == "NEEDS_REVIEW"
    assert fv["confidence"] == "LOW"
    assert "test reason" in fv["justification"]
    assert "Manual review required" in fv["justification"]
    assert fv["mitre"] is None
    assert fv["next_action"] == "Escalate to analyst for manual triage"
    assert fv["risk_score"] == 5


def test_fallback_verdict_includes_automated_unavailable_prefix():
    """fallback_verdict() always starts with 'Automated analysis unavailable:'."""
    fv = fallback_verdict("connection refused")
    assert fv["justification"].startswith("Automated analysis unavailable:")
