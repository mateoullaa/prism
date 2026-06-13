"""
tests/test_router.py — Pytest suite for tools/router.py.

All tests are deterministic; no network or server dependencies.
The router consumes the verdict + reasoner_meta written by reason() and produces
parsed["routing"].  Tests cover every decision branch plus defensive edge cases.
"""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.router import route  # noqa: E402
from tools.parser import parse_alert  # noqa: E402

FIXTURES_DIR = REPO_ROOT / "data" / "sample_alerts"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_parsed(
    verdict: str,
    confidence: str = "HIGH",
    meta_status: str = "ok",
    fallback_reason: str | None = None,
    downgrade_note: str | None = None,
) -> dict:
    """Build a minimal parsed dict with verdict and reasoner_meta pre-filled."""
    meta: dict = {
        "status": meta_status,
        "fallback_reason": fallback_reason,
        "model": "qwen2.5:3b",
        "latency_ms": 100,
    }
    if downgrade_note is not None:
        meta["downgrade_note"] = downgrade_note
    return {
        "alert_type": "ssh",
        "verdict": {
            "verdict": verdict,
            "confidence": confidence,
            "justification": "Test justification.",
            "mitre": None,
            "next_action": "Do something.",
            "risk_score": 5,
        },
        "reasoner_meta": meta,
    }


def load_fixture(name: str) -> dict:
    """Load a JSON fixture by filename from the sample_alerts directory."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. TRUE_POSITIVE → create_case + send_to_shuffle True
# ---------------------------------------------------------------------------


def test_route_true_positive_creates_case():
    """TRUE_POSITIVE verdict results in create_case with send_to_shuffle=True."""
    parsed = _make_parsed("TRUE_POSITIVE")
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True
    assert "TRUE_POSITIVE" in result["routing"]["reason"]


def test_route_true_positive_send_to_shuffle_is_bool_true():
    """send_to_shuffle must be the boolean True, not just truthy."""
    parsed = _make_parsed("TRUE_POSITIVE")
    route(parsed)
    assert type(parsed["routing"]["send_to_shuffle"]) is bool
    assert parsed["routing"]["send_to_shuffle"] is True


# ---------------------------------------------------------------------------
# 2. FALSE_POSITIVE (HIGH confidence) → discard + send_to_shuffle False
# ---------------------------------------------------------------------------


def test_route_false_positive_high_confidence_discards():
    """HIGH-confidence FALSE_POSITIVE is discarded and not sent to Shuffle."""
    parsed = _make_parsed("FALSE_POSITIVE", confidence="HIGH")
    result = route(parsed)

    assert result["routing"]["action"] == "discard"
    assert result["routing"]["send_to_shuffle"] is False
    assert "false positive" in result["routing"]["reason"].lower()


def test_route_false_positive_reason_includes_confidence():
    """The discard reason must cite the confidence level for the audit trail."""
    parsed = _make_parsed("FALSE_POSITIVE", confidence="HIGH")
    route(parsed)
    assert "HIGH" in parsed["routing"]["reason"]


def test_route_false_positive_send_to_shuffle_is_bool_false():
    """send_to_shuffle must be the boolean False, not just falsy."""
    parsed = _make_parsed("FALSE_POSITIVE", confidence="HIGH")
    route(parsed)
    assert type(parsed["routing"]["send_to_shuffle"]) is bool
    assert parsed["routing"]["send_to_shuffle"] is False


# ---------------------------------------------------------------------------
# 3. NEEDS_REVIEW → create_case (conservative)
# ---------------------------------------------------------------------------


def test_route_needs_review_creates_case():
    """NEEDS_REVIEW is conservatively escalated: create_case + send_to_shuffle=True."""
    parsed = _make_parsed("NEEDS_REVIEW")
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True
    assert "NEEDS_REVIEW" in result["routing"]["reason"]


def test_route_needs_review_low_confidence_creates_case():
    """NEEDS_REVIEW with LOW confidence still creates a case (never discards on uncertainty)."""
    parsed = _make_parsed("NEEDS_REVIEW", confidence="LOW")
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True


# ---------------------------------------------------------------------------
# 4. reasoner_meta status="fallback" → reason notes it
# ---------------------------------------------------------------------------


def test_route_fallback_status_noted_in_reason():
    """When reasoner_meta.status == 'fallback', the routing reason must mention it."""
    parsed = _make_parsed(
        "NEEDS_REVIEW",
        meta_status="fallback",
        fallback_reason="Ollama timeout",
    )
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    reason = result["routing"]["reason"]
    # Either "fallback" or the phrase "fell back" must appear
    assert "fallback" in reason.lower() or "fell back" in reason.lower()


def test_route_fallback_reason_string_appears_in_reason():
    """The specific fallback_reason string from reasoner_meta must appear in routing reason."""
    parsed = _make_parsed(
        "NEEDS_REVIEW",
        meta_status="fallback",
        fallback_reason="Ollama timeout: request exceeded the configured timeout",
    )
    route(parsed)
    assert "Ollama timeout: request exceeded the configured timeout" in parsed["routing"]["reason"]


def test_route_fallback_with_true_positive_still_creates_case_and_notes_fallback():
    """TRUE_POSITIVE with fallback meta creates a case and the reason notes the fallback."""
    parsed = _make_parsed(
        "TRUE_POSITIVE",
        meta_status="fallback",
        fallback_reason="LLM returned non-JSON response",
    )
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True
    assert "LLM returned non-JSON response" in result["routing"]["reason"]


def test_route_ok_status_no_fallback_note():
    """When meta_status == 'ok', the routing reason must NOT mention a fallback."""
    parsed = _make_parsed("TRUE_POSITIVE", meta_status="ok")
    route(parsed)
    # "fell back" / "fallback" must not appear when status is ok
    assert "fell back" not in parsed["routing"]["reason"].lower()
    assert "fallback" not in parsed["routing"]["reason"].lower()


# ---------------------------------------------------------------------------
# 5. downgrade_note present → reason includes it
# ---------------------------------------------------------------------------


def test_route_downgrade_note_included_in_reason():
    """When a downgrade_note is present, the routing reason must include the full note."""
    note = (
        "FP guardrail: verdict downgraded from FALSE_POSITIVE "
        "(confidence=MEDIUM) to NEEDS_REVIEW"
    )
    parsed = _make_parsed(
        "NEEDS_REVIEW",
        confidence="MEDIUM",
        downgrade_note=note,
    )
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert note in result["routing"]["reason"]


def test_route_downgrade_note_with_ok_status_still_included():
    """downgrade_note is included even when meta_status == 'ok'."""
    note = (
        "FP guardrail: verdict downgraded from FALSE_POSITIVE "
        "(confidence=LOW) to NEEDS_REVIEW"
    )
    parsed = _make_parsed(
        "NEEDS_REVIEW",
        confidence="LOW",
        meta_status="ok",
        downgrade_note=note,
    )
    route(parsed)
    assert note in parsed["routing"]["reason"]


def test_route_downgrade_note_and_fallback_both_in_reason():
    """Both a downgrade_note and a fallback status can coexist in the routing reason."""
    note = "FP guardrail: verdict downgraded from FALSE_POSITIVE (confidence=LOW) to NEEDS_REVIEW"
    parsed = _make_parsed(
        "NEEDS_REVIEW",
        confidence="LOW",
        meta_status="fallback",
        fallback_reason="Ollama error: connection refused",
        downgrade_note=note,
    )
    route(parsed)
    reason = parsed["routing"]["reason"]
    assert note in reason
    assert "Ollama error: connection refused" in reason


# ---------------------------------------------------------------------------
# 6. Defensive: route({}) and garbage verdict → create_case, never raises
# ---------------------------------------------------------------------------


def test_route_empty_dict_never_raises():
    """route({}) must not raise; defensive escalation produces create_case."""
    result = route({})

    assert "routing" in result
    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True


def test_route_missing_verdict_key_escalates():
    """A dict without a 'verdict' key triggers defensive escalation."""
    parsed = {"alert_type": "ssh", "reasoner_meta": {"status": "ok"}}
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True


def test_route_verdict_not_a_dict_escalates():
    """A non-dict 'verdict' value (e.g. a plain string) triggers defensive escalation."""
    parsed = {"verdict": "TRUE_POSITIVE", "reasoner_meta": {"status": "ok"}}
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True
    # The reason must explain why (not a dict or absent)
    assert (
        "not a dict" in result["routing"]["reason"].lower()
        or "absent" in result["routing"]["reason"].lower()
    )


def test_route_unrecognized_verdict_value_escalates():
    """An unrecognized verdict string triggers defensive escalation and cites the value."""
    parsed = {
        "verdict": {"verdict": "MAYBE_POSITIVE", "confidence": "HIGH"},
        "reasoner_meta": {"status": "ok"},
    }
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True
    assert "MAYBE_POSITIVE" in result["routing"]["reason"]


def test_route_verdict_value_is_integer_escalates():
    """A verdict value that is an integer (not a string) triggers defensive escalation."""
    parsed = {
        "verdict": {"verdict": 42, "confidence": "HIGH"},
        "reasoner_meta": {"status": "ok"},
    }
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True


def test_route_verdict_is_none_escalates():
    """parsed['verdict'] = None triggers defensive escalation (not a dict)."""
    parsed = {"verdict": None, "reasoner_meta": {"status": "ok"}}
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True


def test_route_reasoner_meta_is_absent_still_works():
    """When 'reasoner_meta' is absent, route() must still produce a valid routing entry."""
    parsed = {
        "verdict": {
            "verdict": "TRUE_POSITIVE",
            "confidence": "HIGH",
            "justification": "Test.",
            "mitre": None,
            "next_action": "Test.",
            "risk_score": 7,
        }
        # No 'reasoner_meta' key at all
    }
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True


def test_route_reasoner_meta_is_not_a_dict_still_works():
    """When 'reasoner_meta' is a non-dict value, route() must not raise."""
    parsed = {
        "verdict": {
            "verdict": "NEEDS_REVIEW",
            "confidence": "LOW",
            "justification": "Test.",
            "mitre": None,
            "next_action": "Test.",
            "risk_score": 5,
        },
        "reasoner_meta": "some-string-not-a-dict",
    }
    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True


# ---------------------------------------------------------------------------
# 7. In-place mutation contract
# ---------------------------------------------------------------------------


def test_route_returns_same_dict_instance():
    """route() must return the exact same dict object (in-place mutation)."""
    parsed = _make_parsed("TRUE_POSITIVE")
    result = route(parsed)

    assert result is parsed


def test_route_adds_routing_key():
    """The 'routing' key must be added to the dict by route()."""
    parsed = _make_parsed("NEEDS_REVIEW")
    assert "routing" not in parsed

    route(parsed)

    assert "routing" in parsed


def test_route_routing_has_all_required_fields():
    """The routing dict must always contain 'action', 'send_to_shuffle', and 'reason'."""
    for verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"):
        parsed = _make_parsed(verdict)
        route(parsed)
        routing = parsed["routing"]
        assert "action" in routing, f"'action' missing for {verdict}"
        assert "send_to_shuffle" in routing, f"'send_to_shuffle' missing for {verdict}"
        assert "reason" in routing, f"'reason' missing for {verdict}"
        assert isinstance(routing["reason"], str), "reason must be a string"
        assert len(routing["reason"]) > 0, "reason must be non-empty"


def test_route_does_not_mutate_other_keys():
    """route() must not modify any pre-existing keys in parsed."""
    parsed = _make_parsed("TRUE_POSITIVE")
    verdict_before = dict(parsed["verdict"])
    meta_before = dict(parsed["reasoner_meta"])

    route(parsed)

    assert parsed["verdict"] == verdict_before
    assert parsed["reasoner_meta"] == meta_before
    assert parsed["alert_type"] == "ssh"


# ---------------------------------------------------------------------------
# 8. Realistic end-to-end: parse fixture + inject verdict + route
# ---------------------------------------------------------------------------


def test_route_realistic_ssh_attack_true_positive():
    """Parse real ssh_attack fixture, inject TRUE_POSITIVE verdict, then route.

    Confirms the contract holds on a real parsed structure with all parser fields.
    """
    parsed = parse_alert(load_fixture("ssh_attack.json"))

    parsed["verdict"] = {
        "verdict": "TRUE_POSITIVE",
        "confidence": "HIGH",
        "justification": (
            "External IP with repeated SSH login failures matching brute-force pattern. "
            "Source country has no known business relationship."
        ),
        "mitre": {"id": "T1110", "name": "Brute Force"},
        "next_action": "Block source IP at perimeter firewall.",
        "risk_score": 8,
    }
    parsed["reasoner_meta"] = {
        "status": "ok",
        "fallback_reason": None,
        "model": "qwen2.5:3b",
        "latency_ms": 312,
    }

    result = route(parsed)

    assert result is parsed
    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True
    assert "TRUE_POSITIVE" in result["routing"]["reason"]
    # Parser fields must be intact
    assert result["alert_type"] == "ssh"
    assert "iocs" in result
    assert "has_external_iocs" in result


def test_route_realistic_windows_spp_error_false_positive():
    """Parse windows_spp_error (rule 60602, the dominant FP), inject HIGH-confidence
    FALSE_POSITIVE verdict, and confirm it is discarded.
    """
    parsed = parse_alert(load_fixture("windows_spp_error.json"))

    parsed["verdict"] = {
        "verdict": "FALSE_POSITIVE",
        "confidence": "HIGH",
        "justification": (
            "Rule 60602 matches a known benign Windows SPP service error. "
            "No suspicious indicators present."
        ),
        "mitre": None,
        "next_action": "No action required.",
        "risk_score": 1,
    }
    parsed["reasoner_meta"] = {
        "status": "ok",
        "fallback_reason": None,
        "model": "qwen2.5:3b",
        "latency_ms": 280,
    }

    result = route(parsed)

    assert result is parsed
    assert result["routing"]["action"] == "discard"
    assert result["routing"]["send_to_shuffle"] is False
    assert "false positive" in result["routing"]["reason"].lower()
    assert "HIGH" in result["routing"]["reason"]
    # Parser fields intact
    assert result["alert_type"] == "windows_event"
    assert result["is_known_fp_candidate"] is True


def test_route_realistic_firewall_block_needs_review_with_fallback():
    """Parse firewall_block fixture, inject NEEDS_REVIEW with fallback meta, confirm
    the routing reason includes both the verdict and the fallback context.
    """
    parsed = parse_alert(load_fixture("firewall_block.json"))

    parsed["verdict"] = {
        "verdict": "NEEDS_REVIEW",
        "confidence": "LOW",
        "justification": "Automated analysis unavailable: Ollama error. Manual review required.",
        "mitre": None,
        "next_action": "Escalate to analyst for manual triage.",
        "risk_score": 5,
    }
    parsed["reasoner_meta"] = {
        "status": "fallback",
        "fallback_reason": "Ollama error: HTTP 503",
        "model": "qwen2.5:3b",
        "latency_ms": 0,
    }

    result = route(parsed)

    assert result["routing"]["action"] == "create_case"
    assert result["routing"]["send_to_shuffle"] is True
    reason = result["routing"]["reason"]
    assert "NEEDS_REVIEW" in reason
    assert "Ollama error: HTTP 503" in reason
    assert "fell back" in reason.lower() or "fallback" in reason.lower()
