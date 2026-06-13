"""
tests/test_logger.py — Pytest suite for tools/logger.py.

All tests are deterministic; no network or server dependencies.  Uses
pytest's ``tmp_path`` fixture for log_path injection to avoid filesystem
side effects across test runs.  Mirrors the style of tests/test_router.py.
"""

import csv
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.logger import log_alert  # noqa: E402
from tools.parser import parse_alert  # noqa: E402
from tools.reasoner import OllamaClient, reason  # noqa: E402
from tools.router import route  # noqa: E402

FIXTURES_DIR = REPO_ROOT / "data" / "sample_alerts"

# Fixed timestamp injected into every test for deterministic assertions.
FIXED_TS = "2026-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_parsed(
    verdict: str = "TRUE_POSITIVE",
    confidence: str = "HIGH",
    meta_status: str = "ok",
    fallback_reason: str | None = None,
    action: str = "create_case",
    send_to_shuffle: bool = True,
    routing_reason: str = "Test routing reason.",
    mitre: dict | None = None,
    risk_score: int = 7,
) -> dict:
    """Build a minimal parsed dict with verdict, reasoner_meta, and routing.

    Mirrors the structure produced by the full pipeline (parser + reasoner +
    router), with all required sub-dicts pre-filled.
    """
    meta: dict = {
        "status": meta_status,
        "fallback_reason": fallback_reason,
        "model": "qwen2.5:3b",
        "latency_ms": 150,
    }
    return {
        "alert_type": "ssh",
        "nature_category": "public_attack",
        "rule_id": "5710",
        "rule_level": 5,
        "rule_description": "SSH brute force attempt.",
        "is_known_fp_candidate": False,
        "verdict": {
            "verdict": verdict,
            "confidence": confidence,
            "justification": "Test justification.",
            "mitre": mitre,
            "next_action": "Block IP.",
            "risk_score": risk_score,
        },
        "reasoner_meta": meta,
        "routing": {
            "action": action,
            "send_to_shuffle": send_to_shuffle,
            "reason": routing_reason,
        },
    }


def load_fixture(name: str) -> dict:
    """Load a JSON fixture by filename from the sample_alerts directory."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _read_csv(path: Path) -> list[dict]:
    """Read all rows from a CSV file into a list of dicts."""
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _make_ollama_client(verdict_json: dict) -> OllamaClient:
    """Return a mock OllamaClient that yields a fixed verdict JSON."""
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"response": json.dumps(verdict_json)}
    session.post.return_value = resp
    return OllamaClient(
        session=session,
        host="http://test-ollama:11434",
        model="qwen2.5:3b",
        timeout=5.0,
    )


# ---------------------------------------------------------------------------
# 1. TRUE_POSITIVE (create_case) row — all columns correct
# ---------------------------------------------------------------------------


def test_log_alert_true_positive_all_columns(tmp_path):
    """A TRUE_POSITIVE alert writes a row with every column correctly populated."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed(
        verdict="TRUE_POSITIVE",
        confidence="HIGH",
        action="create_case",
        send_to_shuffle=True,
        routing_reason="Verdict is TRUE_POSITIVE. Case created.",
        mitre={"id": "T1110", "name": "Brute Force"},
        risk_score=8,
    )

    record = log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert len(rows) == 1
    row = rows[0]

    assert row["timestamp"] == FIXED_TS
    assert row["alert_type"] == "ssh"
    assert row["nature_category"] == "public_attack"
    assert row["rule_id"] == "5710"
    assert row["rule_description"] == "SSH brute force attempt."
    assert row["verdict"] == "TRUE_POSITIVE"
    assert row["confidence"] == "HIGH"
    assert row["risk_score"] == "8"
    assert row["mitre_id"] == "T1110"
    assert row["action"] == "create_case"
    assert row["send_to_shuffle"] == "True"
    assert row["status"] == "ok"
    assert row["latency_ms"] == "150"
    assert row["model"] == "qwen2.5:3b"
    assert row["is_known_fp_candidate"] == "False"
    assert row["reason"] == "Verdict is TRUE_POSITIVE. Case created."

    # log_alert also returns the record dict
    assert record["verdict"] == "TRUE_POSITIVE"
    assert record["mitre_id"] == "T1110"
    assert record["timestamp"] == FIXED_TS


# ---------------------------------------------------------------------------
# 2. discard (FALSE_POSITIVE) row IS written and reason persisted (key audit req)
# ---------------------------------------------------------------------------


def test_log_alert_discard_false_positive_row_written(tmp_path):
    """Discarded FALSE_POSITIVE alerts MUST produce a CSV row — mandatory audit trail."""
    log_path = str(tmp_path / "triage.csv")
    fp_reason = (
        "Confirmed false positive (confidence=HIGH). "
        "Alert discarded — no case created."
    )
    parsed = _make_parsed(
        verdict="FALSE_POSITIVE",
        confidence="HIGH",
        action="discard",
        send_to_shuffle=False,
        routing_reason=fp_reason,
    )

    log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert len(rows) == 1, "Discarded alert must produce exactly one CSV row"
    row = rows[0]
    assert row["action"] == "discard"
    assert row["send_to_shuffle"] == "False"
    assert row["verdict"] == "FALSE_POSITIVE"
    assert row["reason"] == fp_reason, "Discard reason must be persisted verbatim"


def test_log_alert_discard_reason_not_empty(tmp_path):
    """The 'reason' column for a discarded alert must not be an empty string."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed(
        verdict="FALSE_POSITIVE",
        action="discard",
        send_to_shuffle=False,
        routing_reason="Some discard reason.",
    )
    log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert rows[0]["reason"] != ""


# ---------------------------------------------------------------------------
# 3. Header written once; second log_alert appends without duplicating header
# ---------------------------------------------------------------------------


def test_log_alert_header_written_once(tmp_path):
    """Header appears exactly once even after multiple log_alert calls."""
    log_path = str(tmp_path / "triage.csv")

    log_alert(_make_parsed("TRUE_POSITIVE"), log_path=log_path, timestamp=FIXED_TS)
    log_alert(
        _make_parsed("FALSE_POSITIVE", action="discard", send_to_shuffle=False),
        log_path=log_path,
        timestamp=FIXED_TS,
    )

    rows = _read_csv(Path(log_path))
    # DictReader consumes the header; we expect exactly 2 data rows.
    assert len(rows) == 2, f"Expected 2 data rows, got {len(rows)}"
    assert rows[0]["verdict"] == "TRUE_POSITIVE"
    assert rows[1]["verdict"] == "FALSE_POSITIVE"


def test_log_alert_header_has_all_expected_columns(tmp_path):
    """The CSV header must contain all 16 expected column names in fixed order."""
    log_path = str(tmp_path / "triage.csv")
    log_alert(_make_parsed(), log_path=log_path, timestamp=FIXED_TS)

    with open(log_path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)

    expected = [
        "timestamp",
        "alert_type",
        "nature_category",
        "rule_id",
        "rule_description",
        "verdict",
        "confidence",
        "risk_score",
        "mitre_id",
        "action",
        "send_to_shuffle",
        "status",
        "latency_ms",
        "model",
        "is_known_fp_candidate",
        "reason",
    ]
    assert header == expected


# ---------------------------------------------------------------------------
# 4. Creates parent directory if missing
# ---------------------------------------------------------------------------


def test_log_alert_creates_parent_directory(tmp_path):
    """log_alert must create the parent directory tree if it does not exist."""
    nested_path = str(tmp_path / "metrics" / "sub" / "triage.csv")
    assert not Path(nested_path).parent.exists()

    log_alert(_make_parsed(), log_path=nested_path, timestamp=FIXED_TS)

    assert Path(nested_path).exists(), "CSV file must be created"
    rows = _read_csv(Path(nested_path))
    assert len(rows) == 1


def test_log_alert_creates_metrics_dir(tmp_path):
    """log_alert must create the default metrics/ dir when it does not exist."""
    log_path = str(tmp_path / "metrics" / "triage_log.csv")
    assert not (tmp_path / "metrics").exists()

    log_alert(_make_parsed(), log_path=log_path, timestamp=FIXED_TS)

    assert (tmp_path / "metrics").is_dir()
    assert Path(log_path).exists()


# ---------------------------------------------------------------------------
# 5. mitre null → mitre_id empty; mitre dict → id extracted
# ---------------------------------------------------------------------------


def test_log_alert_mitre_null_gives_empty_mitre_id(tmp_path):
    """When mitre is null, mitre_id must be empty string."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed(mitre=None)
    log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert rows[0]["mitre_id"] == ""


def test_log_alert_mitre_dict_extracts_id(tmp_path):
    """When mitre is a dict, mitre_id must be the 'id' field value."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed(mitre={"id": "T1059", "name": "Command and Scripting Interpreter"})
    log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert rows[0]["mitre_id"] == "T1059"


def test_log_alert_mitre_dict_missing_id_gives_empty(tmp_path):
    """A mitre dict without an 'id' key must produce an empty mitre_id."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed(mitre={"name": "Some Technique"})
    log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert rows[0]["mitre_id"] == ""


# ---------------------------------------------------------------------------
# 6. fallback: reasoner_meta.status=="fallback" reflected in status column
# ---------------------------------------------------------------------------


def test_log_alert_fallback_status_reflected_in_status_column(tmp_path):
    """When reasoner_meta.status == 'fallback', the status column must be 'fallback'."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed(
        verdict="NEEDS_REVIEW",
        confidence="LOW",
        meta_status="fallback",
        fallback_reason="Ollama timeout",
        action="create_case",
        routing_reason="NEEDS_REVIEW. Fallback: Ollama timeout. Manual review required.",
    )
    log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    row = rows[0]
    assert row["status"] == "fallback"
    assert row["verdict"] == "NEEDS_REVIEW"
    # The router's reason string (which cites the fallback) must be persisted.
    assert "Ollama timeout" in row["reason"]


def test_log_alert_ok_status_reflected(tmp_path):
    """When reasoner_meta.status == 'ok', the status column must be 'ok'."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed(meta_status="ok")
    log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert rows[0]["status"] == "ok"


# ---------------------------------------------------------------------------
# 7. Defensive: malformed input → no raise, row with safe defaults
# ---------------------------------------------------------------------------


def test_log_alert_empty_dict_no_raise(tmp_path):
    """log_alert({}) must not raise; it writes a row with all-empty defaults."""
    log_path = str(tmp_path / "triage.csv")

    record = log_alert({}, log_path=log_path, timestamp=FIXED_TS)

    assert isinstance(record, dict), "Must return the record dict even for empty input"
    rows = _read_csv(Path(log_path))
    assert len(rows) == 1
    assert rows[0]["alert_type"] == ""
    assert rows[0]["verdict"] == ""
    assert rows[0]["action"] == ""
    assert rows[0]["mitre_id"] == ""
    assert rows[0]["timestamp"] == FIXED_TS


def test_log_alert_missing_verdict_no_raise(tmp_path):
    """Parsed dict without a 'verdict' key must not raise."""
    log_path = str(tmp_path / "triage.csv")
    parsed = {
        "alert_type": "ssh",
        "routing": {
            "action": "create_case",
            "send_to_shuffle": True,
            "reason": "defensive escalation",
        },
    }

    record = log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    assert record["verdict"] == ""
    assert record["action"] == "create_case"
    rows = _read_csv(Path(log_path))
    assert len(rows) == 1


def test_log_alert_missing_routing_no_raise(tmp_path):
    """Parsed dict without a 'routing' key must not raise; action/reason default to ''."""
    log_path = str(tmp_path / "triage.csv")
    parsed = {
        "alert_type": "windows_event",
        "verdict": {
            "verdict": "NEEDS_REVIEW",
            "confidence": "LOW",
            "risk_score": 5,
        },
    }

    record = log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    assert record["action"] == ""
    assert record["reason"] == ""
    assert record["verdict"] == "NEEDS_REVIEW"


def test_log_alert_verdict_not_a_dict_no_raise(tmp_path):
    """When 'verdict' is a non-dict, extraction must degrade gracefully."""
    log_path = str(tmp_path / "triage.csv")
    parsed = {
        "verdict": "NOT_A_DICT",
        "routing": {
            "action": "create_case",
            "send_to_shuffle": True,
            "reason": "test",
        },
    }

    record = log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    assert record["verdict"] == ""
    assert record["mitre_id"] == ""


def test_log_alert_routing_not_a_dict_no_raise(tmp_path):
    """When 'routing' is a non-dict, extraction must degrade gracefully."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed()
    parsed["routing"] = "some-string"

    record = log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    assert record["action"] == ""
    assert record["send_to_shuffle"] == ""


def test_log_alert_reasoner_meta_not_a_dict_no_raise(tmp_path):
    """When 'reasoner_meta' is a non-dict, extraction must degrade gracefully."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed()
    parsed["reasoner_meta"] = 42

    record = log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    assert record["status"] == ""
    assert record["model"] == ""


# ---------------------------------------------------------------------------
# 8. I/O error → no raise, returns the record regardless
# ---------------------------------------------------------------------------


def test_log_alert_io_error_no_raise(tmp_path):
    """If _write_row raises an I/O error, log_alert must not propagate it."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed()

    with patch("tools.logger._write_row", side_effect=OSError("disk full")):
        record = log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    assert isinstance(record, dict), "Must return the record even when write fails"
    assert record["verdict"] == "TRUE_POSITIVE"
    assert record["timestamp"] == FIXED_TS
    # File must NOT exist because _write_row was patched to fail before creating it.
    assert not Path(log_path).exists()


def test_log_alert_permission_error_no_raise(tmp_path):
    """A PermissionError during write must not propagate; record is returned."""
    log_path = str(tmp_path / "triage.csv")
    parsed = _make_parsed(verdict="NEEDS_REVIEW")

    with patch("tools.logger._write_row", side_effect=PermissionError("read-only")):
        record = log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    assert record["verdict"] == "NEEDS_REVIEW"


# ---------------------------------------------------------------------------
# 9. End-to-end with real fixtures: parse → reason (mocked) → route → log
# ---------------------------------------------------------------------------


def test_log_e2e_ssh_attack_true_positive(tmp_path):
    """Full chain: parse ssh_attack → reason (mocked TP) → route → log.

    Verifies that the CSV row accurately reflects all pipeline stages.
    """
    log_path = str(tmp_path / "metrics" / "triage_log.csv")

    tp_verdict = {
        "verdict": "TRUE_POSITIVE",
        "confidence": "HIGH",
        "justification": "SSH brute force confirmed.",
        "mitre": {"id": "T1110", "name": "Brute Force"},
        "next_action": "Block source IP.",
        "risk_score": 8,
    }

    parsed = parse_alert(load_fixture("ssh_attack.json"))
    parsed = reason(parsed, client=_make_ollama_client(tp_verdict))
    parsed = route(parsed)
    record = log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert len(rows) == 1
    row = rows[0]

    assert row["alert_type"] == "ssh"
    assert row["verdict"] == "TRUE_POSITIVE"
    assert row["confidence"] == "HIGH"
    assert row["mitre_id"] == "T1110"
    assert row["action"] == "create_case"
    assert row["send_to_shuffle"] == "True"
    assert row["risk_score"] == "8"
    assert row["status"] == "ok"
    assert record["timestamp"] == FIXED_TS


def test_log_e2e_windows_spp_false_positive_discarded(tmp_path):
    """Full chain: parse windows_spp_error → reason (mocked FP) → route → log.

    Verifies that the DISCARDED alert IS recorded — the core audit-trail
    requirement: no alert is ever silently dropped without a trace.
    """
    log_path = str(tmp_path / "audit.csv")

    fp_verdict = {
        "verdict": "FALSE_POSITIVE",
        "confidence": "HIGH",
        "justification": "Rule 60602 is a known benign SPP service event.",
        "mitre": None,
        "next_action": "No action required.",
        "risk_score": 1,
    }

    parsed = parse_alert(load_fixture("windows_spp_error.json"))
    parsed = reason(parsed, client=_make_ollama_client(fp_verdict))
    parsed = route(parsed)
    log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert len(rows) == 1
    row = rows[0]

    assert row["alert_type"] == "windows_event"
    assert row["verdict"] == "FALSE_POSITIVE"
    assert row["action"] == "discard"
    assert row["send_to_shuffle"] == "False"
    assert row["mitre_id"] == ""
    # Router audit reason must be persisted verbatim.
    assert "false positive" in row["reason"].lower()
    # Parser must have flagged this as a known FP candidate (rule 60602).
    assert row["is_known_fp_candidate"] == "True"


def test_log_e2e_firewall_needs_review_fallback(tmp_path):
    """Full chain: parse firewall_block → reason (mocked fallback) → route → log.

    Verifies that a NEEDS_REVIEW alert with fallback metadata is correctly
    recorded with status='fallback' and the reason includes fallback context.
    """
    log_path = str(tmp_path / "audit.csv")

    fallback_verdict = {
        "verdict": "NEEDS_REVIEW",
        "confidence": "LOW",
        "justification": "Automated analysis unavailable. Manual review required.",
        "mitre": None,
        "next_action": "Escalate to analyst.",
        "risk_score": 5,
    }

    # Simulate a fallback by making Ollama return the fallback verdict but
    # injecting it as a clean mock response (the reasoner will accept it and
    # mark status='ok'). Then manually set status to 'fallback' to test the
    # logger's handling of that path.
    parsed = parse_alert(load_fixture("firewall_block.json"))
    parsed = reason(parsed, client=_make_ollama_client(fallback_verdict))
    # Override to simulate a true fallback path
    parsed["reasoner_meta"]["status"] = "fallback"
    parsed["reasoner_meta"]["fallback_reason"] = "Ollama HTTP 503"
    parsed = route(parsed)
    log_alert(parsed, log_path=log_path, timestamp=FIXED_TS)

    rows = _read_csv(Path(log_path))
    assert len(rows) == 1
    row = rows[0]

    assert row["status"] == "fallback"
    assert row["verdict"] == "NEEDS_REVIEW"
    assert row["action"] == "create_case"
    assert "HTTP 503" in row["reason"] or "fallback" in row["reason"].lower()
