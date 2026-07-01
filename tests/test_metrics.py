"""
tests/test_metrics.py — Pytest suite for tools/metrics.py.

All tests are deterministic: metrics are computed from a known in-memory CSV
written to a tmp_path fixture, never from the real production log.
"""

import csv
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.metrics import compute_metrics, _empty  # noqa: E402

# ---------------------------------------------------------------------------
# Shared CSV fixture
# ---------------------------------------------------------------------------

_COLUMNS = [
    "timestamp", "alert_type", "nature_category", "rule_id", "rule_description",
    "verdict", "confidence", "risk_score", "mitre_id", "action", "send_to_shuffle",
    "status", "latency_ms", "model", "is_known_fp_candidate", "reason",
]


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_COLUMNS)
        writer.writeheader()
        for row in rows:
            full = {c: "" for c in _COLUMNS}
            full.update(row)
            writer.writerow(full)


def _row(**kw) -> dict:
    defaults = {
        "timestamp": "2026-06-23T02:24:06+00:00",
        "alert_type": "network",
        "nature_category": "public_attack",
        "rule_id": "651",
        "rule_description": "Host Blocked by firewall-drop",
        "verdict": "TRUE_POSITIVE",
        "confidence": "HIGH",
        "risk_score": "8",
        "status": "ok",
        "latency_ms": "20000",
        "model": "qwen2.5:3b",
    }
    defaults.update(kw)
    return defaults


# ---------------------------------------------------------------------------
# Missing / empty file
# ---------------------------------------------------------------------------


def test_missing_file_returns_empty(tmp_path):
    m = compute_metrics(str(tmp_path / "nonexistent.csv"))
    assert m == _empty()


def test_empty_file_returns_empty(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [])
    m = compute_metrics(str(p))
    assert m == _empty()


# ---------------------------------------------------------------------------
# Total and verdict counts
# ---------------------------------------------------------------------------


def test_total_and_verdict_counts(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [
        _row(verdict="TRUE_POSITIVE"),
        _row(verdict="TRUE_POSITIVE"),
        _row(verdict="FALSE_POSITIVE"),
        _row(verdict="NEEDS_REVIEW"),
    ])
    m = compute_metrics(str(p))
    assert m["total"] == 4
    assert m["verdicts"]["TRUE_POSITIVE"] == 2
    assert m["verdicts"]["FALSE_POSITIVE"] == 1
    assert m["verdicts"]["NEEDS_REVIEW"] == 1


def test_verdict_percentages(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [_row(verdict="TRUE_POSITIVE")] * 3 + [_row(verdict="FALSE_POSITIVE")])
    m = compute_metrics(str(p))
    assert m["verdict_pct"]["TRUE_POSITIVE"] == 75.0
    assert m["verdict_pct"]["FALSE_POSITIVE"] == 25.0
    assert m["verdict_pct"]["NEEDS_REVIEW"] == 0.0


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------


def test_avg_latency_ok_rows_only(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [
        _row(status="ok", latency_ms="10000"),
        _row(status="ok", latency_ms="20000"),
        _row(status="fallback", latency_ms="30000"),  # excluded from avg
    ])
    m = compute_metrics(str(p))
    assert m["avg_latency_ms"] == 15000
    assert m["avg_latency_s"] == 15.0


def test_avg_latency_zero_when_no_ok_rows(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [_row(status="fallback", latency_ms="30000")])
    m = compute_metrics(str(p))
    assert m["avg_latency_ms"] == 0


# ---------------------------------------------------------------------------
# Rates
# ---------------------------------------------------------------------------


def test_fallback_rate(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [_row(status="ok")] * 9 + [_row(status="fallback")])
    m = compute_metrics(str(p))
    assert m["fallback_rate_pct"] == 10.0


def test_auto_fp_rate(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [_row(status="ok")] * 4 + [_row(status="auto_fp")])
    m = compute_metrics(str(p))
    assert m["auto_fp_rate_pct"] == 20.0


# ---------------------------------------------------------------------------
# by_type and per_day
# ---------------------------------------------------------------------------


def test_by_type_counts(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [
        _row(alert_type="network"),
        _row(alert_type="network"),
        _row(alert_type="ssh"),
    ])
    m = compute_metrics(str(p))
    assert m["by_type"]["network"] == 2
    assert m["by_type"]["ssh"] == 1


def test_per_day_groups_by_date(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [
        _row(timestamp="2026-06-22T10:00:00+00:00"),
        _row(timestamp="2026-06-22T22:00:00+00:00"),
        _row(timestamp="2026-06-23T02:00:00+00:00"),
    ])
    m = compute_metrics(str(p))
    assert m["per_day"]["2026-06-22"] == 2
    assert m["per_day"]["2026-06-23"] == 1


def test_per_day_sorted_chronologically(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [
        _row(timestamp="2026-06-23T00:00:00+00:00"),
        _row(timestamp="2026-06-21T00:00:00+00:00"),
        _row(timestamp="2026-06-22T00:00:00+00:00"),
    ])
    m = compute_metrics(str(p))
    assert list(m["per_day"].keys()) == ["2026-06-21", "2026-06-22", "2026-06-23"]


# ---------------------------------------------------------------------------
# Date range and top rules
# ---------------------------------------------------------------------------


def test_date_range(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [
        _row(timestamp="2026-06-17T16:27:32+00:00"),
        _row(timestamp="2026-06-23T13:55:43+00:00"),
    ])
    m = compute_metrics(str(p))
    assert m["first_alert"] == "2026-06-17"
    assert m["last_alert"] == "2026-06-23"


def test_top_rules_sorted_by_count(tmp_path):
    p = tmp_path / "log.csv"
    _write_csv(p, [
        _row(rule_id="651", rule_description="Firewall block"),
        _row(rule_id="651", rule_description="Firewall block"),
        _row(rule_id="651", rule_description="Firewall block"),
        _row(rule_id="60602", rule_description="Windows SPP error"),
    ])
    m = compute_metrics(str(p))
    assert m["top_rules"][0]["rule_id"] == "651"
    assert m["top_rules"][0]["count"] == 3
    assert m["top_rules"][1]["rule_id"] == "60602"


def test_top_rules_max_10(tmp_path):
    p = tmp_path / "log.csv"
    rows = [_row(rule_id=str(i)) for i in range(15)]
    _write_csv(p, rows)
    m = compute_metrics(str(p))
    assert len(m["top_rules"]) <= 10
