"""
metrics.py — compute dashboard statistics from the triage audit log CSV.

Pure functions; reads the triage_log.csv written by tools/logger.py and returns
structured dicts suitable for the /metrics JSON endpoint and the /dashboard HTML
view.  Never raises: on any error (missing file, corrupt CSV) returns a zero-filled
empty dict so the dashboard renders gracefully.
"""

import csv
import logging
import os
from collections import Counter, defaultdict
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_VERDICTS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW")
_STATUSES = ("ok", "fallback", "auto_fp")
_CONFIDENCES = ("HIGH", "MEDIUM", "LOW")


def compute_metrics(log_path: str | None = None) -> dict:
    """Read the triage audit log and return structured statistics.

    Args:
        log_path: Path to the CSV file.  Defaults to the ``LOG_PATH`` env var
                  (itself defaulting to ``./metrics/triage_log.csv``).

    Returns:
        Stats dict with keys: total, first_alert, last_alert, verdicts,
        verdict_pct, by_type, by_status, by_confidence, avg_latency_ms,
        avg_latency_s, fallback_rate_pct, auto_fp_rate_pct, per_day, top_rules.
        Returns an all-zero dict on any error.
    """
    if log_path is None:
        log_path = os.getenv("LOG_PATH", "./metrics/triage_log.csv")
    try:
        return _compute(Path(log_path))
    except Exception as exc:  # noqa: BLE001 — fail-safe by design
        logger.warning("compute_metrics failed: %s", exc)
        return _empty()


def _compute(path: Path) -> dict:
    if not path.is_file():
        return _empty()

    rows: list[dict] = []
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    if not rows:
        return _empty()

    total = len(rows)

    verdict_counts = Counter(r.get("verdict", "") for r in rows)
    type_counts = Counter(r.get("alert_type", "unknown") for r in rows)
    status_counts = Counter(r.get("status", "") for r in rows)
    confidence_counts = Counter(r.get("confidence", "") for r in rows)

    # Average latency — only include LLM-processed rows (status==ok)
    ok_latencies: list[int] = []
    for r in rows:
        if r.get("status") == "ok":
            try:
                ok_latencies.append(int(r["latency_ms"]))
            except (KeyError, ValueError, TypeError):
                pass
    avg_ms = int(sum(ok_latencies) / len(ok_latencies)) if ok_latencies else 0

    # Alerts per calendar day (UTC date prefix of ISO timestamp)
    per_day: dict[str, int] = defaultdict(int)
    for r in rows:
        ts = r.get("timestamp", "")
        if ts and len(ts) >= 10:
            per_day[ts[:10]] += 1
    per_day_sorted = dict(sorted(per_day.items()))

    # Top 10 rules by alert volume
    rule_count: Counter = Counter()
    rule_desc: dict[str, str] = {}
    for r in rows:
        rid = (r.get("rule_id") or "").strip()
        if rid:
            rule_count[rid] += 1
            rule_desc.setdefault(rid, (r.get("rule_description") or "").strip())
    top_rules = [
        {"rule_id": rid, "description": rule_desc[rid], "count": cnt}
        for rid, cnt in rule_count.most_common(10)
    ]

    timestamps = [r["timestamp"] for r in rows if r.get("timestamp")]

    def _pct(n: int) -> float:
        return round(n / total * 100, 1) if total else 0.0

    return {
        "total": total,
        "first_alert": min(timestamps)[:10] if timestamps else "",
        "last_alert": max(timestamps)[:10] if timestamps else "",
        "verdicts": {v: verdict_counts.get(v, 0) for v in _VERDICTS},
        "verdict_pct": {v: _pct(verdict_counts.get(v, 0)) for v in _VERDICTS},
        "by_type": dict(type_counts.most_common()),
        "by_status": {s: status_counts.get(s, 0) for s in _STATUSES},
        "by_confidence": {c: confidence_counts.get(c, 0) for c in _CONFIDENCES},
        "avg_latency_ms": avg_ms,
        "avg_latency_s": round(avg_ms / 1000, 1),
        "fallback_rate_pct": _pct(status_counts.get("fallback", 0)),
        "auto_fp_rate_pct": _pct(status_counts.get("auto_fp", 0)),
        "per_day": per_day_sorted,
        "top_rules": top_rules,
    }


def _empty() -> dict:
    return {
        "total": 0,
        "first_alert": "",
        "last_alert": "",
        "verdicts": {v: 0 for v in _VERDICTS},
        "verdict_pct": {v: 0.0 for v in _VERDICTS},
        "by_type": {},
        "by_status": {s: 0 for s in _STATUSES},
        "by_confidence": {c: 0 for c in _CONFIDENCES},
        "avg_latency_ms": 0,
        "avg_latency_s": 0.0,
        "fallback_rate_pct": 0.0,
        "auto_fp_rate_pct": 0.0,
        "per_day": {},
        "top_rules": [],
    }
