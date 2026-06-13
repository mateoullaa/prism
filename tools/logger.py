"""
logger.py — Audit and metrics logger for the AI triage pipeline.

Appends ONE CSV row per alert to the configured log file (LOG_PATH).
ALL alerts are recorded — including discarded FALSE_POSITIVEs — providing a
mandatory audit trail for Prism routing decisions.  Never raises: on any I/O
error the pipeline continues and the record is still returned to the caller.

Scope (v1): CSV append only.  No aggregation, rotation, or dashboard output
(those are v2 candidates).
"""

import csv
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Thread-safety: FastAPI may process concurrent requests against the same CSV
# file.  A module-level lock prevents interleaved or partially-written rows.
_write_lock = threading.Lock()

# Fixed column order — defines both the CSV header and the write order.
# Changing this list is a breaking schema change; treat it as a contract.
_COLUMNS: list[str] = [
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


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _build_record(parsed: dict, timestamp: str) -> dict:
    """Extract CSV columns from a (possibly malformed) parsed dict.

    All field access is defensive: isinstance checks + .get() with None-aware
    defaults, mirroring the style of router.py.  Never raises.

    Args:
        parsed: The fully mutated alert dict (parser → enricher → reasoner →
                router).  Sub-dicts ``verdict``, ``reasoner_meta``, and
                ``routing`` may be absent or malformed.
        timestamp: ISO-8601 UTC timestamp string to store in the row.

    Returns:
        An ordered dict whose keys match _COLUMNS exactly.
    """

    def _safe(val: Any) -> str:
        """Return str(val) unless val is None, in which case return ''."""
        return "" if val is None else str(val)

    # ------------------------------------------------------------------
    # Top-level fields — from parse_alert()
    # ------------------------------------------------------------------
    alert_type: str = _safe(parsed.get("alert_type"))
    nature_category: str = _safe(parsed.get("nature_category"))
    rule_id: str = _safe(parsed.get("rule_id"))
    rule_description: str = _safe(parsed.get("rule_description"))
    # is_known_fp_candidate is a bool; str(False)="False", str(True)="True"
    is_known_fp_str: str = _safe(parsed.get("is_known_fp_candidate"))

    # ------------------------------------------------------------------
    # Fields from parsed["verdict"] — written by reason()
    # ------------------------------------------------------------------
    raw_verdict: Any = parsed.get("verdict")
    verdict_dict: dict = raw_verdict if isinstance(raw_verdict, dict) else {}

    verdict_val: str = _safe(verdict_dict.get("verdict"))
    confidence: str = _safe(verdict_dict.get("confidence"))
    risk_score: str = _safe(verdict_dict.get("risk_score"))

    # mitre_id: extracted from a nested dict if mitre is not null.
    raw_mitre: Any = verdict_dict.get("mitre")
    mitre_id: str = _safe(raw_mitre.get("id")) if isinstance(raw_mitre, dict) else ""

    # ------------------------------------------------------------------
    # Fields from parsed["reasoner_meta"] — written by reason()
    # ------------------------------------------------------------------
    raw_meta: Any = parsed.get("reasoner_meta")
    meta_dict: dict = raw_meta if isinstance(raw_meta, dict) else {}

    status: str = _safe(meta_dict.get("status"))
    latency_ms: str = _safe(meta_dict.get("latency_ms"))
    model: str = _safe(meta_dict.get("model"))

    # ------------------------------------------------------------------
    # Fields from parsed["routing"] — written by route()
    # ------------------------------------------------------------------
    raw_routing: Any = parsed.get("routing")
    routing_dict: dict = raw_routing if isinstance(raw_routing, dict) else {}

    action: str = _safe(routing_dict.get("action"))
    # send_to_shuffle is a bool; must not be confused with missing (None)
    sts_raw: Any = routing_dict.get("send_to_shuffle")
    send_to_shuffle_str: str = _safe(sts_raw)
    reason: str = _safe(routing_dict.get("reason"))

    return {
        "timestamp": timestamp,
        "alert_type": alert_type,
        "nature_category": nature_category,
        "rule_id": rule_id,
        "rule_description": rule_description,
        "verdict": verdict_val,
        "confidence": confidence,
        "risk_score": risk_score,
        "mitre_id": mitre_id,
        "action": action,
        "send_to_shuffle": send_to_shuffle_str,
        "status": status,
        "latency_ms": latency_ms,
        "model": model,
        "is_known_fp_candidate": is_known_fp_str,
        "reason": reason,
    }


def _write_row(record: dict, log_path: str) -> None:
    """Append one record row to the CSV file at log_path.

    Creates the parent directory tree if it does not exist.  Writes the CSV
    header only when the file is new or empty.  All stat + write operations
    are performed inside the module-level lock to prevent concurrent writes
    from interleaving rows.

    Args:
        record: Ordered dict whose keys match _COLUMNS.
        log_path: Absolute or relative path to the CSV file.
    """
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with _write_lock:
        write_header = not path.exists() or path.stat().st_size == 0
        with open(path, mode="a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_COLUMNS)
            if write_header:
                writer.writeheader()
            writer.writerow(record)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def log_alert(
    parsed: dict,
    *,
    log_path: str | None = None,
    timestamp: str | None = None,
) -> dict:
    """Append one audit/metrics row to the CSV for the given alert.

    Records ALL alerts — including discarded FALSE_POSITIVEs — providing a
    mandatory audit trail for Prism's routing decisions.  Never raises: on any
    I/O error the exception is logged and the record is still returned so the
    pipeline continues uninterrupted.

    Args:
        parsed: The fully mutated alert dict produced by the pipeline
                (parse_alert → enrich → reason → route).  All sub-dicts
                (verdict, reasoner_meta, routing) may be absent or malformed;
                field extraction is fully defensive.
        log_path: Path to the CSV file.  Defaults to the ``LOG_PATH``
                  environment variable, falling back to
                  ``./metrics/triage_log.csv`` if the variable is unset.
                  Inject a ``tmp_path``-based value in tests to avoid
                  filesystem side effects.
        timestamp: ISO-8601 UTC timestamp string.  Defaults to
                   ``datetime.now(timezone.utc).isoformat()``.  Inject a
                   fixed string in tests for deterministic row assertions.

    Returns:
        The record dict that was (attempted to be) written.  Contains all
        _COLUMNS keys.  Callers can inspect it for immediate verification.
    """
    if log_path is None:
        log_path = os.getenv("LOG_PATH", "./metrics/triage_log.csv")

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    record = _build_record(parsed, timestamp)

    try:
        _write_row(record, log_path)
    except Exception as exc:  # noqa: BLE001 — intentional broad catch
        logger.error(
            "logger: failed to write CSV row to %r: %s",
            log_path,
            exc,
        )

    return record
