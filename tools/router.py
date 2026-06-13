"""
router.py — Routing decision for the AI triage pipeline.

Consumes the structured verdict produced by reasoner.py and decides whether the
alert warrants a case (create_case → Shuffle) or can be discarded.  The decision
is audit-driven and conservative: on any doubt, the alert is escalated.

Decision rules (from ARCHITECTURE.md):
  1. FALSE_POSITIVE  → discard (only when verdict is explicitly FALSE_POSITIVE).
  2. TRUE_POSITIVE | NEEDS_REVIEW → create_case.
  3. Missing / malformed verdict → create_case (defensive escalation).

When reasoner_meta.status == "fallback" the routing reason notes that automated
analysis fell back, so the created case carries that context for the analyst.
When a "downgrade_note" is present it is also included in the reason.

Scope (v1): the router ONLY annotates parsed["routing"].  It does NOT create
TheHive cases, does NOT call Shuffle, and does NOT write logs or CSV
(that is logger.py).  No network, no I/O.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Valid verdict enum values — mirrors the reasoner contract.
# Defined locally to avoid a circular import with reasoner.py.
_VALID_VERDICTS: frozenset[str] = frozenset(
    {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"}
)


def route(parsed: dict) -> dict:
    """Add a routing decision to a parsed+reasoned alert dict, in-place.

    Reads ``parsed["verdict"]`` and ``parsed["reasoner_meta"]`` (both written
    by ``reason()``) and sets ``parsed["routing"]`` according to the rules in
    ARCHITECTURE.md.  Never raises, even on an empty or completely malformed
    input — the conservative default is always to create the case.

    Args:
        parsed: Dict produced by ``parse_alert()`` and mutated by ``reason()``.
                Must contain ``"verdict"`` (dict) and ``"reasoner_meta"`` (dict).
                Missing or malformed values trigger the defensive escalation path.

    Returns:
        The same ``parsed`` dict with ``"routing"`` added::

            {
                "action": "create_case" | "discard",
                "send_to_shuffle": bool,   # True iff action == "create_case"
                "reason": str,             # human-readable audit reason
            }
    """
    verdict_dict: Any = parsed.get("verdict")

    # Normalise reasoner_meta: must be a dict; fall back to {} if absent/wrong type.
    raw_meta: Any = parsed.get("reasoner_meta")
    meta_dict: dict = raw_meta if isinstance(raw_meta, dict) else {}

    # ------------------------------------------------------------------
    # Defensive validation — verdict must be a dict with a known string.
    # ------------------------------------------------------------------
    if not isinstance(verdict_dict, dict):
        reason_str = (
            "Defensive escalation: 'verdict' key is absent or not a dict "
            f"(got {type(verdict_dict).__name__!r}). "
            "Escalating to avoid missing a real threat."
        )
        logger.warning("router: defensive escalation — %s", reason_str)
        parsed["routing"] = {
            "action": "create_case",
            "send_to_shuffle": True,
            "reason": reason_str,
        }
        return parsed

    verdict_value: Any = verdict_dict.get("verdict", "")
    if not isinstance(verdict_value, str) or verdict_value not in _VALID_VERDICTS:
        reason_str = (
            f"Defensive escalation: unrecognized verdict value {verdict_value!r}. "
            "Escalating to avoid missing a real threat."
        )
        logger.warning("router: defensive escalation — %s", reason_str)
        parsed["routing"] = {
            "action": "create_case",
            "send_to_shuffle": True,
            "reason": reason_str,
        }
        return parsed

    # At this point verdict_value is one of the three valid enum members.
    confidence: str = str(verdict_dict.get("confidence", "UNKNOWN"))
    meta_status: str = str(meta_dict.get("status", "unknown"))
    downgrade_note: Any = meta_dict.get("downgrade_note")

    # ------------------------------------------------------------------
    # Rule 1: FALSE_POSITIVE → discard
    # ------------------------------------------------------------------
    if verdict_value == "FALSE_POSITIVE":
        reason_str = (
            f"Confirmed false positive (confidence={confidence}). "
            "Alert discarded — no case created."
        )
        logger.info("router: discarding alert — %s", reason_str)
        parsed["routing"] = {
            "action": "discard",
            "send_to_shuffle": False,
            "reason": reason_str,
        }
        return parsed

    # ------------------------------------------------------------------
    # Rule 2: TRUE_POSITIVE | NEEDS_REVIEW → create_case
    # ------------------------------------------------------------------
    reason_parts: list[str] = [
        f"Verdict is {verdict_value} (confidence={confidence}). "
        "Case created for analyst review."
    ]

    if meta_status == "fallback":
        fallback_reason: str = meta_dict.get("fallback_reason") or "unknown reason"
        reason_parts.append(
            f"Note: automated LLM analysis fell back to conservative defaults "
            f"({fallback_reason}). Manual review is essential."
        )

    if downgrade_note:
        reason_parts.append(f"Downgrade context: {downgrade_note}")

    reason_str = " ".join(reason_parts)
    logger.info("router: creating case — %s", reason_str)
    parsed["routing"] = {
        "action": "create_case",
        "send_to_shuffle": True,
        "reason": reason_str,
    }
    return parsed
