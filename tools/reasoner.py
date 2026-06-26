"""
reasoner.py — LLM-based triage verdict for the AI triage pipeline.

Sends a structured prompt to a local Ollama instance and returns a validated
verdict conforming to the ARCHITECTURE.md contract.  All failure paths produce
a conservative NEEDS_REVIEW fallback; the pipeline never breaks.
"""

import json
import logging
import os
import sys
import time

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Valid enum values (contract)
# ---------------------------------------------------------------------------

_VALID_VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"}
_VALID_CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}

# Enrichment thresholds — evaluated in Python before the prompt is built so
# the model never has to do numeric comparisons itself.
_ABUSEIPDB_SCORE_THRESHOLD = 80
_ABUSEIPDB_REPORTS_THRESHOLD = 10
_VT_MALICIOUS_THRESHOLD = 5
# OTX pulses are curated; even one referencing pulse is a meaningful signal → HIGH RISK.
_OTX_PULSE_THRESHOLD = 1


# ---------------------------------------------------------------------------
# OllamaClient
# ---------------------------------------------------------------------------


class OllamaClient:
    """HTTP client for the Ollama /api/generate endpoint.

    All dependencies are injectable to enable deterministic unit tests.
    Never raises: every failure path returns a structured error dict.
    """

    def __init__(
        self,
        session: requests.Session,
        host: str,
        model: str,
        timeout: float,
    ) -> None:
        self._session = session
        self._host = host.rstrip("/")
        self._model = model
        self._timeout = timeout

    @property
    def model(self) -> str:
        """Name of the Ollama model this client targets."""
        return self._model

    def generate(self, prompt: str) -> dict:
        """Send a prompt to Ollama and return the raw response text.

        Args:
            prompt: The full prompt string to send.

        Returns:
            ``{"status": "ok", "response": "<text>"}`` on success, or
            ``{"status": "timeout", "message": "..."}`` on timeout, or
            ``{"status": "error", "message": "..."}`` on any other failure.
            Never raises.
        """
        url = f"{self._host}/api/generate"
        body = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        }
        try:
            resp = self._session.post(url, json=body, timeout=self._timeout)
            if resp.status_code != 200:
                logger.warning("Ollama returned HTTP %s", resp.status_code)
                return {"status": "error", "message": f"HTTP {resp.status_code}"}
            data = resp.json()
            return {"status": "ok", "response": data.get("response", "")}
        except requests.Timeout as exc:
            logger.warning("Ollama request timed out: %s", exc)
            return {"status": "timeout", "message": str(exc)}
        except Exception as exc:
            logger.warning("Ollama request failed: %s", exc)
            return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Default client factory
# ---------------------------------------------------------------------------


def _build_default_client() -> OllamaClient:
    """Build the production OllamaClient from environment variables.

    Reads OLLAMA_HOST, OLLAMA_MODEL, and OLLAMA_TIMEOUT from the environment
    (populated from .env via load_dotenv at module import time).
    """
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    timeout = float(os.getenv("OLLAMA_TIMEOUT", "30.0"))
    return OllamaClient(
        session=requests.Session(),
        host=host,
        model=model,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

# Static prefix: role, output schema, conservative bias rules, one example.
# Using concatenation (not .format) to avoid f-string injection from alert data
# that may contain braces in log lines or IOC values.
_PROMPT_PREFIX = """\
You are a SOC triage analyst. Analyze the following security alert and return a structured verdict.

OUTPUT SCHEMA (return ONLY this JSON, no other text):
{
  "verdict": "TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW",
  "confidence": "HIGH | MEDIUM | LOW",
  "justification": "<max 3 sentences explaining your reasoning>",
  "mitre": {"id": "TXXXX", "name": "technique name"} or null,
  "next_action": "<concrete action the analyst should take>",
  "risk_score": <integer 1-10>
}

CONSERVATIVE BIAS RULES (mandatory):
- If uncertain, return NEEDS_REVIEW.
- Return FALSE_POSITIVE ONLY with HIGH confidence and clear benign evidence.
- A missed true positive is worse than a reviewed false positive.
- When in doubt between TRUE_POSITIVE and NEEDS_REVIEW, choose NEEDS_REVIEW.
- FALSE_POSITIVE alerts should have risk_score 1-2. TRUE_POSITIVE critical attacks should be 8-10.

ENRICHMENT SIGNALS (thresholds pre-evaluated — trust these assessments):
- "threshold MET -> HIGH RISK": this provider confirmed the IP is malicious. Weight strongly toward TRUE_POSITIVE.
- "threshold NOT MET -> LOW RISK": no significant threat signal from this provider.
- Multiple providers showing HIGH RISK: return TRUE_POSITIVE with HIGH confidence.
- All providers showing LOW RISK: weight toward FALSE_POSITIVE or NEEDS_REVIEW based on other context.

MITRE ATT&CK MAPPING: use the pre-evaluated mapping from the alert data below.
If pre-evaluated as null, output "mitre": null. Never invent a technique.

EXAMPLE OF VALID OUTPUT:
{"verdict": "TRUE_POSITIVE", "confidence": "HIGH", "justification": "Alert characteristics match a known attack pattern. Source is an external IP with confirmed malicious reputation across multiple threat intelligence sources. No legitimate business use case identified for this traffic.", "mitre": {"id": "T1110", "name": "Brute Force"}, "next_action": "Block the source IP at the perimeter and escalate to tier-2 analyst for deeper investigation.", "risk_score": 8}

ALERT DATA:
"""

_PROMPT_SUFFIX = "\n\nRespond with ONLY the JSON object, no other text."


def build_prompt(parsed: dict) -> str:
    """Build the LLM prompt from a parsed (and optionally enriched) alert.

    Includes alert metadata, IOCs, enrichment summary (ok/cached entries only),
    type-specific context, and an FP-candidate hint when applicable.

    Args:
        parsed: Output of ``parse_alert()`` (optionally enriched).

    Returns:
        A complete prompt string ready to send to Ollama.
    """
    parts: list[str] = []

    # Core alert metadata
    parts.append(f"Alert type: {parsed.get('alert_type', 'unknown')}")
    parts.append(f"Nature category: {parsed.get('nature_category', 'unknown')}")
    parts.append(f"Rule ID: {parsed.get('rule_id', 'N/A')}")
    parts.append(f"Rule level: {parsed.get('rule_level', 'N/A')}")
    parts.append(f"Rule description: {parsed.get('rule_description', 'N/A')}")
    parts.append(f"Agent/host: {parsed.get('agent_name', 'N/A')}")

    # IOCs
    iocs: list[dict] = parsed.get("iocs", [])
    if iocs:
        ioc_lines = []
        for ioc in iocs:
            ext_label = "external" if ioc.get("external") else "internal"
            ioc_lines.append(
                f"  - {ioc.get('value')} (type={ioc.get('type')}, {ext_label})"
            )
        parts.append("IOCs:\n" + "\n".join(ioc_lines))
    else:
        parts.append("IOCs: none")

    # Enrichment — thresholds evaluated in Python; model receives conclusions, not raw numbers
    enrichment: dict = parsed.get("enrichment", {})
    enrichment_lines = _evaluate_enrichment(enrichment)
    if enrichment_lines:
        parts.append("Enrichment:\n" + "\n".join(enrichment_lines))
    else:
        parts.append("Enrichment: unavailable or not applicable")

    # Type-specific context
    alert_type: str = parsed.get("alert_type", "unknown") or "unknown"
    context: dict = parsed.get("context", {}) or {}
    context_lines = _format_context(alert_type, context)
    if context_lines:
        parts.append("Context:\n" + "\n".join(context_lines))

    # FP candidate hint for the dominant known-FP Windows SPP rules
    # (60602 single events / 61061 their aggregation — same root cause).
    if parsed.get("is_known_fp_candidate"):
        parts.append(
            "Note: This alert matches a known Windows Security-SPP service-error "
            "false positive (rule 60602, or its 61061 aggregation of multiple "
            "60602 events), which accounts for the largest share of corpus false "
            "positives. Consider FALSE_POSITIVE with HIGH confidence if no other "
            "suspicious indicators are present."
        )

    # MITRE technique — pre-evaluated in Python (same principle as enrichment thresholds)
    mitre_hint = _evaluate_mitre(parsed)
    if mitre_hint:
        parts.append(
            f"MITRE mapping (pre-evaluated): {mitre_hint['id']} {mitre_hint['name']}"
            " — include this in your output as-is."
        )
    else:
        parts.append('MITRE mapping (pre-evaluated): null — output "mitre": null.')

    alert_data = "\n".join(parts)
    return _PROMPT_PREFIX + alert_data + _PROMPT_SUFFIX


def _evaluate_enrichment(enrichment: dict) -> list[str]:
    """Evaluate enrichment thresholds in Python and return pre-labelled lines.

    Each line states the raw values AND the pre-computed risk label so the LLM
    never has to do numeric comparisons itself.  Only ok/cached entries are
    included; error/rate_limited/skipped entries are silently dropped to avoid
    misleading the model with absent data.
    """
    lines: list[str] = []
    for ip, providers in enrichment.items():
        if not isinstance(providers, dict):
            continue
        for provider, data in providers.items():
            if not isinstance(data, dict):
                continue
            if data.get("status") not in ("ok", "cached"):
                continue
            if provider == "abuseipdb":
                score = int(data.get("abuse_confidence_score") or 0)
                reports = int(data.get("total_reports") or 0)
                met = score >= _ABUSEIPDB_SCORE_THRESHOLD and reports >= _ABUSEIPDB_REPORTS_THRESHOLD
                label = "threshold MET -> HIGH RISK" if met else "threshold NOT MET -> LOW RISK"
                lines.append(
                    f"  - {ip} [AbuseIPDB]: abuse_confidence_score={score}, "
                    f"reports={reports} — {label}"
                )
            elif provider == "virustotal":
                malicious = int(data.get("malicious") or 0)
                suspicious = int(data.get("suspicious") or 0)
                met = malicious >= _VT_MALICIOUS_THRESHOLD
                label = "threshold MET -> HIGH RISK" if met else "threshold NOT MET -> LOW RISK"
                lines.append(
                    f"  - {ip} [VirusTotal]: malicious={malicious}, "
                    f"suspicious={suspicious} — {label}"
                )
            elif provider == "otx":
                pulses = int(data.get("pulse_count") or 0)
                reputation = int(data.get("reputation") or 0)
                met = pulses >= _OTX_PULSE_THRESHOLD
                label = "threshold MET -> HIGH RISK" if met else "threshold NOT MET -> LOW RISK"
                lines.append(
                    f"  - {ip} [OTX]: pulses={pulses}, "
                    f"reputation={reputation} — {label}"
                )
    return lines


_MITRE_MAP: dict[str, dict] = {
    "ssh": {"id": "T1110", "name": "Brute Force"},
    "network": {"id": "T1595", "name": "Active Scanning"},
    "vulnerability": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "virustotal": {"id": "T1204", "name": "User Execution"},
    "windows_event": {"id": "T1078", "name": "Valid Accounts"},
}


def _evaluate_mitre(parsed: dict) -> dict | None:
    """Return the pre-evaluated MITRE ATT&CK technique for this alert, or None.

    Maps ``alert_type`` to a technique using a deterministic lookup table so the
    LLM never has to do the mapping itself (same design principle as enrichment
    threshold evaluation).

    Returns None for known-FP candidates: they have no TTP to map.
    """
    if parsed.get("is_known_fp_candidate"):
        return None
    return _MITRE_MAP.get(parsed.get("alert_type") or "")


def _format_context(alert_type: str, context: dict) -> list[str]:
    """Return type-specific context lines formatted for the prompt.

    Full log lines are truncated to ~500 chars to keep prompt size bounded
    on CPU inference.
    """
    lines: list[str] = []
    if not context:
        return lines

    if alert_type == "ssh":
        if context.get("firedtimes") is not None:
            lines.append(f"  - Fired times: {context['firedtimes']}")
        if context.get("country"):
            lines.append(f"  - Source country: {context['country']}")
        full_log = context.get("full_log")
        if full_log:
            truncated = str(full_log)[:500]
            lines.append(f"  - Log sample: {truncated}")

    elif alert_type == "network":
        if context.get("country"):
            lines.append(f"  - Source country: {context['country']}")
        if context.get("rule_description"):
            lines.append(f"  - Original rule: {context['rule_description']}")

    elif alert_type == "vulnerability":
        if context.get("severity"):
            lines.append(f"  - Severity: {context['severity']}")
        if context.get("cvss_base") is not None:
            lines.append(f"  - CVSS base score: {context['cvss_base']}")
        if context.get("package"):
            lines.append(f"  - Affected package: {context['package']}")
        if context.get("rationale"):
            lines.append(f"  - Rationale: {str(context['rationale'])[:500]}")

    elif alert_type == "virustotal":
        if context.get("malicious") is not None:
            lines.append(f"  - VT malicious detections: {context['malicious']}")
        if context.get("found") is not None:
            lines.append(f"  - VT found: {context['found']}")
        if context.get("file"):
            lines.append(f"  - File: {context['file']}")

    elif alert_type == "windows_event":
        if context.get("event_id"):
            lines.append(f"  - Event ID: {context['event_id']}")
        if context.get("computer"):
            lines.append(f"  - Computer: {context['computer']}")

    else:
        # Generic fallback for unknown or future alert types
        for k, v in context.items():
            if v is not None:
                lines.append(f"  - {k}: {str(v)[:500]}")

    return lines


# ---------------------------------------------------------------------------
# JSON parsing and validation
# ---------------------------------------------------------------------------


def _parse_llm_json(text: str) -> dict | None:
    """Attempt to parse a JSON object from raw LLM response text.

    Strategy:
    1. Direct ``json.loads`` on the full text.
    2. Defensive extraction: substring from the first ``{`` to the last ``}``.

    This covers both clean JSON output and responses with a preamble/postamble
    (e.g. "Here is my analysis: {...}").

    Args:
        text: Raw text returned by the LLM.

    Returns:
        Parsed dict, or ``None`` if no valid JSON object can be extracted.
    """
    if not isinstance(text, str):
        return None

    # Attempt 1: direct parse
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass

    # Attempt 2: extract from first '{' to last '}'
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            obj = json.loads(text[start : end + 1])
            if isinstance(obj, dict):
                return obj
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def _validate_verdict(obj: dict) -> dict | None:
    """Normalize and validate a parsed LLM response against the verdict contract.

    Normalization rules:
    - ``verdict`` and ``confidence`` are upper-cased before enum membership check.
    - ``risk_score`` is coerced to ``int`` via ``float`` conversion and clamped 1–10.
    - ``mitre`` with an unexpected shape is silently normalized to ``None`` without
      invalidating the whole verdict.

    Args:
        obj: Parsed dict from the LLM response.

    Returns:
        Normalized verdict dict conforming to the ARCHITECTURE.md contract, or
        ``None`` if any required field is absent or carries an invalid value.
    """
    if not isinstance(obj, dict):
        return None

    # Normalize and validate verdict enum
    verdict = str(obj.get("verdict", "")).upper()
    if verdict not in _VALID_VERDICTS:
        logger.debug("Invalid verdict value: %r", obj.get("verdict"))
        return None

    # Normalize and validate confidence enum
    confidence = str(obj.get("confidence", "")).upper()
    if confidence not in _VALID_CONFIDENCES:
        logger.debug("Invalid confidence value: %r", obj.get("confidence"))
        return None

    # Coerce and clamp risk_score.
    # Special case: NEEDS_REVIEW with a missing/None risk_score gets a safe default of
    # 5 rather than a fatal rejection.  For TRUE_POSITIVE and FALSE_POSITIVE a missing
    # score is still fatal — those verdicts carry calibration-significant scores (8-10
    # and 1-2 respectively) and we prefer an explicit fallback to an invented number.
    raw_score = obj.get("risk_score")
    if raw_score is None and verdict == "NEEDS_REVIEW":
        risk_score = 5
        logger.info(
            "risk_score absent for NEEDS_REVIEW verdict; defaulting to 5"
        )
    else:
        try:
            risk_score = max(1, min(10, int(float(str(raw_score)))))
        except (TypeError, ValueError):
            logger.debug("Invalid risk_score: %r", raw_score)
            return None

    # Enforce verdict-appropriate range deterministically.  Even at temperature=0,
    # CPU inference (BLAS float ops) is not perfectly reproducible across runs, so
    # a 3b model may drift between 1 and 2 for FALSE_POSITIVE or between 7 and 8
    # for TRUE_POSITIVE.  Python makes the final call: FP is always 1; TP is [8,10].
    if verdict == "FALSE_POSITIVE":
        risk_score = 1
    elif verdict == "TRUE_POSITIVE":
        risk_score = max(8, min(10, risk_score))

    # Validate justification (non-empty string)
    justification = obj.get("justification", "")
    if not isinstance(justification, str) or not justification.strip():
        logger.debug("Missing or empty justification")
        return None

    # Validate next_action (non-empty string)
    next_action = obj.get("next_action", "")
    if not isinstance(next_action, str) or not next_action.strip():
        logger.debug("Missing or empty next_action")
        return None

    # Normalize mitre: any malformed value becomes None (does not invalidate verdict)
    mitre = obj.get("mitre")
    if mitre is not None:
        if not (
            isinstance(mitre, dict)
            and isinstance(mitre.get("id"), str)
            and isinstance(mitre.get("name"), str)
        ):
            mitre = None

    return {
        "verdict": verdict,
        "confidence": confidence,
        "justification": justification,
        "mitre": mitre,
        "next_action": next_action,
        "risk_score": risk_score,
    }


# ---------------------------------------------------------------------------
# Fallback verdict
# ---------------------------------------------------------------------------


def fallback_verdict(reason: str) -> dict:
    """Return a conservative NEEDS_REVIEW fallback verdict.

    Used when the LLM call fails, times out, or returns an invalid response.
    Risk score defaults to 5 (mid-range) to trigger case creation in the router.

    Args:
        reason: Human-readable explanation for why automated analysis failed.

    Returns:
        Verdict dict conforming to the ARCHITECTURE.md contract.
    """
    return {
        "verdict": "NEEDS_REVIEW",
        "confidence": "LOW",
        "justification": (
            f"Automated analysis unavailable: {reason}. Manual review required."
        ),
        "mitre": None,
        "next_action": "Escalate to analyst for manual triage",
        "risk_score": 5,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def reason(parsed: dict, *, client: OllamaClient | None = None) -> dict:
    """Run LLM-based triage on a parsed (optionally enriched) alert.

    Adds ``parsed["verdict"]`` and ``parsed["reasoner_meta"]`` in-place and
    returns the mutated dict.  All failure paths produce a conservative
    NEEDS_REVIEW fallback; never raises, even on an empty or malformed input.

    Failure paths that trigger fallback:
    - ``build_prompt`` raises (malformed input)
    - Ollama request times out
    - Ollama connection error or non-200 HTTP response
    - LLM returns non-JSON or JSON that violates the contract

    Code-level FP guardrail (independent of the prompt):
    - If ``verdict == FALSE_POSITIVE`` and ``confidence != HIGH``, the verdict
      is forced to NEEDS_REVIEW and the downgrade is recorded in
      ``reasoner_meta["downgrade_note"]``.

    Args:
        parsed: Output of ``parse_alert()`` (optionally enriched).
        client: Optional injectable ``OllamaClient`` for tests.  When ``None``,
                a client is built from environment variables.

    Returns:
        The same ``parsed`` dict with ``"verdict"`` and ``"reasoner_meta"`` added.
    """
    if client is None:
        client = _build_default_client()

    model: str = client.model
    downgrade_note: str | None = None

    # Build prompt (can fail on completely unexpected input shapes)
    t_start = time.monotonic()
    try:
        prompt = build_prompt(parsed)
    except Exception as exc:
        logger.error("build_prompt raised an exception: %s", exc)
        reason_str = f"prompt build error: {exc}"
        parsed["verdict"] = fallback_verdict(reason_str)
        parsed["reasoner_meta"] = {
            "status": "fallback",
            "fallback_reason": reason_str,
            "model": model,
            "latency_ms": int((time.monotonic() - t_start) * 1000),
        }
        return parsed

    # Call Ollama
    llm_result = client.generate(prompt)
    latency_ms = int((time.monotonic() - t_start) * 1000)

    # Handle timeout
    if llm_result.get("status") == "timeout":
        reason_str = "Ollama timeout: request exceeded the configured timeout"
        parsed["verdict"] = fallback_verdict(reason_str)
        parsed["reasoner_meta"] = {
            "status": "fallback",
            "fallback_reason": reason_str,
            "model": model,
            "latency_ms": latency_ms,
        }
        return parsed

    # Handle connection/HTTP errors
    if llm_result.get("status") == "error":
        reason_str = f"Ollama error: {llm_result.get('message', 'unknown')}"
        parsed["verdict"] = fallback_verdict(reason_str)
        parsed["reasoner_meta"] = {
            "status": "fallback",
            "fallback_reason": reason_str,
            "model": model,
            "latency_ms": latency_ms,
        }
        return parsed

    # Parse JSON from LLM response
    raw_text: str = llm_result.get("response", "")
    obj = _parse_llm_json(raw_text)
    if obj is None:
        reason_str = "LLM returned non-JSON response"
        parsed["verdict"] = fallback_verdict(reason_str)
        parsed["reasoner_meta"] = {
            "status": "fallback",
            "fallback_reason": reason_str,
            "model": model,
            "latency_ms": latency_ms,
        }
        return parsed

    # Validate and normalize against the contract
    verdict_dict = _validate_verdict(obj)
    if verdict_dict is None:
        reason_str = "LLM response failed contract validation"
        # Preserve the LLM output before it is discarded: in production this is
        # the only record of what the model actually returned when it broke the
        # contract. _validate_verdict() emits a DEBUG line naming the offending
        # field; these WARNINGs capture the full payload alongside it.
        logger.warning("Contract validation failed; raw LLM response: %r", raw_text)
        logger.warning("Contract validation failed; parsed-but-invalid object: %r", obj)
        parsed["verdict"] = fallback_verdict(reason_str)
        parsed["reasoner_meta"] = {
            "status": "fallback",
            "fallback_reason": reason_str,
            "model": model,
            "latency_ms": latency_ms,
        }
        return parsed

    # Code-level FP guardrail — conservative bias cannot rely on a 3b model
    # obeying the prompt alone.
    if verdict_dict["verdict"] == "FALSE_POSITIVE" and verdict_dict["confidence"] != "HIGH":
        downgrade_note = (
            f"FP guardrail: verdict downgraded from FALSE_POSITIVE "
            f"(confidence={verdict_dict['confidence']}) to NEEDS_REVIEW"
        )
        logger.info(downgrade_note)
        verdict_dict["verdict"] = "NEEDS_REVIEW"
        # Risk score was forced to 1 by FP enforcement in _validate_verdict();
        # reset to the NEEDS_REVIEW appropriate default now that the verdict changed.
        verdict_dict["risk_score"] = 5

    parsed["verdict"] = verdict_dict
    meta: dict = {
        "status": "ok",
        "fallback_reason": None,
        "model": model,
        "latency_ms": latency_ms,
    }
    if downgrade_note:
        meta["downgrade_note"] = downgrade_note
    parsed["reasoner_meta"] = meta

    return parsed


# ---------------------------------------------------------------------------
# Manual runner — iterate prompt against real Ollama fixtures
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from pathlib import Path as _Path

    # Surface the module loggers (incl. the contract-validation WARNINGs above
    # and the field-level DEBUG lines in _validate_verdict) for manual runs.
    logging.basicConfig(
        level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s"
    )

    _repo_root = _Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(_repo_root))

    from tools.parser import parse_alert  # noqa: E402 (local import for runner only)

    if len(sys.argv) < 2:
        print("Usage: python tools/reasoner.py <fixture_path>")
        sys.exit(1)

    _fixture_path = _Path(sys.argv[1])
    with _fixture_path.open(encoding="utf-8") as _f:
        _raw = json.load(_f)

    _parsed = parse_alert(_raw)
    _prompt = build_prompt(_parsed)

    print("=== PROMPT ===")
    print(_prompt)
    print()

    _result = reason(_parsed)

    print("=== VERDICT ===")
    print(json.dumps(_result.get("verdict"), indent=2))
    print()
    print("=== META ===")
    print(json.dumps(_result.get("reasoner_meta"), indent=2))
