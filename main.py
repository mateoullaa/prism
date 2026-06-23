"""
main.py — FastAPI service orchestrating the Wazuh AI triage pipeline.

Exposes two endpoints:
  - POST /analyze : receives a Wazuh alert JSON object, runs the full triage
    pipeline (parse → enrich → reason → route → log), and returns the complete
    parsed dict as the response body.  The caller (Shuffle) reads
    ``routing.send_to_shuffle`` to decide what to do next.  This service does
    NOT make outbound calls to Shuffle (that is item 7, out of scope).
  - GET  /health  : readiness probe → {"status": "ok"}.

Design decisions:
  - Sync endpoint (def, not async def): FastAPI runs it in a thread pool so
    blocking calls to VirusTotal, AbuseIPDB, and Ollama don't stall the event
    loop, and concurrent requests execute in separate threads.
  - Module-level singletons: enricher clients (RateLimiter + TTLCache) and the
    OllamaClient are built ONCE at startup.  This preserves the rate-limit token
    bucket and the TTL cache across requests — essential given VirusTotal's
    ~4 req/min free-tier limit.
  - Dependency injection via FastAPI Depends: tests override get_pipeline() with
    mock clients without patching module globals.
  - Last-resort robustness: the orchestration is wrapped in a try/except.  On
    any unexpected error the endpoint still returns HTTP 200 with a conservative
    create_case body so no alert is ever lost.  HTTP 500 is never returned.
"""

import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import Body, Depends, FastAPI

# ---------------------------------------------------------------------------
# Bootstrap: env vars + logging
# ---------------------------------------------------------------------------

load_dotenv()
logging.basicConfig(level=logging.INFO)

_logger = logging.getLogger(__name__)

# Ensure repo root is importable as a package prefix when running directly.
_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ---------------------------------------------------------------------------
# Tool imports (after sys.path is set)
# ---------------------------------------------------------------------------

import tools.enricher as _enricher_module  # noqa: E402
import tools.reasoner as _reasoner_module  # noqa: E402
from tools.enricher import enrich  # noqa: E402
from tools.logger import log_alert  # noqa: E402
from tools.parser import parse_alert  # noqa: E402
from tools.reasoner import reason  # noqa: E402
from tools.router import route  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level singletons (built ONCE; shared across all requests)
#
# _ENRICHER_CLIENTS — (VirusTotalClient, AbuseIPDBClient, OTXClient) sharing one
#   requests.Session, one RateLimiter per provider, and one TTLCache.
#   Singletons ensure the token bucket and cache state survive across requests.
#
# _OLLAMA_CLIENT — OllamaClient wrapping a persistent requests.Session.
#   Both are thread-safe (internal locks in RateLimiter/TTLCache/logger).
# ---------------------------------------------------------------------------

_ENRICHER_CLIENTS = _enricher_module._build_default_clients()
_OLLAMA_CLIENT = _reasoner_module._build_default_client()


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


def get_pipeline() -> dict:
    """Return the shared pipeline clients as an injectable dependency dict.

    Override in tests via ``app.dependency_overrides[get_pipeline]`` to inject
    mock clients without touching module globals or real network services.

    Returns:
        Dict with keys ``"enricher_clients"`` and ``"ollama_client"``.
    """
    return {
        "enricher_clients": _ENRICHER_CLIENTS,
        "ollama_client": _OLLAMA_CLIENT,
    }


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Prism Triage Agent",
    description=(
        "SOC triage service: receives Wazuh alerts, classifies them, enriches "
        "IOCs, and uses a local LLM to produce a structured verdict."
    ),
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict:
    """Readiness probe for Shuffle and infrastructure monitoring.

    Returns:
        ``{"status": "ok"}`` always.
    """
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Observable builder (orchestration helper — not a tool, not an endpoint)
# ---------------------------------------------------------------------------

_OK_STATUSES: frozenset[str] = frozenset({"ok", "cached"})


def _build_observables(parsed: dict) -> list:
    """Build enriched observable metadata for each IOC in *parsed*.

    Iterates ``parsed["iocs"]`` and, for each entry, produces a structured
    dict with verdict, confidence, provider sources, and human-readable
    reasons derived from the enrichment data already stored in
    ``parsed["enrichment"]``.

    Signal thresholds (identical to those used by tools/reasoner.py):
      - VirusTotal: malicious >= 5 → strong signal
      - AbuseIPDB : abuse_confidence_score >= 80 AND total_reports >= 10 → strong
      - OTX       : pulse_count >= 1 → strong

    Confidence mapping:
      - 2+ strong signals → "malicious", confidence 95
      - 1  strong signal  → "malicious", confidence 75
      - weak signal only  → "suspicious", confidence 40
      - no signal         → "unknown",  confidence 0

    Args:
        parsed: The fully populated pipeline dict produced by parse_alert,
                enrich, reason, and route.  Must contain ``"iocs"`` (list)
                and ``"enrichment"`` (dict) keys; missing keys are handled
                gracefully.

    Returns:
        List of observable dicts, one per IOC.  Never raises; malformed IOCs
        produce a safe fallback entry with ``verdict="unknown"``.
    """
    observables: list = []
    iocs: list = parsed.get("iocs", [])
    enrichment: dict = parsed.get("enrichment", {})

    for ioc in iocs:
        try:
            value: str = ioc.get("value", "")
            ioc_type: str = ioc.get("type", "unknown")
            is_public: bool = ioc.get("external", False)

            ioc_enrichment: dict | None = enrichment.get(value)

            if ioc_enrichment is None:
                # No enrichment entry: hash, CVE, domain not yet supported, etc.
                observables.append(
                    {
                        "type": ioc_type,
                        "value": value,
                        "is_public": is_public,
                        "verdict": "unknown",
                        "sources": {},
                        "confidence": 0,
                        "reasons": ["No enrichment available for this IOC type"],
                    }
                )
                continue

            # Sources: providers with a successful (ok/cached) response only.
            sources: dict = {
                provider: data
                for provider, data in ioc_enrichment.items()
                if isinstance(data, dict) and data.get("status") in _OK_STATUSES
            }

            # Per-provider data extraction.
            vt_data: dict = ioc_enrichment.get("virustotal", {}) or {}
            abuse_data: dict = ioc_enrichment.get("abuseipdb", {}) or {}
            otx_data: dict = ioc_enrichment.get("otx", {}) or {}

            vt_status: str | None = vt_data.get("status")
            abuse_status: str | None = abuse_data.get("status")
            otx_status: str | None = otx_data.get("status")

            vt_present: bool = vt_status in _OK_STATUSES
            abuse_present: bool = abuse_status in _OK_STATUSES
            otx_present: bool = otx_status in _OK_STATUSES

            vt_malicious: int = int(vt_data.get("malicious", 0)) if vt_present else 0
            abuse_score: int = (
                int(abuse_data.get("abuse_confidence_score", 0)) if abuse_present else 0
            )
            abuse_reports: int = (
                int(abuse_data.get("total_reports", 0)) if abuse_present else 0
            )
            otx_pulses: int = int(otx_data.get("pulse_count", 0)) if otx_present else 0

            # Strong signals (same thresholds as reasoner.py).
            vt_strong: bool = vt_present and vt_malicious >= 5
            abuse_strong: bool = (
                abuse_present and abuse_score >= 80 and abuse_reports >= 10
            )
            otx_strong: bool = otx_present and otx_pulses >= 1

            # Weak signals: provider present and ok/cached but below threshold.
            vt_weak: bool = vt_present and 0 < vt_malicious < 5
            abuse_weak: bool = abuse_present and abuse_score > 0 and not abuse_strong

            strong_count: int = sum([vt_strong, abuse_strong, otx_strong])

            if strong_count >= 2:
                verdict, confidence = "malicious", 95
            elif strong_count == 1:
                verdict, confidence = "malicious", 75
            elif vt_weak or abuse_weak:
                verdict, confidence = "suspicious", 40
            else:
                verdict, confidence = "unknown", 0

            # Build reasons: one string per provider that has any status.
            reasons: list[str] = []

            if vt_status in _OK_STATUSES:
                reasons.append(f"VirusTotal: {vt_malicious} malicious detections")
            elif vt_status == "rate_limited":
                reasons.append("VirusTotal: rate limited")
            elif vt_status == "error":
                reasons.append("VirusTotal: unavailable")
            # "skipped" → omit (API key not configured; no signal value)

            if abuse_status in _OK_STATUSES:
                reasons.append(
                    f"AbuseIPDB: confidence {abuse_score}, {abuse_reports} reports"
                )
            elif abuse_status == "rate_limited":
                reasons.append("AbuseIPDB: rate limited")
            elif abuse_status == "error":
                reasons.append("AbuseIPDB: unavailable")

            if otx_status in _OK_STATUSES:
                reasons.append(f"OTX: {otx_pulses} threat pulses")
            elif otx_status == "rate_limited":
                reasons.append("OTX: rate limited")
            elif otx_status == "error":
                reasons.append("OTX: unavailable (timeout)")

            observables.append(
                {
                    "type": ioc_type,
                    "value": value,
                    "is_public": is_public,
                    "verdict": verdict,
                    "sources": sources,
                    "confidence": confidence,
                    "reasons": reasons,
                }
            )

        except Exception:  # noqa: BLE001 — never propagate from observable builder
            _logger.warning(
                "_build_observables: malformed IOC skipped", exc_info=True
            )
            ioc_safe: dict = ioc if isinstance(ioc, dict) else {}
            observables.append(
                {
                    "type": ioc_safe.get("type", "unknown"),
                    "value": ioc_safe.get("value", ""),
                    "is_public": ioc_safe.get("external", False),
                    "verdict": "unknown",
                    "sources": {},
                    "confidence": 0,
                    "reasons": ["Malformed IOC"],
                }
            )

    return observables


# ---------------------------------------------------------------------------
# Tag builder (orchestration helper — not a tool, not an endpoint)
# ---------------------------------------------------------------------------

_VERDICT_TAG_MAP: dict[str, str] = {
    "TRUE_POSITIVE": "true_positive",
    "FALSE_POSITIVE": "false_positive",
}

_NATURE_TAG_MAP: dict[str, str] = {
    "public_attack": "public_attack",
    "internal_movement": "internal_movement",
    "informational": "informational",
}


def _build_tags(parsed: dict) -> list:
    """Build a flat list of classification tags from the pipeline result.

    Produces up to five tags derived from four independent sources:

    1. **verdict** — LLM verdict string mapped to a lowercase tag.
       ``"TRUE_POSITIVE"`` → ``"true_positive"``,
       ``"FALSE_POSITIVE"`` → ``"false_positive"``,
       anything else (including ``"NEEDS_REVIEW"``, missing, or error) →
       ``"needs_review"``.

    2. **nature_category** — orthogonal axis from the parser.
       ``"public_attack"`` / ``"internal_movement"`` / ``"informational"``
       are passed through unchanged.  Missing key is silently skipped.

    3. **alert_type** — technical type from the parser (already lowercase,
       e.g. ``"network"``, ``"windows_event"``).  Added as-is if present
       and non-empty.

    4. **mitre** — if ``parsed["verdict"]["mitre"]`` is a dict with both
       ``"id"`` and ``"name"``, adds ``"mitre:<id>"`` (e.g. ``"mitre:T1110"``)
       and ``"tactic:<name_snake_case>"`` (e.g. ``"tactic:brute_force"``).
       ``None`` or missing: silently skipped.

    Args:
        parsed: The fully populated pipeline dict after all stages have run.
                Must contain ``"verdict"`` (dict) and may contain
                ``"nature_category"`` and ``"alert_type"``.

    Returns:
        List of lowercase tag strings, never raises.  Returns ``[]`` on any
        unexpected error (defensive: a broken tag builder must never stall
        the pipeline or lose the alert).
    """
    try:
        tags: list[str] = []

        # 1. Verdict tag
        verdict_dict: dict = parsed.get("verdict") or {}
        raw_verdict: str = verdict_dict.get("verdict", "") or ""
        tags.append(_VERDICT_TAG_MAP.get(raw_verdict, "needs_review"))

        # 2. Nature category tag (optional — skip if key is absent)
        nature: str | None = parsed.get("nature_category")
        if nature is not None:
            tags.append(_NATURE_TAG_MAP.get(nature, "informational"))

        # 3. Alert type tag (optional — skip if absent or empty)
        alert_type: str | None = parsed.get("alert_type")
        if alert_type and isinstance(alert_type, str):
            tags.append(alert_type)

        # 4. MITRE tags (optional — skip if mitre is None or malformed)
        mitre = verdict_dict.get("mitre")
        if isinstance(mitre, dict):
            mitre_id: str | None = mitre.get("id")
            mitre_name: str | None = mitre.get("name")
            if mitre_id and mitre_name:
                tags.append(f"mitre:{mitre_id}")
                tags.append(f"tactic:{mitre_name.lower().replace(' ', '_')}")

        return tags

    except Exception:  # noqa: BLE001 — never propagate from tag builder
        _logger.warning("_build_tags: unexpected error building tags", exc_info=True)
        return []


# ---------------------------------------------------------------------------
# Key-factors builder (orchestration helper — not a tool, not an endpoint)
# ---------------------------------------------------------------------------


def _build_key_factors(parsed: dict) -> list:
    """Build a human-readable list of key factors explaining the triage verdict.

    Collects signal evidence from four sources in this order:

    A. **Enriched malicious IPs** — one string per provider that detected the
       IP as malicious, derived from ``parsed["observables"][*].sources``
       (already filtered to ok/cached providers by ``_build_observables``).
       Only observables whose ``verdict == "malicious"`` are considered.

    B. **Rule description** — ``parsed["rule_description"]`` appended as-is
       when it is a non-empty string (the parser already formats it).

    C. **Nature category** — appends ``"External IP targeting exposed asset"``
       only when ``parsed["nature_category"] == "public_attack"``.

    D. **Justification extract** — the first complete sentence of the LLM
       justification, extracted by splitting on sentence-ending punctuation
       (period, exclamation mark, or question mark) followed by whitespace or
       end-of-string.  This preserves dotted IP addresses and decimal numbers
       intact.  If the single extracted sentence exceeds 150 characters it is
       truncated at the last word boundary within the first 150 characters.

    Args:
        parsed: The fully populated pipeline dict after all stages have run,
                including ``"observables"`` (set by ``_build_observables``),
                ``"rule_description"``, ``"nature_category"``, and
                ``"verdict"`` (with ``"justification"``) keys.  All missing
                keys are handled gracefully.

    Returns:
        List of human-readable factor strings.  Never raises; returns ``[]``
        on any unexpected error (defensive: a broken key-factors builder must
        never stall the pipeline or lose the alert).
    """
    try:
        factors: list[str] = []

        # A. Enriched malicious IPs (per observable, per provider)
        for observable in parsed.get("observables", []):
            if observable.get("verdict") != "malicious":
                continue
            ip: str = observable.get("value", "")
            sources: dict = observable.get("sources", {})

            vt: dict | None = sources.get("virustotal")
            if vt and vt.get("malicious", 0) > 0:
                factors.append(
                    f"IP {ip} flagged by VirusTotal ({vt['malicious']} malicious detections)"
                )

            abuse: dict | None = sources.get("abuseipdb")
            if abuse and abuse.get("abuse_confidence_score", 0) > 0:
                factors.append(
                    f"IP {ip} flagged by AbuseIPDB "
                    f"(confidence {abuse['abuse_confidence_score']}, "
                    f"{abuse.get('total_reports', 0)} reports)"
                )

            otx: dict | None = sources.get("otx")
            if otx and otx.get("pulse_count", 0) > 0:
                factors.append(
                    f"IP {ip} flagged by OTX ({otx['pulse_count']} threat pulses)"
                )

        # B. Rule description (appended verbatim — already formatted by parser)
        rule_desc: str | None = parsed.get("rule_description")
        if rule_desc and isinstance(rule_desc, str):
            factors.append(rule_desc)

        # C. Nature category (public attack only)
        nc: str | None = parsed.get("nature_category")
        if nc == "public_attack":
            factors.append("External IP targeting exposed asset")

        # D. Justification extract — first complete sentence using regex boundary.
        # Sentence boundary = . ! or ? followed by whitespace OR end-of-string.
        # This preserves dotted IPs and decimal numbers (no space after those dots).
        just: str = (parsed.get("verdict") or {}).get("justification", "") or ""
        if just:
            parts = re.split(r"(?<=[.!?])\s+", just.strip())
            first_sentence: str = parts[0].strip() if parts else ""
            if len(first_sentence) > 150:
                truncated: str = first_sentence[:150]
                first_sentence = truncated.rsplit(" ", 1)[0] if " " in truncated else truncated
            if first_sentence:
                factors.append(first_sentence)

        return factors

    except Exception:  # noqa: BLE001 — never propagate from key-factors builder
        _logger.warning(
            "_build_key_factors: unexpected error building key factors", exc_info=True
        )
        return []


# ---------------------------------------------------------------------------
# Case-description builder (orchestration helper — not a tool, not an endpoint)
# ---------------------------------------------------------------------------


def _build_case_description(parsed: dict) -> str:
    """Build a 4-paragraph case description in English for the triage result.

    Combines agent identity, current UTC timestamp, rule context, enrichment
    reputation data, the LLM justification, and the final verdict into a
    single human-readable block suitable for case management notes.
    All text is ASCII-only to prevent encoding issues in downstream systems.

    Paragraphs (joined with double newlines):
      1. Event      -- agent, timestamp, rule description, malicious IPs.
      2. Enrichment -- per-provider reputation summary; OTX error notices.
      3. Analysis   -- LLM justification verbatim.
      4. Verdict    -- verdict, confidence, risk_score, next_action.

    Args:
        parsed: The fully populated pipeline dict after all stages have run,
                including ``"observables"``, ``"enrichment"``, ``"verdict"``,
                ``"agent_name"``, and ``"rule_description"`` keys.  All
                missing keys are handled gracefully.

    Returns:
        Multi-paragraph string.  Returns ``""`` on any unexpected error
        (defensive: a broken description builder must never stall the pipeline).
    """
    try:
        agent: str = parsed.get("agent_name") or "unknown agent"
        timestamp: str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        rule_desc: str = parsed.get("rule_description") or "No rule description."
        p1: str = f"An alert was received from {agent} on {timestamp}. {rule_desc}"

        malicious_values: list[str] = [
            obs["value"]
            for obs in parsed.get("observables", [])
            if obs.get("verdict") == "malicious"
        ]
        if len(malicious_values) == 1:
            p1 += f" IP involved: {malicious_values[0]}."
        elif len(malicious_values) >= 2:
            p1 += f" IPs involved: {', '.join(malicious_values)}."

        malicious_obs: list = [
            obs
            for obs in parsed.get("observables", [])
            if obs.get("verdict") == "malicious"
        ]

        if malicious_obs:
            sentences: list[str] = []
            for obs in malicious_obs:
                ip: str = obs.get("value", "")
                sources: dict = obs.get("sources", {})
                provider_parts: list[str] = []

                vt: dict = sources.get("virustotal") or {}
                if vt.get("malicious", 0) > 0:
                    provider_parts.append(
                        f"VirusTotal: {vt['malicious']} malicious engines"
                    )

                abuse: dict = sources.get("abuseipdb") or {}
                if abuse.get("abuse_confidence_score", 0) > 0:
                    provider_parts.append(
                        f"AbuseIPDB: confidence {abuse['abuse_confidence_score']}, "
                        f"{abuse.get('total_reports', 0)} reports"
                    )

                otx_src: dict = sources.get("otx") or {}
                if otx_src.get("pulse_count", 0) > 0:
                    provider_parts.append(f"OTX: {otx_src['pulse_count']} pulses")

                if provider_parts:
                    sentences.append(
                        f"IP {ip} has malicious reputation: "
                        f"{', '.join(provider_parts)}."
                    )

            enrichment: dict = parsed.get("enrichment", {})
            for enrich_ip, ip_data in enrichment.items():
                if isinstance(ip_data, dict):
                    otx_enrich: dict = ip_data.get("otx") or {}
                    if otx_enrich.get("status") == "error":
                        sentences.append(
                            f"OTX unavailable for {enrich_ip} "
                            f"({otx_enrich.get('message', 'error')})."
                        )

            p2: str = (
                " ".join(sentences)
                if sentences
                else "No IPs with malicious reputation found in external sources."
            )
        else:
            p2 = "No IPs with malicious reputation found in external sources."

        just: str = (
            (parsed.get("verdict") or {}).get("justification")
            or "No justification available."
        )
        p3: str = just

        v: dict = parsed.get("verdict") or {}
        verdict_val: str = v.get("verdict", "UNKNOWN")
        confidence: str = v.get("confidence", "N/A")
        risk_score = v.get("risk_score", "N/A")
        next_action: str = v.get("next_action") or "No action recommended."
        p4: str = (
            f"Verdict: {verdict_val} (confidence: {confidence}, "
            f"risk_score: {risk_score}). "
            f"Recommended action: {next_action}"
        )

        return "\n\n".join([p1, p2, p3, p4])

    except Exception:  # noqa: BLE001 — never propagate from case description builder
        _logger.warning(
            "_build_case_description: unexpected error building case description",
            exc_info=True,
        )
        return ""


# ---------------------------------------------------------------------------
# Severity-number builder (orchestration helper — not a tool, not an endpoint)
# ---------------------------------------------------------------------------


def _build_severity_num(parsed: dict) -> int:
    """Map risk_score to a TheHive severity integer (1–4).

    TheHive 5 severity scale: 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL.
    Defaults to 2 (MEDIUM) on any error.
    """
    try:
        risk = parsed.get("verdict", {}).get("risk_score", 5)
        if risk is None:
            risk = 5
        risk = int(risk)
        if risk <= 3:
            return 1
        elif risk <= 6:
            return 2
        elif risk <= 8:
            return 3
        else:
            return 4
    except Exception:
        _logger.warning("_build_severity_num: unexpected error", exc_info=True)
        return 2


@app.post("/analyze")
def analyze(
    payload: dict = Body(...),
    deps: dict = Depends(get_pipeline),
) -> dict:
    """Orchestrate the full triage pipeline for a single Wazuh alert.

    Accepts an arbitrary JSON object (Wazuh alert, optionally wrapped under
    ``_source``).  The pipeline runs synchronously in FastAPI's thread pool:

        parse_alert → enrich → reason → route → log_alert

    Every stage mutates ``parsed`` in-place; all stages are individually
    defensive (never raise on malformed input).  The outer try/except is a
    last-resort safety net for truly unexpected failures.

    Args:
        payload: Raw alert dict.  Validated by FastAPI as a JSON object;
                 non-object bodies (e.g. JSON arrays) → HTTP 422.
        deps:    Injected pipeline clients from ``get_pipeline()``.

    Returns:
        The fully populated ``parsed`` dict including ``alert_type``,
        ``iocs``, ``enrichment``, ``verdict``, ``reasoner_meta``, and
        ``routing``.

    Notes:
        - Never returns HTTP 500.  On any unexpected error, returns HTTP 200
          with a conservative escalation body so no alert is ever silently
          lost.
        - The caller (Shuffle) reads ``routing.send_to_shuffle`` to decide
          whether to open a case.  This service does NOT call Shuffle directly.
    """
    try:
        parsed = parse_alert(payload)
        enrich(parsed, clients=deps["enricher_clients"])
        reason(parsed, client=deps["ollama_client"])
        route(parsed)
        parsed["observables"] = _build_observables(parsed)
        parsed["tags"] = _build_tags(parsed)
        parsed["key_factors"] = _build_key_factors(parsed)
        parsed["case_description"] = _build_case_description(parsed)
        parsed["severity_num"] = _build_severity_num(parsed)
        log_alert(parsed)
        return parsed

    except Exception as exc:  # noqa: BLE001 — intentional last-resort catch
        _logger.error(
            "Unexpected pipeline error for payload %r: %s",
            type(payload).__name__,
            exc,
            exc_info=True,
        )
        escalation = {
            "routing": {
                "action": "create_case",
                "send_to_shuffle": True,
                "reason": f"defensive escalation: unexpected pipeline error — {exc}",
            }
        }
        # Best-effort audit row: the mandatory audit trail must record EVERY
        # alert, including those that crash the pipeline.  log_alert is itself
        # defensive, but guard here too since this is the catastrophic path.
        try:
            log_alert(escalation)
        except Exception:  # noqa: BLE001 — never let the audit write break escalation
            _logger.error(
                "audit log_alert failed in defensive escalation path", exc_info=True
            )
        return escalation


# ---------------------------------------------------------------------------
# Local runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.getenv("SERVICE_HOST", "0.0.0.0")
    port = int(os.getenv("SERVICE_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
