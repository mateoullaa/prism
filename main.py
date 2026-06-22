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
import sys
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
