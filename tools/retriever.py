"""
retriever.py — v2.2 RAG runtime learning (ChromaDB + Ollama embeddings).

Provides two fail-safe capabilities on top of the historical alert corpus:

  1. Auto-classification by similarity (``decide_auto_fp``): when an incoming
     alert is nearly identical to enough unanimous HIGH-confidence
     FALSE_POSITIVE precedents, classify it as FALSE_POSITIVE WITHOUT invoking
     the LLM.  Conservative by design — any doubt → no auto-classification.
  2. Context enrichment (``retrieve_similar``): aggregate the verdicts of the
     nearest historical alerts so the reasoner can use them as an extra signal,
     exactly like VirusTotal/AbuseIPDB/OTX enrichment today.

Design principles (mirrors reasoner.py / enricher.py):
  - Embeddings are produced by Ollama (EMBED_MODEL); ChromaDB is used purely as
    a local vector store — we pass our own vectors, no Chroma embedding fn.
  - Every dependency is injectable so unit tests run with MagicMock objects and
    never touch the network or disk.
  - NOTHING here ever raises.  On any failure (RAG disabled, Chroma/embedding
    unavailable, empty corpus) the functions degrade to "no result", so the
    pipeline behaves exactly as v2.1.
  - Numeric thresholds are evaluated in Python (decide_auto_fp), never delegated
    to the LLM — same principle as the enrichment thresholds in reasoner.py.
"""

import hashlib
import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Chroma collection that stores the historical alert corpus.
COLLECTION_NAME = "alert_history"

# Model label recorded in the audit trail for auto-classified alerts.
_AUTO_FP_MODEL_PREFIX = "rag-similarity"


# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def rag_enabled() -> bool:
    """Master switch.  When false the whole subsystem is a no-op."""
    return _truthy(os.getenv("RAG_ENABLED", "false"))


def shadow_mode() -> bool:
    """When true, auto-classification is computed and logged but NEVER acted on."""
    return _truthy(os.getenv("RAG_SHADOW_MODE", "true"))


# ---------------------------------------------------------------------------
# EmbeddingClient — Ollama /api/embeddings (same shape as reasoner.OllamaClient)
# ---------------------------------------------------------------------------


class EmbeddingClient:
    """HTTP client for the Ollama /api/embeddings endpoint.

    Injectable for tests.  Never raises: returns ``None`` on any failure so the
    caller degrades gracefully.
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
        """Name of the Ollama embedding model this client targets."""
        return self._model

    def embed(self, text: str) -> list[float] | None:
        """Return the embedding vector for ``text``, or ``None`` on any failure."""
        url = f"{self._host}/api/embeddings"
        body = {"model": self._model, "prompt": text}
        try:
            resp = self._session.post(url, json=body, timeout=self._timeout)
            if resp.status_code != 200:
                logger.warning("Ollama embeddings returned HTTP %s", resp.status_code)
                return None
            vector = resp.json().get("embedding")
            if not isinstance(vector, list) or not vector:
                logger.warning("Ollama embeddings returned no vector")
                return None
            return vector
        except Exception as exc:  # noqa: BLE001 — fail-safe by design
            logger.warning("Ollama embeddings request failed: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Retriever — wraps an (injectable) Chroma collection + EmbeddingClient
# ---------------------------------------------------------------------------


class Retriever:
    """Thin wrapper over a Chroma collection used as a vector store.

    Both the collection and the embedder are injected, so tests pass MagicMock
    objects.  ``query`` and ``index`` never raise — they return ``[]`` / ``False``
    on any failure.
    """

    def __init__(self, *, collection, embedder: EmbeddingClient, top_k: int) -> None:
        self._collection = collection
        self._embedder = embedder
        self._top_k = top_k

    def query(self, text: str) -> list[dict]:
        """Return up to ``top_k`` nearest historical hits for ``text``.

        Each hit: ``{"similarity": float, "verdict", "confidence", "alert_type",
        "rule_id", "mitre_id", "timestamp"}``.  Returns ``[]`` on any failure
        (no embedding, empty corpus, Chroma error).
        """
        vector = self._embedder.embed(text)
        if vector is None:
            return []
        try:
            res = self._collection.query(
                query_embeddings=[vector],
                n_results=self._top_k,
            )
        except Exception as exc:  # noqa: BLE001 — fail-safe by design
            logger.warning("Chroma query failed: %s", exc)
            return []
        return _parse_query_result(res)

    def index(self, *, doc_id: str, text: str, metadata: dict) -> bool:
        """Upsert one document into the corpus.  Returns ``False`` on any failure."""
        vector = self._embedder.embed(text)
        if vector is None:
            return False
        try:
            self._collection.upsert(
                ids=[doc_id],
                embeddings=[vector],
                metadatas=[metadata],
                documents=[text],
            )
            return True
        except Exception as exc:  # noqa: BLE001 — fail-safe by design
            logger.warning("Chroma upsert failed: %s", exc)
            return False


def _parse_query_result(res: dict) -> list[dict]:
    """Flatten a Chroma query response into a list of hit dicts.

    Cosine distance is converted to similarity (``1 - distance``).  Defensive:
    any malformed shape yields ``[]``.
    """
    try:
        distances = (res.get("distances") or [[]])[0]
        metadatas = (res.get("metadatas") or [[]])[0]
    except Exception:  # noqa: BLE001
        return []
    hits: list[dict] = []
    for distance, meta in zip(distances, metadatas):
        if not isinstance(meta, dict):
            meta = {}
        try:
            similarity = 1.0 - float(distance)
        except (TypeError, ValueError):
            continue
        hits.append(
            {
                "similarity": similarity,
                "verdict": meta.get("verdict", ""),
                "confidence": meta.get("confidence", ""),
                "alert_type": meta.get("alert_type", ""),
                "rule_id": meta.get("rule_id", ""),
                "mitre_id": meta.get("mitre_id", ""),
                "timestamp": meta.get("timestamp", ""),
            }
        )
    return hits


# ---------------------------------------------------------------------------
# Canonical embedding text — used identically by backfill (CSV) and runtime
# ---------------------------------------------------------------------------


def _embedding_text(fields: dict) -> str:
    """Build the deterministic similarity signature for an alert.

    Uses only fields available BEFORE the reasoner runs, so the query side
    (live ``parsed``) and the corpus side (CSV rows) produce comparable vectors.
    ``rule_id`` + ``rule_description`` dominate, so recurring FPs (e.g. rule
    60602/61061) collapse to ~identical vectors.
    """
    alert_type = fields.get("alert_type") or "unknown"
    nature = fields.get("nature_category") or "unknown"
    rule_id = fields.get("rule_id")
    rule_id = str(rule_id) if rule_id not in (None, "") else "N/A"
    rule_desc = fields.get("rule_description") or "N/A"
    return f"{alert_type} | {nature} | rule {rule_id} | {rule_desc}"


# ---------------------------------------------------------------------------
# Function 2 — context enrichment for the LLM
# ---------------------------------------------------------------------------


def retrieve_similar(parsed: dict, *, retriever: Retriever | None = None) -> dict:
    """Fetch similar historical alerts and summarise their verdicts.

    Returns ``{"hits": [...], "summary": str | None}``.  When ``retriever`` is
    ``None`` (RAG disabled) or no precedent exists, returns an empty result and
    ``summary`` is ``None`` so the prompt is unchanged.
    """
    if retriever is None:
        return {"hits": [], "summary": None}
    hits = retriever.query(_embedding_text(parsed))
    return {"hits": hits, "summary": _summarise(hits)}


def _summarise(hits: list[dict]) -> str | None:
    """One-line verdict aggregate, or ``None`` when there are no hits."""
    if not hits:
        return None
    counts = {"FALSE_POSITIVE": 0, "TRUE_POSITIVE": 0, "NEEDS_REVIEW": 0}
    for hit in hits:
        verdict = hit.get("verdict", "")
        if verdict in counts:
            counts[verdict] += 1
    return (
        f"Of {len(hits)} similar past alerts: "
        f"{counts['FALSE_POSITIVE']} FALSE_POSITIVE, "
        f"{counts['TRUE_POSITIVE']} TRUE_POSITIVE, "
        f"{counts['NEEDS_REVIEW']} NEEDS_REVIEW."
    )


# ---------------------------------------------------------------------------
# Correlation summary — human-readable interpretation of historical precedents
# ---------------------------------------------------------------------------


def build_correlation_summary(hits: list[dict]) -> str | None:
    """Build a human-readable correlation insight from historical precedents.

    This field is intended for analyst consumption (TheHive case notes, Shuffle
    payload) — distinct from ``_summarise`` which produces a terse aggregate for
    the LLM prompt.  Returns ``None`` when there are no hits so callers can
    omit the field cleanly.
    """
    if not hits:
        return None

    total = len(hits)
    counts = {"FALSE_POSITIVE": 0, "TRUE_POSITIVE": 0, "NEEDS_REVIEW": 0}
    top_score = 0.0
    for hit in hits:
        verdict = hit.get("verdict", "")
        if verdict in counts:
            counts[verdict] += 1
        s = hit.get("similarity", 0.0)
        if s > top_score:
            top_score = s

    fp = counts["FALSE_POSITIVE"]
    tp = counts["TRUE_POSITIVE"]
    nr = counts["NEEDS_REVIEW"]
    score_pct = int(top_score * 100)

    # Dominant-FP pattern
    if fp == total:
        return (
            f"Patrón recurrente benigno: {fp}/{total} precedentes similares son "
            f"FALSE_POSITIVE (similitud máx. {score_pct}%). "
            f"Sin incidentes reales registrados para este patrón."
        )
    # Dominant-TP pattern
    if tp == total:
        return (
            f"Patrón de riesgo confirmado: {tp}/{total} precedentes similares son "
            f"TRUE_POSITIVE (similitud máx. {score_pct}%). "
            f"Alta probabilidad de incidente real."
        )
    # Strong TP majority (≥60%)
    if tp / total >= 0.6:
        return (
            f"Historial con señal real predominante: {tp}/{total} TRUE_POSITIVE, "
            f"{fp}/{total} FALSE_POSITIVE, {nr}/{total} NEEDS_REVIEW "
            f"(similitud máx. {score_pct}%). Revisar enriquecimiento de IOCs."
        )
    # Strong FP majority (≥60%)
    if fp / total >= 0.6:
        return (
            f"Historial mayoritariamente benigno: {fp}/{total} FALSE_POSITIVE, "
            f"{tp}/{total} TRUE_POSITIVE, {nr}/{total} NEEDS_REVIEW "
            f"(similitud máx. {score_pct}%). Aplicar criterio conservador."
        )
    # Mixed signal
    return (
        f"Historial mixto: {tp}/{total} TRUE_POSITIVE, {fp}/{total} FALSE_POSITIVE, "
        f"{nr}/{total} NEEDS_REVIEW (similitud máx. {score_pct}%). "
        f"Señal ambigua — requiere revisión manual."
    )


# ---------------------------------------------------------------------------
# Function 1 — auto-classification by similarity (pure, no I/O → trivially tested)
# ---------------------------------------------------------------------------


def decide_auto_fp(
    hits: list[dict],
    *,
    threshold: float | None = None,
    min_precedents: int | None = None,
) -> dict | None:
    """Decide whether to auto-classify as FALSE_POSITIVE — conservative by design.

    Returns a decision dict (``{"verdict": <full verdict>, "score", "precedent_count"}``)
    only when ALL of the following hold; otherwise ``None`` (→ fall through to LLM):
      1. at least ``min_precedents`` hits with ``similarity >= threshold``;
      2. every such precedent has ``verdict == FALSE_POSITIVE``;
      3. every such precedent has ``confidence == HIGH``.

    Never auto-classifies to TRUE_POSITIVE or NEEDS_REVIEW: a missed TP is worse
    than a reviewed FP, so auto-classification only ever discards high-certainty FPs.
    """
    if threshold is None:
        try:
            threshold = float(os.getenv("AUTO_FP_THRESHOLD", "0.92"))
        except ValueError:
            logger.warning("Invalid AUTO_FP_THRESHOLD; falling back to 0.92")
            threshold = 0.92
    if min_precedents is None:
        try:
            min_precedents = int(os.getenv("RAG_MIN_PRECEDENTS", "5"))
        except ValueError:
            logger.warning("Invalid RAG_MIN_PRECEDENTS; falling back to 5")
            min_precedents = 5

    precedents = [h for h in hits if h.get("similarity", 0.0) >= threshold]
    if len(precedents) < min_precedents:
        return None
    if not all(h.get("verdict") == "FALSE_POSITIVE" for h in precedents):
        return None
    if not all(h.get("confidence") == "HIGH" for h in precedents):
        return None

    top_score = max(h["similarity"] for h in precedents)
    count = len(precedents)
    justification = (
        f"Auto-classified FALSE_POSITIVE by similarity "
        f"(score={top_score:.2f}, {count}/{count} HIGH-confidence FP precedents). "
        f"No LLM invocation."
    )
    return {
        "verdict": {
            "verdict": "FALSE_POSITIVE",
            "confidence": "HIGH",
            "justification": justification,
            "mitre": None,
            "next_action": (
                "No action required — recurring benign pattern confirmed by "
                "historical precedent. Alert discarded."
            ),
            "risk_score": 1,
        },
        "score": top_score,
        "precedent_count": count,
    }


def auto_fp_model_label() -> str:
    """Audit-trail ``model`` value for an auto-classified alert."""
    embed_model = os.getenv("EMBED_MODEL", "nomic-embed-text")
    return f"{_AUTO_FP_MODEL_PREFIX}:{embed_model}"


# ---------------------------------------------------------------------------
# Incremental indexing (write path)
# ---------------------------------------------------------------------------


def index_alert(
    parsed: dict,
    *,
    retriever: Retriever | None = None,
    timestamp: str = "",
) -> bool:
    """Upsert a fully-processed alert into the corpus.  No-op when disabled.

    Chroma metadata values must be str/int/float/bool (no ``None``), so all
    fields are coalesced to strings.
    """
    if retriever is None:
        return False
    verdict = parsed.get("verdict") or {}
    mitre = verdict.get("mitre") if isinstance(verdict, dict) else None
    mitre_id = mitre.get("id", "") if isinstance(mitre, dict) else ""
    text = _embedding_text(parsed)
    metadata = {
        "verdict": str(verdict.get("verdict", "") if isinstance(verdict, dict) else ""),
        "confidence": str(verdict.get("confidence", "") if isinstance(verdict, dict) else ""),
        "alert_type": str(parsed.get("alert_type", "") or ""),
        "rule_id": str(parsed.get("rule_id", "") or ""),
        "mitre_id": str(mitre_id or ""),
        "timestamp": str(timestamp or ""),
    }
    doc_id = hashlib.sha1(f"{text}|{timestamp}".encode("utf-8")).hexdigest()
    return retriever.index(doc_id=doc_id, text=text, metadata=metadata)


# ---------------------------------------------------------------------------
# Default factory — built ONCE at startup by main.py (singleton)
# ---------------------------------------------------------------------------


def _build_default_retriever() -> Retriever | None:
    """Build the production Retriever from environment, or ``None`` if unavailable.

    Returns ``None`` (and the pipeline runs exactly as v2.1) when RAG is
    disabled, ``chromadb`` cannot be imported, or the Chroma store fails to open.
    """
    if not rag_enabled():
        logger.info("RAG disabled (RAG_ENABLED is not truthy) — retriever is a no-op")
        return None
    try:
        import chromadb
    except Exception as exc:  # noqa: BLE001
        logger.warning("RAG_ENABLED but chromadb import failed: %s — disabling RAG", exc)
        return None
    try:
        path = os.getenv("CHROMA_PATH", "./chroma_db")
        client = chromadb.PersistentClient(path=path)
        collection = client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("RAG_ENABLED but Chroma init failed: %s — disabling RAG", exc)
        return None
    embedder = EmbeddingClient(
        session=requests.Session(),
        host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        model=os.getenv("EMBED_MODEL", "nomic-embed-text"),
        timeout=float(os.getenv("OLLAMA_TIMEOUT", "30.0")),
    )
    top_k = int(os.getenv("RAG_TOP_K", "5"))
    logger.info("RAG enabled — Chroma store at %s, embed model %s", path, embedder.model)
    return Retriever(collection=collection, embedder=embedder, top_k=top_k)
