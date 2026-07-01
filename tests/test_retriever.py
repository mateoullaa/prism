"""
tests/test_retriever.py — Pytest suite for tools/retriever.py (v2.2 RAG).

All tests are deterministic; no network, disk, or ChromaDB server dependencies.
The Ollama embeddings endpoint and the Chroma collection are replaced by injected
mock sessions / MagicMock collections, mirroring test_reasoner.py's pattern.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Ensure the repo root is on the path so tools.* is importable.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.retriever import (  # noqa: E402
    EmbeddingClient,
    Retriever,
    _embedding_text,
    auto_fp_model_label,
    build_correlation_summary,
    decide_auto_fp,
    index_alert,
    retrieve_similar,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    return resp


def _make_embedder(session: MagicMock) -> EmbeddingClient:
    return EmbeddingClient(
        session=session,
        host="http://test-ollama:11434",
        model="nomic-embed-text",
        timeout=5.0,
    )


def _hit(similarity: float, verdict: str = "FALSE_POSITIVE", confidence: str = "HIGH") -> dict:
    return {
        "similarity": similarity,
        "verdict": verdict,
        "confidence": confidence,
        "alert_type": "windows_event",
        "rule_id": "60602",
        "mitre_id": "",
        "timestamp": "2026-06-17T16:27:32+00:00",
    }


def _chroma_result(distances: list[float], metadatas: list[dict]) -> dict:
    """Shape a Chroma query() response (each list wrapped one level deep)."""
    return {
        "ids": [[f"id{i}" for i in range(len(distances))]],
        "distances": [distances],
        "metadatas": [metadatas],
        "documents": [["doc"] * len(distances)],
    }


# ---------------------------------------------------------------------------
# _embedding_text — deterministic canonical signature
# ---------------------------------------------------------------------------


def test_embedding_text_canonical_format():
    parsed = {
        "alert_type": "windows_event",
        "nature_category": "informational",
        "rule_id": "60602",
        "rule_description": "Windows application error event.",
    }
    assert _embedding_text(parsed) == (
        "windows_event | informational | rule 60602 | Windows application error event."
    )


def test_embedding_text_matches_between_parsed_and_csv_row():
    # The query side (parsed dict) and corpus side (CSV row) must produce the
    # SAME signature so their vectors are comparable.
    parsed = {
        "alert_type": "network",
        "nature_category": "public_attack",
        "rule_id": 651,  # parser may yield int
        "rule_description": "Host Blocked by firewall-drop Active Response",
    }
    csv_row = {
        "alert_type": "network",
        "nature_category": "public_attack",
        "rule_id": "651",  # CSV yields str
        "rule_description": "Host Blocked by firewall-drop Active Response",
    }
    assert _embedding_text(parsed) == _embedding_text(csv_row)


def test_embedding_text_defaults_for_missing_fields():
    assert _embedding_text({}) == "unknown | unknown | rule N/A | N/A"


# ---------------------------------------------------------------------------
# EmbeddingClient — fail-safe (never raises, None on failure)
# ---------------------------------------------------------------------------


def test_embed_ok_returns_vector():
    session = MagicMock()
    session.post.return_value = _mock_response({"embedding": [0.1, 0.2, 0.3]})
    assert _make_embedder(session).embed("text") == [0.1, 0.2, 0.3]


def test_embed_non_200_returns_none():
    session = MagicMock()
    session.post.return_value = _mock_response({}, status_code=500)
    assert _make_embedder(session).embed("text") is None


def test_embed_empty_vector_returns_none():
    session = MagicMock()
    session.post.return_value = _mock_response({"embedding": []})
    assert _make_embedder(session).embed("text") is None


def test_embed_network_error_returns_none():
    session = MagicMock()
    session.post.side_effect = Exception("connection refused")
    assert _make_embedder(session).embed("text") is None


# ---------------------------------------------------------------------------
# Retriever.query / index — convert distance→similarity, fail safe
# ---------------------------------------------------------------------------


def test_query_converts_distance_to_similarity():
    embedder = MagicMock()
    embedder.embed.return_value = [0.1, 0.2, 0.3]
    collection = MagicMock()
    collection.query.return_value = _chroma_result(
        distances=[0.0, 0.2],
        metadatas=[
            {"verdict": "FALSE_POSITIVE", "confidence": "HIGH"},
            {"verdict": "TRUE_POSITIVE", "confidence": "HIGH"},
        ],
    )
    hits = Retriever(collection=collection, embedder=embedder, top_k=5).query("text")
    assert [round(h["similarity"], 3) for h in hits] == [1.0, 0.8]
    assert hits[0]["verdict"] == "FALSE_POSITIVE"


def test_query_returns_empty_when_embedding_fails():
    embedder = MagicMock()
    embedder.embed.return_value = None
    collection = MagicMock()
    assert Retriever(collection=collection, embedder=embedder, top_k=5).query("t") == []
    collection.query.assert_not_called()


def test_query_returns_empty_on_chroma_error():
    embedder = MagicMock()
    embedder.embed.return_value = [0.1]
    collection = MagicMock()
    collection.query.side_effect = Exception("store corrupt")
    assert Retriever(collection=collection, embedder=embedder, top_k=5).query("t") == []


def test_index_upserts_and_returns_true():
    embedder = MagicMock()
    embedder.embed.return_value = [0.1, 0.2]
    collection = MagicMock()
    ok = Retriever(collection=collection, embedder=embedder, top_k=5).index(
        doc_id="d1", text="sig", metadata={"verdict": "FALSE_POSITIVE"}
    )
    assert ok is True
    collection.upsert.assert_called_once()


def test_index_returns_false_when_embedding_fails():
    embedder = MagicMock()
    embedder.embed.return_value = None
    collection = MagicMock()
    ok = Retriever(collection=collection, embedder=embedder, top_k=5).index(
        doc_id="d1", text="sig", metadata={}
    )
    assert ok is False
    collection.upsert.assert_not_called()


# ---------------------------------------------------------------------------
# retrieve_similar — context aggregate (function 2)
# ---------------------------------------------------------------------------


def test_retrieve_similar_none_retriever_is_noop():
    result = retrieve_similar({"alert_type": "ssh"}, retriever=None)
    assert result == {"hits": [], "summary": None}


def test_retrieve_similar_builds_summary():
    retriever = MagicMock()
    retriever.query.return_value = [
        _hit(0.99, "FALSE_POSITIVE"),
        _hit(0.95, "FALSE_POSITIVE"),
        _hit(0.90, "TRUE_POSITIVE"),
    ]
    result = retrieve_similar({"alert_type": "windows_event"}, retriever=retriever)
    assert result["summary"] == (
        "Of 3 similar past alerts: 2 FALSE_POSITIVE, 1 TRUE_POSITIVE, 0 NEEDS_REVIEW."
    )
    assert len(result["hits"]) == 3


def test_retrieve_similar_no_hits_summary_is_none():
    retriever = MagicMock()
    retriever.query.return_value = []
    result = retrieve_similar({"alert_type": "ssh"}, retriever=retriever)
    assert result["summary"] is None


# ---------------------------------------------------------------------------
# decide_auto_fp — conservative auto-classification (function 1)
# ---------------------------------------------------------------------------


def test_auto_fp_unanimous_high_fp_above_threshold():
    hits = [_hit(0.99), _hit(0.97), _hit(0.96), _hit(0.95), _hit(0.93)]
    decision = decide_auto_fp(hits, threshold=0.92, min_precedents=5)
    assert decision is not None
    assert decision["verdict"]["verdict"] == "FALSE_POSITIVE"
    assert decision["verdict"]["confidence"] == "HIGH"
    assert decision["verdict"]["risk_score"] == 1
    assert decision["verdict"]["mitre"] is None
    assert decision["precedent_count"] == 5
    assert "Auto-classified FALSE_POSITIVE" in decision["verdict"]["justification"]


def test_auto_fp_blocked_by_insufficient_precedents():
    hits = [_hit(0.99), _hit(0.97)]  # only 2 above threshold, need 5
    assert decide_auto_fp(hits, threshold=0.92, min_precedents=5) is None


def test_auto_fp_blocked_when_a_precedent_is_not_fp():
    hits = [_hit(0.99), _hit(0.97), _hit(0.96), _hit(0.95), _hit(0.93, "TRUE_POSITIVE")]
    assert decide_auto_fp(hits, threshold=0.92, min_precedents=5) is None


def test_auto_fp_blocked_when_a_precedent_is_not_high_confidence():
    hits = [_hit(0.99), _hit(0.97), _hit(0.96), _hit(0.95), _hit(0.93, confidence="MEDIUM")]
    assert decide_auto_fp(hits, threshold=0.92, min_precedents=5) is None


def test_auto_fp_ignores_hits_below_threshold():
    # 5 FP/HIGH hits but only 4 above threshold → blocked.
    hits = [_hit(0.99), _hit(0.97), _hit(0.96), _hit(0.95), _hit(0.50)]
    assert decide_auto_fp(hits, threshold=0.92, min_precedents=5) is None


def test_auto_fp_low_confidence_below_threshold_does_not_count_against():
    # A weak (below-threshold) non-HIGH/non-FP hit is simply ignored, not a blocker.
    hits = [
        _hit(0.99), _hit(0.97), _hit(0.96), _hit(0.95), _hit(0.93),
        _hit(0.10, "TRUE_POSITIVE", "LOW"),
    ]
    decision = decide_auto_fp(hits, threshold=0.92, min_precedents=5)
    assert decision is not None
    assert decision["precedent_count"] == 5


def test_auto_fp_empty_hits_returns_none():
    assert decide_auto_fp([], threshold=0.92, min_precedents=5) is None


def test_auto_fp_uses_env_defaults(monkeypatch):
    monkeypatch.setenv("AUTO_FP_THRESHOLD", "0.80")
    monkeypatch.setenv("RAG_MIN_PRECEDENTS", "2")
    hits = [_hit(0.85), _hit(0.82)]
    assert decide_auto_fp(hits) is not None


# ---------------------------------------------------------------------------
# index_alert — write-path metadata coalescing
# ---------------------------------------------------------------------------


def test_index_alert_none_retriever_is_noop():
    assert index_alert({"alert_type": "ssh"}, retriever=None) is False


def test_index_alert_builds_string_only_metadata():
    retriever = MagicMock()
    retriever.index.return_value = True
    parsed = {
        "alert_type": "windows_event",
        "nature_category": "informational",
        "rule_id": 60602,
        "rule_description": "Windows application error event.",
        "verdict": {
            "verdict": "FALSE_POSITIVE",
            "confidence": "HIGH",
            "mitre": None,
        },
    }
    ok = index_alert(parsed, retriever=retriever, timestamp="2026-06-17T16:27:32+00:00")
    assert ok is True
    _, kwargs = retriever.index.call_args
    meta = kwargs["metadata"]
    # All metadata values must be Chroma-safe (str/int/float/bool), never None.
    assert all(isinstance(v, (str, int, float, bool)) for v in meta.values())
    assert meta["verdict"] == "FALSE_POSITIVE"
    assert meta["rule_id"] == "60602"
    assert meta["mitre_id"] == ""


def test_index_alert_extracts_mitre_id():
    retriever = MagicMock()
    retriever.index.return_value = True
    parsed = {
        "alert_type": "ssh",
        "rule_id": "5710",
        "verdict": {"verdict": "TRUE_POSITIVE", "confidence": "HIGH",
                    "mitre": {"id": "T1110", "name": "Brute Force"}},
    }
    index_alert(parsed, retriever=retriever, timestamp="t")
    _, kwargs = retriever.index.call_args
    assert kwargs["metadata"]["mitre_id"] == "T1110"


def test_auto_fp_model_label(monkeypatch):
    monkeypatch.setenv("EMBED_MODEL", "nomic-embed-text")
    assert auto_fp_model_label() == "rag-similarity:nomic-embed-text"


# ---------------------------------------------------------------------------
# build_correlation_summary — human-readable interpretation for analysts
# ---------------------------------------------------------------------------


def _cs_hit(verdict: str, similarity: float = 0.95) -> dict:
    return {"similarity": similarity, "verdict": verdict, "confidence": "HIGH",
            "alert_type": "windows_event", "rule_id": "60602", "mitre_id": "", "timestamp": ""}


def test_correlation_summary_none_on_empty_hits():
    assert build_correlation_summary([]) is None


def test_correlation_summary_all_fp():
    hits = [_cs_hit("FALSE_POSITIVE") for _ in range(5)]
    summary = build_correlation_summary(hits)
    assert summary is not None
    assert "FALSE_POSITIVE" in summary
    assert "5/5" in summary
    assert "benign" in summary.lower()


def test_correlation_summary_all_tp():
    hits = [_cs_hit("TRUE_POSITIVE") for _ in range(5)]
    summary = build_correlation_summary(hits)
    assert "TRUE_POSITIVE" in summary
    assert "5/5" in summary
    assert "risk" in summary.lower()


def test_correlation_summary_mixed():
    hits = [_cs_hit("TRUE_POSITIVE"), _cs_hit("FALSE_POSITIVE"), _cs_hit("NEEDS_REVIEW")]
    summary = build_correlation_summary(hits)
    assert "mixed" in summary.lower() or "ambiguous" in summary.lower()


def test_correlation_summary_majority_tp():
    hits = [_cs_hit("TRUE_POSITIVE")] * 4 + [_cs_hit("FALSE_POSITIVE")]
    summary = build_correlation_summary(hits)
    assert "4/5" in summary
    assert "TRUE_POSITIVE" in summary


def test_correlation_summary_majority_fp():
    hits = [_cs_hit("FALSE_POSITIVE")] * 4 + [_cs_hit("TRUE_POSITIVE")]
    summary = build_correlation_summary(hits)
    assert "4/5" in summary
    assert "FALSE_POSITIVE" in summary


def test_correlation_summary_includes_similarity_score():
    hits = [_cs_hit("FALSE_POSITIVE", similarity=0.97)]
    summary = build_correlation_summary(hits)
    assert "97%" in summary
