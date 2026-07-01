#!/usr/bin/env python3
"""
validate_threshold.py — pick a SAFE auto-classification threshold via leave-one-out.

For every alert in the historical corpus (``metrics/triage_log.csv``) this script
queries the Chroma corpus EXCLUDING that alert itself, then asks
``tools.retriever.decide_auto_fp`` what it WOULD decide, across a sweep of
similarity thresholds.  For each threshold it reports:

  - auto-classified : how many alerts would be auto-discarded as FALSE_POSITIVE
  - correct         : of those, how many were ACTUALLY FALSE_POSITIVE in the log
  - WRONG DISCARDS  : of those, how many were actually TP/NEEDS_REVIEW  <-- MUST be 0
  - precision       : correct / auto-classified

Choose the lowest threshold where WRONG DISCARDS == 0 (and precision == 100%),
then set AUTO_FP_THRESHOLD to that value (with a safety margin) in .env.

Prerequisite: run ``scripts/backfill_chroma.py`` first to populate the store.

Usage:
    python scripts/validate_threshold.py
    python scripts/validate_threshold.py --thresholds 0.85,0.88,0.90,0.92,0.95,0.98
"""

import argparse
import csv
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.retriever import (  # noqa: E402
    COLLECTION_NAME,
    EmbeddingClient,
    _embedding_text,
    decide_auto_fp,
)

load_dotenv()

DEFAULT_THRESHOLDS = [0.85, 0.88, 0.90, 0.92, 0.95, 0.98]
MIN_PRECEDENTS = int(os.getenv("RAG_MIN_PRECEDENTS", "5"))
TOP_K = int(os.getenv("RAG_TOP_K", "5"))


def _hits_excluding_self(collection, embedder, row) -> list[dict] | None:
    """Query the corpus for a row's neighbours, excluding the row's own document.

    Returns hit dicts (similarity/verdict/confidence) or ``None`` if the row
    could not be embedded.
    """
    text = _embedding_text(row)
    vector = embedder.embed(text)
    if vector is None:
        return None
    # Fetch a few extra so dropping the self-match still leaves TOP_K candidates.
    res = collection.query(query_embeddings=[vector], n_results=TOP_K + 3)
    ids = (res.get("ids") or [[]])[0]
    distances = (res.get("distances") or [[]])[0]
    metadatas = (res.get("metadatas") or [[]])[0]

    self_ts = (row.get("timestamp") or "").strip()
    hits: list[dict] = []
    for doc_id, distance, meta in zip(ids, distances, metadatas):
        meta = meta or {}
        # Drop the leave-one-out target: same signature AND same timestamp.
        if meta.get("timestamp", "") == self_ts and (1.0 - float(distance)) > 0.9999:
            continue
        hits.append(
            {
                "similarity": 1.0 - float(distance),
                "verdict": meta.get("verdict", ""),
                "confidence": meta.get("confidence", ""),
            }
        )
        if len(hits) >= TOP_K:
            break
    return hits


def validate(csv_path: str, chroma_path: str, embed_model: str, thresholds: list[float]) -> int:
    import chromadb

    path = Path(csv_path)
    if not path.is_file():
        print(f"ERROR: corpus not found: {csv_path}", file=sys.stderr)
        return 1

    client = chromadb.PersistentClient(path=chroma_path)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
    )
    if collection.count() == 0:
        print("ERROR: Chroma collection is empty — run backfill_chroma.py first.", file=sys.stderr)
        return 1

    embedder = EmbeddingClient(
        session=requests.Session(),
        host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        model=embed_model,
        timeout=float(os.getenv("OLLAMA_TIMEOUT", "30.0")),
    )

    with path.open(newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if (r.get("verdict") or "").strip()]

    # Embed + retrieve once per row; reuse for all thresholds.
    neighbour_cache: list[tuple[str, list[dict]]] = []
    embed_failures = 0
    for row in rows:
        hits = _hits_excluding_self(collection, embedder, row)
        if hits is None:
            embed_failures += 1
            continue
        neighbour_cache.append(((row.get("verdict") or "").strip(), hits))

    print(f"corpus rows with verdict: {len(rows)}  (embedded: {len(neighbour_cache)}, "
          f"embed failures: {embed_failures})")
    print(f"min_precedents={MIN_PRECEDENTS}  top_k={TOP_K}\n")
    print(f"{'threshold':>10} {'auto-clf':>9} {'correct':>8} {'WRONG':>6} {'precision':>10}")
    print("-" * 48)

    recommended = None
    for threshold in thresholds:
        auto = correct = wrong = 0
        for actual_verdict, hits in neighbour_cache:
            decision = decide_auto_fp(hits, threshold=threshold, min_precedents=MIN_PRECEDENTS)
            if decision is None:
                continue
            auto += 1
            if actual_verdict == "FALSE_POSITIVE":
                correct += 1
            else:
                wrong += 1
        precision = (correct / auto * 100.0) if auto else 0.0
        flag = "  <-- WRONG DISCARDS" if wrong else ""
        print(f"{threshold:>10.2f} {auto:>9} {correct:>8} {wrong:>6} {precision:>9.1f}%{flag}")
        if wrong == 0 and auto > 0 and recommended is None:
            recommended = threshold

    print()
    if recommended is not None:
        print(f"Lowest safe threshold (0 wrong discards, auto-classifies something): "
              f"{recommended:.2f}")
        print("Set AUTO_FP_THRESHOLD to this (or slightly higher) in .env.")
    else:
        print("No threshold both auto-classifies AND avoids wrong discards on this corpus.\n"
              "Keep auto-classification in SHADOW mode until the corpus grows.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default=os.getenv("LOG_PATH", "./metrics/triage_log.csv"))
    parser.add_argument("--chroma-path", default=os.getenv("CHROMA_PATH", "./chroma_db"))
    parser.add_argument("--embed-model", default=os.getenv("EMBED_MODEL", "nomic-embed-text"))
    parser.add_argument(
        "--thresholds",
        default=",".join(str(t) for t in DEFAULT_THRESHOLDS),
        help="comma-separated similarity thresholds to sweep",
    )
    args = parser.parse_args()
    thresholds = sorted(float(t) for t in args.thresholds.split(","))
    return validate(args.csv, args.chroma_path, args.embed_model, thresholds)


if __name__ == "__main__":
    raise SystemExit(main())
