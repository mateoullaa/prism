#!/usr/bin/env python3
"""
backfill_chroma.py — one-time migration of the historical triage corpus into ChromaDB.

Reads ``metrics/triage_log.csv`` (the audit log written by tools/logger.py) and
upserts each classified alert into the Chroma ``alert_history`` collection, using
the SAME canonical signature (``tools.retriever._embedding_text``) and the SAME
vector store (Ollama embeddings) that the runtime retriever uses.  Idempotent:
re-running it upserts by a stable id (signature + timestamp), so duplicates are
not created.

Usage:
    python scripts/backfill_chroma.py
    python scripts/backfill_chroma.py --csv metrics/triage_log.csv --chroma-path ./chroma_db

Requires the Ollama embedding model to be available on the host
(``ollama pull nomic-embed-text``).  Rows whose embedding cannot be produced are
skipped and counted, never fatal.
"""

import argparse
import csv
import hashlib
import os
import sys
from collections import Counter
from pathlib import Path

import requests
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.retriever import (  # noqa: E402
    COLLECTION_NAME,
    EmbeddingClient,
    Retriever,
    _embedding_text,
)

load_dotenv()


def _build_retriever(chroma_path: str, embed_model: str) -> Retriever:
    """Build a real Retriever (Chroma + Ollama), independent of RAG_ENABLED."""
    import chromadb

    client = chromadb.PersistentClient(path=chroma_path)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
    embedder = EmbeddingClient(
        session=requests.Session(),
        host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        model=embed_model,
        timeout=float(os.getenv("OLLAMA_TIMEOUT", "30.0")),
    )
    return Retriever(collection=collection, embedder=embedder, top_k=5)


def _row_metadata(row: dict) -> dict:
    """Chroma-safe metadata (str only, never None) from a CSV row."""
    return {
        "verdict": (row.get("verdict") or "").strip(),
        "confidence": (row.get("confidence") or "").strip(),
        "alert_type": (row.get("alert_type") or "").strip(),
        "rule_id": (row.get("rule_id") or "").strip(),
        "mitre_id": (row.get("mitre_id") or "").strip(),
        "timestamp": (row.get("timestamp") or "").strip(),
    }


def backfill(csv_path: str, chroma_path: str, embed_model: str) -> int:
    path = Path(csv_path)
    if not path.is_file():
        print(f"ERROR: corpus not found: {csv_path}", file=sys.stderr)
        return 1

    retriever = _build_retriever(chroma_path, embed_model)

    indexed = 0
    skipped_no_verdict = 0
    skipped_embed_fail = 0
    by_verdict: Counter = Counter()

    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            verdict = (row.get("verdict") or "").strip()
            if not verdict:
                skipped_no_verdict += 1
                continue
            text = _embedding_text(row)
            timestamp = (row.get("timestamp") or "").strip()
            doc_id = hashlib.sha1(f"{text}|{timestamp}".encode("utf-8")).hexdigest()
            if retriever.index(doc_id=doc_id, text=text, metadata=_row_metadata(row)):
                indexed += 1
                by_verdict[verdict] += 1
            else:
                skipped_embed_fail += 1

    print("--- backfill summary ---")
    print(f"corpus:        {csv_path}")
    print(f"chroma store:  {chroma_path}  (collection: {COLLECTION_NAME})")
    print(f"embed model:   {embed_model}")
    print(f"indexed:       {indexed}")
    print(f"skipped (no verdict):   {skipped_no_verdict}")
    print(f"skipped (embed failed): {skipped_embed_fail}")
    for verdict, count in by_verdict.most_common():
        print(f"  {verdict}: {count}")
    if skipped_embed_fail:
        print(
            "\nWARNING: some rows failed to embed — is the Ollama embedding model "
            f"'{embed_model}' pulled on the host (ollama pull {embed_model})?",
            file=sys.stderr,
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default=os.getenv("LOG_PATH", "./metrics/triage_log.csv"))
    parser.add_argument("--chroma-path", default=os.getenv("CHROMA_PATH", "./chroma_db"))
    parser.add_argument("--embed-model", default=os.getenv("EMBED_MODEL", "nomic-embed-text"))
    args = parser.parse_args()
    return backfill(args.csv, args.chroma_path, args.embed_model)


if __name__ == "__main__":
    raise SystemExit(main())
