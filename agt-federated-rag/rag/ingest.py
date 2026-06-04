"""Document ingestion pipeline: split → embed → upsert into Qdrant.

NOTE: despite the GraphRAGRetriever wiring below, this pipeline writes to **Qdrant
only** — it does NOT write Chunk nodes or a vector index to Neo4j.  The graph
retriever is constructed (and its driver closed) for symmetry with the query
path, but no Neo4j ingest happens here, so graph retrieval stays inert.  Wiring a
real Neo4j ingest path is future work.

Design decisions:
- make_chunk_id: SHA-256 over the text gives a stable, content-addressable ID.
  We use the first 16 hex characters (64 bits) — collision probability is
  negligible for knowledge-base scale corpora.
- split_text: word-based splitting (not token-based) keeps the implementation
  dependency-free.  Overlap is expressed in words so context is preserved
  across chunk boundaries.  ValueError is raised eagerly if overlap >= chunk_size
  to prevent infinite loops or degenerate splits.
- ingest_documents: opens the Qdrant retriever and (for symmetry/cleanup) the
  Neo4j-backed GraphRAGRetriever in a try/finally so close() runs even on partial
  failure.  Only Qdrant is written; the Neo4j client performs no ingest.  Files
  are read, split, and upserted one at a time to bound memory usage.
- cli() entry point: allows `python -m rag.ingest path/to/docs...` for batch
  ingestion from the command line or container init jobs.
"""
from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path

import structlog

from config import settings
from rag.neo4j_retriever import GraphRAGRetriever
from rag.qdrant_retriever import HybridQdrantRetriever

log = structlog.get_logger(__name__)


# ── Chunk ID ───────────────────────────────────────────────────────────────────


def make_chunk_id(text: str) -> str:
    """Return a 16-character hex SHA-256 prefix as a stable chunk ID.

    The first 16 hex characters of SHA-256 provide 64 bits of collision
    resistance, which is sufficient for any reasonable knowledge base.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ── Text splitting ─────────────────────────────────────────────────────────────


def split_text(
    text: str,
    chunk_size: int = 512,
    overlap: int = 64,
) -> list[str]:
    """Split *text* into overlapping word-based chunks.

    Args:
        text:       Input document text.
        chunk_size: Maximum number of words per chunk.
        overlap:    Number of words shared between consecutive chunks.

    Returns:
        List of chunk strings.

    Raises:
        ValueError: If overlap >= chunk_size (degenerate configuration).
    """
    if overlap >= chunk_size:
        raise ValueError(
            f"overlap ({overlap}) must be strictly less than chunk_size ({chunk_size})"
        )

    words = text.split()
    if not words:
        return []

    step = chunk_size - overlap
    chunks: list[str] = []
    start = 0
    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunks.append(" ".join(words[start:end]))
        start += step

    return chunks


# ── Ingestion pipeline ─────────────────────────────────────────────────────────


async def ingest_documents(
    paths: list[str | Path],
    chunk_size: int = 512,
    overlap: int = 64,
) -> None:
    """Ingest a list of document files into Qdrant (Neo4j is NOT written).

    Each file is read as UTF-8 text, split into overlapping word-based chunks,
    and upserted into Qdrant.  Neo4j ingestion would require a separate graph-import
    pipeline and is left as future work — so graph retrieval is inert in the demo.

    The Qdrant and Neo4j clients are closed in a try/finally block to ensure
    connections are released even on partial failure.

    Args:
        paths:      File paths to ingest.
        chunk_size: Words per chunk (passed to split_text).
        overlap:    Overlap words between chunks (passed to split_text).
    """
    qdrant = await HybridQdrantRetriever.get_instance()
    graph = GraphRAGRetriever()
    # Pre-initialise Neo4j in background while we start reading files.
    init_task = asyncio.create_task(graph._ensure_init())

    try:
        for raw_path in paths:
            path = Path(raw_path)
            if not path.exists():
                log.warning("ingest.file_not_found", path=str(path))
                continue
            if not path.is_file():
                log.warning("ingest.not_a_file", path=str(path))
                continue

            log.info("ingest.file_start", path=str(path))
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                log.exception("ingest.read_error", path=str(path))
                continue

            texts = split_text(text, chunk_size=chunk_size, overlap=overlap)
            if not texts:
                log.warning("ingest.empty_file", path=str(path))
                continue

            chunks = [
                {
                    "chunk_id": make_chunk_id(t),
                    "text": t,
                    "metadata": {
                        "source": path.name,
                        "source_path": str(path),
                    },
                }
                for t in texts
            ]

            await qdrant.upsert_chunks(chunks)
            log.info("ingest.file_done", path=str(path), chunks=len(chunks))

        # Await Neo4j init (it may have errored; log and continue).
        try:
            await init_task
        except Exception:
            log.exception("ingest.neo4j_init_error")

    finally:
        await qdrant.close()
        await graph.close()
        log.info("ingest.clients_closed")


# ── CLI entry point ────────────────────────────────────────────────────────────


def cli() -> None:
    """CLI entry point: ``python -m rag.ingest <file1> [file2 ...]``"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Ingest documents into the AGT federated RAG knowledge base."
    )
    parser.add_argument(
        "paths",
        nargs="+",
        metavar="FILE",
        help="One or more document files to ingest.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=512,
        help="Words per chunk (default: 512).",
    )
    parser.add_argument(
        "--overlap",
        type=int,
        default=64,
        help="Overlap words between chunks (default: 64).",
    )
    args = parser.parse_args()

    asyncio.run(
        ingest_documents(
            paths=args.paths,
            chunk_size=args.chunk_size,
            overlap=args.overlap,
        )
    )


if __name__ == "__main__":
    cli()
