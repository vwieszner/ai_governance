"""
Document ingestion pipeline.

Reads plain-text / PDF documents, splits them into chunks,
writes to Qdrant (hybrid vectors) AND Neo4j (entity graph via SimpleKGPipeline).

Usage:
    python -m rag.ingest --path ./docs --chunk-size 512 --overlap 64
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import textwrap
import uuid
from pathlib import Path
from typing import Any

import structlog

from config import settings
from rag.neo4j_retriever import GraphRAGRetriever
from rag.qdrant_retriever import HybridQdrantRetriever

log = structlog.get_logger(__name__)


# ── Text splitting ─────────────────────────────────────────────────────────────

def split_text(text: str, chunk_size: int = 512, overlap: int = 64) -> list[str]:
    """Simple sentence-aware chunker."""
    words = text.split()
    chunks: list[str] = []
    start = 0
    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunks.append(" ".join(words[start:end]))
        start += chunk_size - overlap
    return chunks


def make_chunk_id(source: str, index: int) -> str:
    h = hashlib.sha256(f"{source}:{index}".encode()).hexdigest()[:16]
    return f"{h}"


# ── Neo4j KG ingestion ────────────────────────────────────────────────────────

async def ingest_to_neo4j(chunks: list[dict[str, Any]]) -> None:
    """
    Extract entities and relations from chunks and write to Neo4j.
    Uses neo4j-graphrag's SimpleKGPipeline for entity extraction via LLM.
    """
    import neo4j
    from neo4j_graphrag.embeddings.openai import OpenAIEmbeddings
    from neo4j_graphrag.experimental.pipeline.kg_builder import SimpleKGPipeline
    from neo4j_graphrag.llm import OpenAILLM

    driver = neo4j.GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )
    # Q-6: always close the driver, even if ingestion raises an exception.
    try:
        embedder = OpenAIEmbeddings(
            model="text-embedding-3-small",
            base_url=settings.openai_api_base,
            api_key=settings.openai_api_key,
        )
        llm = OpenAILLM(
            model_name=settings.llm_model,
            base_url=settings.openai_api_base,
            api_key=settings.openai_api_key,
            model_params={"temperature": 0},
        )

        kg_builder = SimpleKGPipeline(
            llm=llm,
            driver=driver,
            embedder=embedder,
            from_pdf=False,
        )

        # L3-4: count failures so we can surface a total at the end and raise if
        # every chunk failed (indicates a systemic problem, not transient noise).
        failed = 0
        for chunk in chunks:
            try:
                await kg_builder.run_async(text=chunk["text"])
                log.info("neo4j_chunk_ingested", chunk_id=chunk["chunk_id"])
            except Exception as e:
                failed += 1
                log.warning("neo4j_chunk_failed", chunk_id=chunk["chunk_id"], error=str(e))

        log.info("neo4j_ingestion_summary", total=len(chunks), failed=failed)
        if failed == len(chunks) and chunks:
            raise RuntimeError(
                f"Neo4j ingestion failed for all {failed} chunks — check LLM / Neo4j connectivity."
            )
    finally:
        driver.close()


# ── Main pipeline ─────────────────────────────────────────────────────────────

async def ingest_documents(
    paths: list[Path],
    chunk_size: int = 512,
    overlap: int = 64,
) -> None:
    qdrant = HybridQdrantRetriever()
    graph = GraphRAGRetriever()

    await qdrant.ensure_collection()
    await graph.ensure_indexes()

    all_chunks: list[dict[str, Any]] = []

    for path in paths:
        log.info("reading_file", path=str(path))
        text = path.read_text(encoding="utf-8", errors="replace")
        raw_chunks = split_text(text, chunk_size=chunk_size, overlap=overlap)

        for i, chunk_text in enumerate(raw_chunks):
            chunk_id = make_chunk_id(str(path), i)
            all_chunks.append(
                {
                    "chunk_id": chunk_id,
                    "text": chunk_text,
                    "metadata": {
                        "source": str(path),
                        "chunk_index": i,
                        "title": path.stem,
                    },
                }
            )

    log.info("upserting_to_qdrant", count=len(all_chunks))
    # Batch upserts to Qdrant (100 at a time)
    batch_size = 100
    for i in range(0, len(all_chunks), batch_size):
        await qdrant.upsert_chunks(all_chunks[i : i + batch_size])

    log.info("building_knowledge_graph", count=len(all_chunks))
    await ingest_to_neo4j(all_chunks)

    await qdrant.close()
    await graph.close()
    log.info("ingestion_complete", total_chunks=len(all_chunks))


# ── CLI ────────────────────────────────────────────────────────────────────────

def cli() -> None:
    parser = argparse.ArgumentParser(description="Ingest documents into Qdrant + Neo4j")
    parser.add_argument("--path", required=True, help="Directory or file to ingest")
    parser.add_argument("--chunk-size", type=int, default=512)
    parser.add_argument("--overlap", type=int, default=64)
    args = parser.parse_args()

    target = Path(args.path)
    paths = list(target.rglob("*.txt")) + list(target.rglob("*.md")) if target.is_dir() else [target]

    asyncio.run(ingest_documents(paths, chunk_size=args.chunk_size, overlap=args.overlap))


if __name__ == "__main__":
    cli()
