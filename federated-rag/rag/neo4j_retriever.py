"""Neo4j GraphRAG retriever using the official neo4j-graphrag Python package."""
from __future__ import annotations

from typing import Any

import neo4j
from neo4j_graphrag.embeddings.openai import OpenAIEmbeddings
from neo4j_graphrag.generation import GraphRAG
from neo4j_graphrag.llm import OpenAILLM
from neo4j_graphrag.retrievers import HybridRetriever

from config import settings


class GraphRAGRetriever:
    """
    Wraps neo4j-graphrag's HybridRetriever (vector + keyword) and
    exposes a simple async `retrieve` interface.

    The underlying driver is synchronous; we run it in a thread-pool via
    `asyncio.to_thread` so it doesn't block the event loop.
    """

    def __init__(self) -> None:
        self._driver: neo4j.Driver | None = None
        self._rag: GraphRAG | None = None

    # ── Lazy init ─────────────────────────────────────────────────────────────

    def _ensure_init(self) -> GraphRAG:
        if self._rag is not None:
            return self._rag

        self._driver = neo4j.GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )

        embedder = OpenAIEmbeddings(
            model="text-embedding-3-small",      # replaced at runtime if NVIDIA endpoint supports embeddings
            base_url=settings.openai_api_base,
            api_key=settings.openai_api_key,
        )

        retriever = HybridRetriever(
            driver=self._driver,
            index_name="chunkVector",            # created during ingestion
            fulltext_index_name="chunkFulltext", # created during ingestion
            embedder=embedder,
            return_properties=["text", "chunk_id", "source", "title"],
        )

        llm = OpenAILLM(
            model_name=settings.llm_model,
            base_url=settings.openai_api_base,
            api_key=settings.openai_api_key,
            model_params={"temperature": 0, "max_tokens": 1024},
        )

        self._rag = GraphRAG(retriever=retriever, llm=llm)
        return self._rag

    # ── Retrieval ─────────────────────────────────────────────────────────────

    async def retrieve_context(
        self,
        query: str,
        top_k: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve relevant graph context (subgraph + text chunks).

        Returns a list of chunk-like dicts so callers can fuse with Qdrant results.
        """
        import asyncio

        k = top_k or settings.neo4j_top_k

        def _run() -> list[dict[str, Any]]:
            rag = self._ensure_init()
            # neo4j-graphrag's retriever returns RetrieverResult
            result = rag.retriever.get_search_results(query_text=query, top_k=k)
            items = []
            for item in result.items:
                content = item.content if hasattr(item, "content") else str(item)
                metadata = item.metadata if hasattr(item, "metadata") else {}
                items.append(
                    {
                        "chunk_id": metadata.get("chunk_id", ""),
                        "text": content,
                        "metadata": metadata,
                        "score": metadata.get("score", 0.0),
                        "source": "graphrag",
                    }
                )
            return items

        return await asyncio.to_thread(_run)

    async def generate_answer(self, query: str) -> str:
        """Full GraphRAG answer generation (used for summarisation queries)."""
        import asyncio

        def _run() -> str:
            rag = self._ensure_init()
            result = rag.search(query_text=query, retriever_config={"top_k": settings.neo4j_top_k})
            return result.answer

        return await asyncio.to_thread(_run)

    # ── Ingestion helpers ─────────────────────────────────────────────────────

    async def ensure_indexes(self) -> None:
        """
        Create vector + fulltext indexes if they don't exist.

        FIX H-4: reuses the existing driver from _ensure_init() instead of
        opening a second driver (and leaking it when the method returned without
        calling driver.close() in the error path).
        """
        import asyncio

        def _run() -> None:
            # Reuse the instance driver — no new connection opened here.
            rag = self._ensure_init()
            driver = self._driver
            assert driver is not None, "Driver must be initialised by _ensure_init()"
            with driver.session() as session:
                # Vector index
                session.run(
                    """
                    CREATE VECTOR INDEX chunkVector IF NOT EXISTS
                    FOR (c:Chunk) ON (c.embedding)
                    OPTIONS {indexConfig: {`vector.dimensions`: 1024, `vector.similarity_function`: 'cosine'}}
                    """
                )
                # Fulltext index
                session.run(
                    """
                    CREATE FULLTEXT INDEX chunkFulltext IF NOT EXISTS
                    FOR (c:Chunk) ON EACH [c.text]
                    """
                )

        await asyncio.to_thread(_run)

    async def close(self) -> None:
        if self._driver:
            self._driver.close()
            self._driver = None
        self._rag = None
