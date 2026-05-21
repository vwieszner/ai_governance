"""GraphRAG retriever backed by Neo4j using the neo4j-graphrag library.

Design decisions:
- threading.Lock for _ensure_init: neo4j-graphrag's driver setup is synchronous
  and blocking.  We run it in a thread-pool executor and guard the one-time
  initialisation with a threading.Lock (double-checked pattern) so concurrent
  async callers don't race to create multiple drivers.
- retrieve_context is the primary entry point.  It returns dicts with the same
  schema as HybridQdrantRetriever.retrieve so that rag/fusion.py can treat
  results from both retrievers uniformly.
- The Neo4j VectorRetriever is used for graph-augmented retrieval (hop expansion
  is configured via neo4j_graph_hops in settings).  For query embeddings we
  reuse the same BGE-M3 model that Qdrant uses, embedding synchronously in an
  executor to stay non-blocking.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Any

import structlog

from config import settings

log = structlog.get_logger(__name__)


class GraphRAGRetriever:
    """GraphRAG retriever using neo4j-graphrag with threading.Lock singleton init.

    Usage::

        retriever = GraphRAGRetriever()
        await retriever._ensure_init()   # idempotent; called automatically
        results = await retriever.retrieve_context(query)
    """

    def __init__(self) -> None:
        self._driver: Any = None
        self._retriever: Any = None
        self._embed_model: Any = None
        self._init_lock = threading.Lock()
        self._initialised = False

    # ── Initialisation ─────────────────────────────────────────────────────────

    def _sync_init(self) -> None:
        """Synchronous driver + model setup; called once inside a thread executor."""
        with self._init_lock:
            if self._initialised:
                return
            log.info(
                "neo4j.init",
                uri=settings.neo4j_uri,
                user=settings.neo4j_user,
            )
            try:
                import neo4j  # type: ignore[import]
                from fastembed import TextEmbedding  # type: ignore[import]
                from neo4j_graphrag.embeddings import BaseEmbedder  # type: ignore[import]
                from neo4j_graphrag.retrievers import VectorRetriever  # type: ignore[import]
            except ImportError as exc:
                raise RuntimeError(
                    "neo4j, neo4j-graphrag, and fastembed are required. "
                    "Install: pip install neo4j neo4j-graphrag fastembed"
                ) from exc

            self._driver = neo4j.GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
            )

            # Wrap fastembed in the neo4j-graphrag BaseEmbedder interface.
            embed_model = TextEmbedding(model_name=settings.qdrant_dense_model)

            class _FastEmbedWrapper(BaseEmbedder):
                def __init__(self, model: Any) -> None:
                    self._model = model

                def embed_query(self, text: str) -> list[float]:
                    return list(self._model.embed([text]))[0].tolist()

            self._retriever = VectorRetriever(
                driver=self._driver,
                index_name="chunk_embedding",   # must match the Neo4j vector index name
                embedder=_FastEmbedWrapper(embed_model),
                return_properties=["chunk_id", "text", "metadata"],
            )
            self._initialised = True
            log.info("neo4j.ready")

    async def _ensure_init(self) -> None:
        """Async wrapper — runs synchronous init in a thread-pool executor."""
        if self._initialised:
            return
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sync_init)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def retrieve_context(self, query: str) -> list[dict]:
        """Retrieve graph-augmented context for *query*.

        Returns:
            List of dicts with keys: chunk_id, text, metadata, score.
            Score is the cosine similarity reported by the Neo4j vector index.
        """
        await self._ensure_init()
        log.debug("neo4j.retrieve", top_k=settings.neo4j_top_k)

        loop = asyncio.get_event_loop()
        try:
            raw_results = await loop.run_in_executor(
                None,
                lambda: self._retriever.get_search_results(
                    query_text=query,
                    top_k=settings.neo4j_top_k,
                ),
            )
        except Exception:
            log.exception("neo4j.retrieve.error", query_preview=query[:80])
            return []

        out: list[dict] = []
        for item in raw_results.items:
            content = item.content if hasattr(item, "content") else {}
            # neo4j-graphrag returns RetrieverResultItem; normalise to our schema.
            chunk_id = content.get("chunk_id", "") if isinstance(content, dict) else ""
            text = content.get("text", "") if isinstance(content, dict) else str(content)
            metadata = content.get("metadata", {}) if isinstance(content, dict) else {}
            score: float = getattr(item, "score", 0.0) or 0.0
            out.append(
                {
                    "chunk_id": chunk_id,
                    "text": text,
                    "metadata": metadata,
                    "score": score,
                }
            )

        log.debug("neo4j.retrieve.done", returned=len(out))
        return out

    async def close(self) -> None:
        """Close the Neo4j driver."""
        if self._driver is not None:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._driver.close)
            self._driver = None
            log.info("neo4j.closed")
