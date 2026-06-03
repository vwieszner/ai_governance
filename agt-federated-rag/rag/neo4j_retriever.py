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
        # When the Neo4j vector index doesn't exist yet (e.g. only Qdrant was
        # ingested), VectorRetriever can't be constructed (it eagerly probes the
        # index in __init__ and raises "No index with name ... found").  We cache
        # this so retrieve_context degrades gracefully to Qdrant-only retrieval
        # instead of crashing the query — and we don't re-probe on every request.
        self._graph_unavailable = False

    # ── Initialisation ─────────────────────────────────────────────────────────

    def _sync_init(self) -> None:
        """Synchronous driver + model setup; called once inside a thread executor."""
        with self._init_lock:
            if self._initialised or self._graph_unavailable:
                return
            log.info(
                "neo4j.init",
                uri=settings.neo4j_uri,
                user=settings.neo4j_user,
            )
            try:
                import neo4j  # type: ignore[import]
                from fastembed import TextEmbedding  # type: ignore[import]
                from neo4j_graphrag.retrievers import VectorRetriever  # type: ignore[import]
                # neo4j-graphrag renamed the embedder base class from
                # ``BaseEmbedder`` to ``Embedder``; accept either so the code
                # works across library versions.
                try:
                    from neo4j_graphrag.embeddings import Embedder as BaseEmbedder  # type: ignore[import]
                except ImportError:  # older library exposes BaseEmbedder
                    from neo4j_graphrag.embeddings import BaseEmbedder  # type: ignore[import]
            except ImportError as exc:
                raise RuntimeError(
                    "neo4j, neo4j-graphrag, and fastembed are required. "
                    "Install: pip install neo4j neo4j-graphrag fastembed"
                ) from exc

            self._driver = neo4j.GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
            )

            # Proactively verify the vector index exists before constructing the
            # VectorRetriever — its __init__ probes the index and raises if it's
            # absent (which would otherwise crash the whole query).
            if not self._vector_index_exists(neo4j, "chunk_embedding"):
                log.warning(
                    "neo4j.index_unavailable",
                    index="chunk_embedding",
                    detail="Neo4j vector index not found — degrading to Qdrant-only retrieval",
                )
                self._graph_unavailable = True
                return

            # Wrap fastembed in the neo4j-graphrag BaseEmbedder interface.
            embed_model = TextEmbedding(model_name=settings.qdrant_dense_model)

            class _FastEmbedWrapper(BaseEmbedder):
                def __init__(self, model: Any) -> None:
                    self._model = model

                def embed_query(self, text: str) -> list[float]:
                    return list(self._model.embed([text]))[0].tolist()

            try:
                self._retriever = VectorRetriever(
                    driver=self._driver,
                    index_name="chunk_embedding",   # must match the Neo4j vector index name
                    embedder=_FastEmbedWrapper(embed_model),
                    return_properties=["chunk_id", "text", "metadata"],
                )
            except Exception as exc:  # noqa: BLE001 — degrade rather than crash the query
                log.warning(
                    "neo4j.retriever_init_failed",
                    error=str(exc),
                    detail="VectorRetriever construction failed — degrading to Qdrant-only retrieval",
                )
                self._graph_unavailable = True
                return

            self._initialised = True
            log.info("neo4j.ready")

    def _vector_index_exists(self, neo4j_mod: Any, index_name: str) -> bool:
        """Return True iff a vector index with the given name exists in Neo4j.

        Any error talking to Neo4j is treated as "not available" so retrieval
        degrades gracefully rather than raising.
        """
        if self._driver is None:
            return False
        try:
            records, _, _ = self._driver.execute_query(
                "SHOW VECTOR INDEXES YIELD name WHERE name = $name RETURN name",
                {"name": index_name},
                database_=None,
                routing_=neo4j_mod.RoutingControl.READ,
            )
            return len(records) > 0
        except Exception as exc:  # noqa: BLE001 — Neo4j down/unreachable → unavailable
            log.warning("neo4j.index_probe_failed", index=index_name, error=str(exc))
            return False

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
        if self._graph_unavailable or self._retriever is None:
            # Graph index unavailable — degrade to empty graph results so the
            # caller can still fuse Qdrant results (logged once in _sync_init).
            return []
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
