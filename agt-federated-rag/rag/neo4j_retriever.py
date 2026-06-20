"""GraphRAG retriever backed by Neo4j using the neo4j-graphrag library.

Design decisions:
- threading.Lock for _ensure_init: neo4j-graphrag's driver setup is synchronous
  and blocking.  We run it in a thread-pool executor and guard the one-time
  initialisation with a threading.Lock (double-checked pattern) so concurrent
  async callers don't race to create multiple drivers.
- retrieve_context is the primary entry point.  It returns dicts with the same
  schema as HybridQdrantRetriever.retrieve so that rag/fusion.py can treat
  results from both retrievers uniformly.
- The Neo4j VectorRetriever does plain vector lookup of Chunk nodes — it does
  NOT traverse graph edges or expand entity neighbourhoods.  (The settings field
  ``neo4j_graph_hops`` is reserved for a future traversal retriever and is not
  read anywhere today.)  For query embeddings we reuse the same BGE-M3 model that
  Qdrant uses, embedding synchronously in an executor to stay non-blocking.

NOTE — as built, this retriever is currently INERT: the AGT ingest pipeline
(rag/ingest.py) only upserts to Qdrant and never writes Chunk nodes or the
``chunk_embedding`` vector index to Neo4j.  With no index, _sync_init() flips
``_graph_unavailable`` and retrieve_context() returns [], so retrieval is
Qdrant-only.  This class is kept as the graph-retrieval seam for when a Neo4j
ingest path and a traversal retriever are wired up.
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

            # Short connection/retry bounds so that when NO Neo4j is deployed (the default —
            # the graph seam is optional), the bolt:// connect FAILS FAST instead of retry-
            # storming for ~30s and blocking the executor thread. The retrieve_local fan-out
            # already wall-clock-bounds + degrades this retriever; these driver-level bounds
            # make the underlying thread give up quickly too (defence in depth).
            self._driver = neo4j.GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
                connection_timeout=2.0,            # TCP connect gives up fast
                connection_acquisition_timeout=2.0,
                max_transaction_retry_time=2.0,    # don't retry-storm a dead host
            )

            # Presence check: a usable graph backend means Neo4j is reachable AND has the
            # vector index. If either is false (no Neo4j deployed, or deployed-but-empty),
            # RAISE so the retriever fan-out (_get_retrievers) EXCLUDES this backend — it
            # won't run per query at all ("not attached -> doesn't run"). _vector_index_exists
            # also returns False when the connection itself fails (bounded by the driver's
            # 2s connection_timeout, so this probe is fast). Attach a Neo4j + create the
            # chunk_embedding index and this passes -> the backend joins the fan-out.
            if not self._vector_index_exists(neo4j, "chunk_embedding"):
                self._graph_unavailable = True
                raise RuntimeError(
                    "Neo4j graph backend not attached/usable (unreachable or missing the "
                    "'chunk_embedding' vector index) — excluding it from the retriever fan-out"
                )

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
        """Retrieve vector-matched chunks from the Neo4j vector index for *query*.

        This is plain vector lookup, NOT graph traversal.  It currently returns
        an empty list (see the module docstring: no Neo4j ingest → no index).

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
