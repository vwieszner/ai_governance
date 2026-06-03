"""Neo4j GraphRAG retriever using the official neo4j-graphrag Python package."""
from __future__ import annotations

import asyncio  # PY-7: was imported inside method bodies — moved to module top
import threading
from typing import Any

import neo4j
import structlog
from neo4j_graphrag.embeddings.openai import OpenAIEmbeddings
from neo4j_graphrag.generation import GraphRAG
from neo4j_graphrag.llm import OpenAILLM
from neo4j_graphrag.retrievers import HybridRetriever

from config import settings

log = structlog.get_logger(__name__)


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
        # R-5: _ensure_init() is called from asyncio.to_thread (thread-pool).
        # Multiple concurrent calls at cold-start could race on the None check,
        # creating duplicate driver connections.  threading.Lock serialises them.
        self._lock: threading.Lock = threading.Lock()
        # When the Neo4j vector index doesn't exist yet (e.g. only Qdrant was
        # ingested), HybridRetriever can't be constructed.  We cache this state
        # so callers degrade gracefully to Qdrant-only retrieval instead of
        # crashing the whole query — and we don't re-probe (and re-log) on every
        # request.  Set inside self._lock alongside _rag.
        self._graph_unavailable: bool = False

    # ── Lazy init ─────────────────────────────────────────────────────────────

    def _ensure_init(self) -> GraphRAG | None:
        """
        Lazily build the GraphRAG pipeline.

        Returns None (and caches `self._graph_unavailable`) when the Neo4j
        vector index doesn't exist — e.g. only Qdrant has been ingested.  In
        that state HybridRetriever.__init__ would raise (it eagerly probes the
        index via _fetch_index_infos, and the SDK's "no index" handler is itself
        buggy — it references a non-existent `index_name` attr and surfaces an
        AttributeError instead of the real cause).  We avoid triggering it.
        """
        # Fast path — no lock needed once initialised / known-unavailable
        if self._rag is not None:
            return self._rag
        if self._graph_unavailable:
            return None

        with self._lock:
            # Double-check after acquiring the lock (R-5)
            if self._rag is not None:
                return self._rag
            if self._graph_unavailable:
                return None

            if self._driver is None:
                self._driver = neo4j.GraphDatabase.driver(
                    settings.neo4j_uri,
                    auth=(settings.neo4j_user, settings.neo4j_password),
                )

            # Proactively verify the vector index exists before constructing the
            # HybridRetriever.  If it's absent, degrade to Qdrant-only.
            if not self._vector_index_exists("chunkVector"):
                log.warning(
                    "graph_index_unavailable",
                    index="chunkVector",
                    detail="Neo4j vector index not found — degrading to Qdrant-only retrieval",
                )
                self._graph_unavailable = True
                return None

            # QUERY embedder MUST match the INGEST embedder (rag/ingest.py uses
            # settings.embedding_model) and the chunkVector index dimension
            # (settings.embedding_dim = 1024). The previous hardcoded
            # "text-embedding-3-small" is 1536-dim AND is not served by the NVIDIA
            # endpoint, so graph vector search would 404 / dimension-mismatch.
            embedder = OpenAIEmbeddings(
                model=settings.embedding_model,
                base_url=settings.openai_api_base,
                api_key=settings.openai_api_key,
            )

            try:
                retriever = HybridRetriever(
                    driver=self._driver,
                    vector_index_name="chunkVector",      # created during ingestion
                    fulltext_index_name="chunkFulltext",  # created during ingestion
                    embedder=embedder,
                    return_properties=["text", "chunk_id", "source", "title"],
                )
            except Exception as exc:  # noqa: BLE001 — degrade rather than crash the query
                # Belt-and-suspenders: even though we pre-checked the index,
                # construction can still fail (race with index drop, missing
                # fulltext index, etc.).  Don't let it take down retrieval.
                log.warning(
                    "graph_retriever_init_failed",
                    error=str(exc),
                    detail="HybridRetriever construction failed — degrading to Qdrant-only retrieval",
                )
                self._graph_unavailable = True
                return None

            llm = OpenAILLM(
                model_name=settings.llm_model,
                base_url=settings.openai_api_base,
                api_key=settings.openai_api_key,
                model_params={"temperature": 0, "max_tokens": 1024},
            )

            self._rag = GraphRAG(retriever=retriever, llm=llm)

        return self._rag

    def _vector_index_exists(self, index_name: str) -> bool:
        """
        Return True iff a vector index with the given name exists in Neo4j.

        Uses the instance driver (which must already be set).  Any error talking
        to Neo4j is treated as "not available" so retrieval degrades gracefully
        rather than raising.
        """
        if self._driver is None:
            return False
        try:
            records, _, _ = self._driver.execute_query(
                "SHOW VECTOR INDEXES YIELD name WHERE name = $name RETURN name",
                {"name": index_name},
                database_=None,  # default database (matches HybridRetriever default)
                routing_=neo4j.RoutingControl.READ,
            )
            return len(records) > 0
        except Exception as exc:  # noqa: BLE001 — Neo4j down/unreachable → unavailable
            log.warning(
                "graph_index_probe_failed",
                index=index_name,
                error=str(exc),
            )
            return False

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
        # PY-7: asyncio imported at module top
        k = top_k or settings.neo4j_top_k

        def _run() -> list[dict[str, Any]]:
            rag = self._ensure_init()
            if rag is None:
                # Graph index unavailable — degrade to empty graph results so the
                # caller can still fuse Qdrant results (logged once in _ensure_init).
                return []
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
        # PY-7: asyncio imported at module top

        def _run() -> str:
            rag = self._ensure_init()
            if rag is None:
                # Graph index unavailable — no GraphRAG answer to contribute.
                return ""
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
        # PY-7: asyncio imported at module top

        def _run() -> None:
            # Reuse the instance driver — no new connection opened here.
            # We deliberately don't call _ensure_init() (it may short-circuit to
            # "unavailable" precisely because the indexes don't exist yet, which
            # is what we're about to fix).  Just make sure the driver is up.
            with self._lock:
                if self._driver is None:
                    self._driver = neo4j.GraphDatabase.driver(
                        settings.neo4j_uri,
                        auth=(settings.neo4j_user, settings.neo4j_password),
                    )
                driver = self._driver
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
            # Indexes now exist — clear any cached "unavailable" state so the next
            # retrieval re-probes and builds the GraphRAG pipeline.
            with self._lock:
                self._graph_unavailable = False

        await asyncio.to_thread(_run)

    async def close(self) -> None:
        if self._driver:
            self._driver.close()
            self._driver = None
        self._rag = None
        self._graph_unavailable = False
