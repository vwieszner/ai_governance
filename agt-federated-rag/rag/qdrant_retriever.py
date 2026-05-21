"""Hybrid Qdrant retriever using BGE-M3 dense embeddings and BM25 sparse vectors.

Design decisions:
- Server-side RRF fusion: Qdrant's native Query API performs reciprocal rank fusion
  on the server, avoiding double round-trips and ensuring consistent scoring.
- UUID5 point IDs: Qdrant requires UUID or uint64 point IDs. Raw hex chunk_id strings
  are not valid; we deterministically derive a UUID5 from each chunk_id via
  uuid.uuid5(uuid.NAMESPACE_OID, chunk_id). The original chunk_id is stored as
  a payload field for ACL filtering and cross-retriever deduplication.
- Singleton with asyncio.Lock double-checked locking: the client is expensive to
  initialise (loads two fastembed models). A single instance is shared across
  all concurrent requests.
- ACL filter: allowed_chunk_ids are filtered server-side via MatchAny on the
  chunk_id payload field, keeping unauthorised vectors out of result scoring.
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qm
from qdrant_client.http.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchAny,
    NamedSparseVector,
    NamedVector,
    PointStruct,
    SparseIndexParams,
    SparseVector,
    SparseVectorParams,
    VectorParams,
)

from config import settings

log = structlog.get_logger(__name__)

# ── Payload field name used for ACL filtering ──────────────────────────────────
_CHUNK_ID_FIELD = "chunk_id"

# ── Vector name constants (must match collection config) ───────────────────────
_DENSE_VEC = "dense"
_SPARSE_VEC = "sparse"


def _to_qdrant_id(chunk_id: str) -> str:
    """Deterministically convert an arbitrary chunk_id string to a UUID5 string.

    Qdrant accepts UUID strings or uint64 integers as point IDs.  Raw hex or
    arbitrary strings are rejected.  uuid.uuid5 produces a stable, collision-
    resistant mapping from any string namespace.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_OID, chunk_id))


class HybridQdrantRetriever:
    """Singleton hybrid retriever: BGE-M3 dense + BM25 sparse, server-side RRF.

    Usage::

        retriever = await HybridQdrantRetriever.get_instance()
        results = await retriever.retrieve(query, allowed_chunk_ids, limit=10)
    """

    _instance: HybridQdrantRetriever | None = None
    _lock: asyncio.Lock = asyncio.Lock()

    def __init__(self) -> None:
        self._client: AsyncQdrantClient | None = None
        self._dense_model: Any = None   # fastembed TextEmbedding
        self._sparse_model: Any = None  # fastembed SparseTextEmbedding

    # ── Singleton factory ──────────────────────────────────────────────────────

    @classmethod
    async def get_instance(cls) -> "HybridQdrantRetriever":
        """Return the shared instance, initialising it once (double-checked locking)."""
        if cls._instance is not None:
            return cls._instance
        async with cls._lock:
            if cls._instance is None:
                inst = cls()
                await inst._init()
                cls._instance = inst
        return cls._instance

    async def _init(self) -> None:
        """Connect to Qdrant and load fastembed models."""
        log.info("qdrant.init", url=settings.qdrant_url, collection=settings.qdrant_collection)
        api_key = settings.qdrant_api_key or None  # empty string → None
        self._client = AsyncQdrantClient(
            url=settings.qdrant_url,
            api_key=api_key,
        )
        # fastembed is loaded lazily by qdrant-client when we call set_model;
        # import here to surface ImportError early.
        try:
            from fastembed import SparseTextEmbedding, TextEmbedding  # type: ignore[import]

            loop = asyncio.get_event_loop()
            self._dense_model = await loop.run_in_executor(
                None, lambda: TextEmbedding(model_name=settings.qdrant_dense_model)
            )
            self._sparse_model = await loop.run_in_executor(
                None, lambda: SparseTextEmbedding(model_name=settings.qdrant_sparse_model)
            )
        except ImportError as exc:
            raise RuntimeError(
                "fastembed is required for HybridQdrantRetriever. "
                "Install it with: pip install fastembed"
            ) from exc

        await self.ensure_collection()
        log.info("qdrant.ready")

    # ── Collection lifecycle ───────────────────────────────────────────────────

    async def ensure_collection(self) -> None:
        """Create the Qdrant collection if it does not already exist."""
        assert self._client is not None
        exists = await self._client.collection_exists(settings.qdrant_collection)
        if exists:
            log.debug("qdrant.collection_exists", name=settings.qdrant_collection)
            return

        log.info("qdrant.create_collection", name=settings.qdrant_collection)
        await self._client.create_collection(
            collection_name=settings.qdrant_collection,
            vectors_config={
                _DENSE_VEC: VectorParams(
                    size=settings.qdrant_dense_size,
                    distance=Distance.COSINE,
                ),
            },
            sparse_vectors_config={
                _SPARSE_VEC: SparseVectorParams(
                    index=SparseIndexParams(on_disk=False),
                ),
            },
        )
        # Index the chunk_id payload field for fast ACL filtering.
        await self._client.create_payload_index(
            collection_name=settings.qdrant_collection,
            field_name=_CHUNK_ID_FIELD,
            field_schema=qm.PayloadSchemaType.KEYWORD,
        )
        log.info("qdrant.collection_created", name=settings.qdrant_collection)

    # ── Embedding helpers ──────────────────────────────────────────────────────

    async def _embed_dense(self, text: str) -> list[float]:
        loop = asyncio.get_event_loop()
        embeddings = await loop.run_in_executor(
            None, lambda: list(self._dense_model.embed([text]))
        )
        return embeddings[0].tolist()

    async def _embed_sparse(self, text: str) -> SparseVector:
        loop = asyncio.get_event_loop()
        embeddings = await loop.run_in_executor(
            None, lambda: list(self._sparse_model.embed([text]))
        )
        sparse = embeddings[0]
        return SparseVector(indices=sparse.indices.tolist(), values=sparse.values.tolist())

    # ── Public API ─────────────────────────────────────────────────────────────

    async def retrieve(
        self,
        query: str,
        allowed_chunk_ids: list[str],
        limit: int | None = None,
    ) -> list[dict]:
        """Hybrid retrieve with server-side RRF fusion and ACL pre-filter.

        Args:
            query: Natural language query string.
            allowed_chunk_ids: Chunk IDs the caller is authorised to see.
                               An empty list returns no results (deny-by-default).
            limit: Maximum results to return; defaults to settings.qdrant_final_k.

        Returns:
            List of dicts with keys: chunk_id, text, metadata, score.
        """
        assert self._client is not None
        if not allowed_chunk_ids:
            log.debug("qdrant.retrieve.no_allowed_chunks")
            return []

        limit = limit or settings.qdrant_final_k
        log.debug("qdrant.retrieve", limit=limit, acl_size=len(allowed_chunk_ids))

        acl_filter = Filter(
            must=[
                FieldCondition(
                    key=_CHUNK_ID_FIELD,
                    match=MatchAny(any=allowed_chunk_ids),
                )
            ]
        )

        dense_vec, sparse_vec = await asyncio.gather(
            self._embed_dense(query),
            self._embed_sparse(query),
        )

        # Qdrant Query API: prefetch both dense and sparse, fuse with RRF server-side.
        results = await self._client.query_points(
            collection_name=settings.qdrant_collection,
            prefetch=[
                qm.Prefetch(
                    query=NamedVector(name=_DENSE_VEC, vector=dense_vec),
                    filter=acl_filter,
                    limit=settings.qdrant_top_k,
                ),
                qm.Prefetch(
                    query=NamedSparseVector(name=_SPARSE_VEC, vector=sparse_vec),
                    filter=acl_filter,
                    limit=settings.qdrant_top_k,
                ),
            ],
            query=qm.FusionQuery(fusion=qm.Fusion.RRF),
            limit=limit,
            with_payload=True,
        )

        out: list[dict] = []
        for pt in results.points:
            payload = pt.payload or {}
            out.append(
                {
                    "chunk_id": payload.get(_CHUNK_ID_FIELD, ""),
                    "text": payload.get("text", ""),
                    "metadata": payload.get("metadata", {}),
                    "score": pt.score,
                }
            )
        log.debug("qdrant.retrieve.done", returned=len(out))
        return out

    async def upsert_chunks(self, chunks: list[dict]) -> None:
        """Upsert a list of chunk dicts into Qdrant.

        Each chunk dict must have: chunk_id (str), text (str), metadata (dict).
        Point IDs are derived via _to_qdrant_id to satisfy Qdrant's UUID/uint64
        requirement.  The original chunk_id is stored in payload for ACL filtering.
        """
        assert self._client is not None
        if not chunks:
            return

        log.info("qdrant.upsert", count=len(chunks))

        # Embed all texts concurrently.
        texts = [c["text"] for c in chunks]
        loop = asyncio.get_event_loop()
        dense_list, sparse_list = await asyncio.gather(
            loop.run_in_executor(None, lambda: list(self._dense_model.embed(texts))),
            loop.run_in_executor(None, lambda: list(self._sparse_model.embed(texts))),
        )

        points: list[PointStruct] = []
        for chunk, dense_emb, sparse_emb in zip(chunks, dense_list, sparse_list):
            point_id = _to_qdrant_id(chunk["chunk_id"])
            points.append(
                PointStruct(
                    id=point_id,
                    vector={
                        _DENSE_VEC: dense_emb.tolist(),
                        _SPARSE_VEC: SparseVector(
                            indices=sparse_emb.indices.tolist(),
                            values=sparse_emb.values.tolist(),
                        ),
                    },
                    payload={
                        _CHUNK_ID_FIELD: chunk["chunk_id"],
                        "text": chunk["text"],
                        "metadata": chunk.get("metadata", {}),
                    },
                )
            )

        await self._client.upsert(
            collection_name=settings.qdrant_collection,
            points=points,
            wait=True,
        )
        log.info("qdrant.upsert.done", count=len(points))

    async def close(self) -> None:
        """Close the underlying Qdrant client connection."""
        if self._client is not None:
            await self._client.close()
            self._client = None
            log.info("qdrant.closed")
