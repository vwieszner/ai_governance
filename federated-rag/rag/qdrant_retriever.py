"""Hybrid Qdrant retriever: BGE-M3 dense + BM25 sparse with server-side RRF fusion."""
from __future__ import annotations

import asyncio
import uuid
from typing import Any


def _to_qdrant_id(chunk_id: str) -> str:
    """Convert an arbitrary chunk_id string to a stable Qdrant-compatible UUID.

    H-4 FIX: make_chunk_id() returns a 16-char hex prefix of a SHA-256 hash,
    which is neither a valid UUID nor a uint64.  Qdrant rejects such strings
    server-side, meaning every ingest call silently drops chunks.

    uuid5(NAMESPACE_OID, chunk_id) produces a deterministic UUID from the same
    input string so:
      • upserts are idempotent (same chunk_id → same point ID),
      • the original chunk_id is still stored in the payload and used by OpenFGA,
      • no random IDs are generated for chunks that already have a chunk_id.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_OID, chunk_id))

from qdrant_client import AsyncQdrantClient, models
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchAny,
    SparseVectorParams,
    VectorParams,
)

from config import settings


class HybridQdrantRetriever:
    """
    Performs hybrid retrieval using Qdrant's Query API (v1.10+).

    Dense vectors  : BGE-M3 via FastEmbed (768-dim)
    Sparse vectors : Qdrant/bm25 via FastEmbed
    Fusion         : Server-side RRF
    ACL filtering  : chunk_ids allowlist injected by the caller (from OpenFGA)
    """

    def __init__(self) -> None:
        self._client: AsyncQdrantClient | None = None
        # M3-2: lock prevents check-then-set race at cold-start (same pattern as
        # OpenFGAAuth._lock and the singletons in agent/nodes.py).
        self._lock: asyncio.Lock = asyncio.Lock()

    async def client(self) -> AsyncQdrantClient:
        if self._client is not None:
            return self._client
        async with self._lock:
            if self._client is None:
                self._client = AsyncQdrantClient(
                    url=settings.qdrant_url,
                    api_key=settings.qdrant_api_key or None,
                )
        return self._client

    # ── Collection bootstrap ──────────────────────────────────────────────────

    async def ensure_collection(self) -> None:
        """Create the collection if it doesn't exist yet."""
        c = await self.client()
        exists = await c.collection_exists(settings.qdrant_collection)
        if exists:
            return
        await c.create_collection(
            collection_name=settings.qdrant_collection,
            vectors_config={
                # GQ-6: use settings.qdrant_dense_size so this stays in sync with
                # the embedding model dimension configured in config.py (default 1024).
                "dense": VectorParams(size=settings.qdrant_dense_size, distance=Distance.COSINE),
            },
            sparse_vectors_config={
                "sparse": SparseVectorParams(),
            },
        )

    # ── Retrieval ─────────────────────────────────────────────────────────────

    async def retrieve(
        self,
        query: str,
        allowed_chunk_ids: list[str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Run hybrid retrieval.

        Args:
            query: Natural language query string.
            allowed_chunk_ids: If provided, only return chunks whose `chunk_id`
                               payload field is in this list (OpenFGA ACL filter).
            limit: Number of results after RRF fusion.

        Returns:
            List of dicts with keys: chunk_id, text, metadata, score.
        """
        c = await self.client()
        final_k = limit or settings.qdrant_final_k
        top_k = settings.qdrant_top_k

        acl_filter: Filter | None = None
        if allowed_chunk_ids is not None:
            acl_filter = Filter(
                must=[
                    FieldCondition(
                        key="chunk_id",
                        match=MatchAny(any=allowed_chunk_ids),
                    )
                ]
            )

        results = await c.query_points(
            collection_name=settings.qdrant_collection,
            prefetch=[
                models.Prefetch(
                    query=models.Document(text=query, model=settings.qdrant_dense_model),
                    using="dense",
                    limit=top_k,
                    filter=acl_filter,
                ),
                models.Prefetch(
                    query=models.Document(text=query, model=settings.qdrant_sparse_model),
                    using="sparse",
                    limit=top_k,
                    filter=acl_filter,
                ),
            ],
            query=models.FusionQuery(fusion=models.Fusion.RRF),
            limit=final_k,
            with_payload=True,
        )

        return [
            {
                # MED-1: return the chunk_id from the payload, not str(point.id).
                # point.id is the Qdrant-internal UUID assigned at upsert time;
                # the application-level chunk_id (a 16-hex SHA-256 prefix stored
                # separately in the payload) is what OpenFGA ACL lookups use.
                # Using str(point.id) would break every authorization decision.
                "chunk_id": (point.payload or {}).get("chunk_id", str(point.id)),
                "text": (point.payload or {}).get("text", ""),
                "metadata": {
                    k: v
                    for k, v in (point.payload or {}).items()
                    if k not in ("text", "chunk_id")
                },
                "score": point.score,
            }
            for point in results.points
        ]

    # ── Ingestion ─────────────────────────────────────────────────────────────

    async def upsert_chunks(self, chunks: list[dict[str, Any]]) -> None:
        """
        Upsert a list of chunks.

        Each chunk dict must have:
            chunk_id : str
            text     : str
            metadata : dict  (arbitrary; persisted as payload alongside text/chunk_id)
        """
        c = await self.client()
        await c.upsert(
            collection_name=settings.qdrant_collection,
            points=[
                models.PointStruct(
                    # H-4: convert to UUID5 so Qdrant accepts the point ID.
                    # Falls back to a random UUID when chunk_id is absent.
                    id=_to_qdrant_id(chunk.get("chunk_id") or str(uuid.uuid4())),
                    payload={"text": chunk["text"], "chunk_id": chunk["chunk_id"], **chunk.get("metadata", {})},
                    vector={
                        "dense": models.Document(
                            text=chunk["text"], model=settings.qdrant_dense_model
                        ),
                        "sparse": models.Document(
                            text=chunk["text"], model=settings.qdrant_sparse_model
                        ),
                    },
                )
                for chunk in chunks
            ],
        )

    async def close(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None
