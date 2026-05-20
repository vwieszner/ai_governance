"""Hybrid Qdrant retriever: BGE-M3 dense + BM25 sparse with server-side RRF fusion."""
from __future__ import annotations

import uuid
from typing import Any

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

    async def client(self) -> AsyncQdrantClient:
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
                "dense": VectorParams(size=1024, distance=Distance.COSINE),
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
                "chunk_id": str(point.id),
                "text": point.payload.get("text", "") if point.payload else "",
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
                    id=chunk.get("chunk_id") or str(uuid.uuid4()),
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
