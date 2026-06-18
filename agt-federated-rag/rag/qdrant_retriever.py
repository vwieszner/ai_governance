"""Hybrid Qdrant retriever (cluster-b): dense + BM25 sparse, server-side RRF."""
from __future__ import annotations

import asyncio
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


def _chunk_uuid(chunk_id: str) -> str:
    """Deterministic UUID5 from chunk_id so re-ingest is idempotent (H-4 parity)."""
    return str(uuid.uuid5(uuid.NAMESPACE_OID, chunk_id))


class HybridQdrantRetriever:
    """Cluster-B hybrid retriever — mirror of the cluster-A implementation."""

    def __init__(self) -> None:
        self._client: AsyncQdrantClient | None = None
        self._lock = asyncio.Lock()

    async def _client_conn(self) -> AsyncQdrantClient:
        if self._client is None:
            async with self._lock:
                if self._client is None:
                    self._client = AsyncQdrantClient(
                        url=settings.qdrant_url,
                        api_key=settings.qdrant_api_key or None,
                    )
        return self._client

    async def ensure_collection(self) -> None:
        """Create the collection (idempotent) with named dense + sparse vectors."""
        client = await self._client_conn()
        if await client.collection_exists(settings.qdrant_collection):
            return
        # Declared dense dim must match the embedding model output.
        await client.create_collection(
            collection_name=settings.qdrant_collection,
            vectors_config={
                "dense": VectorParams(size=settings.qdrant_dense_size, distance=Distance.COSINE),
            },
            sparse_vectors_config={"sparse": SparseVectorParams()},
        )

    async def retrieve(
        self,
        query: str,
        allowed_chunk_ids: list[str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Hybrid dense + sparse retrieval with server-side RRF and ACL filter."""
        client = await self._client_conn()
        filter_: Filter | None = None
        if allowed_chunk_ids is not None:
            filter_ = Filter(
                must=[FieldCondition(key="chunk_id", match=MatchAny(any=allowed_chunk_ids))]
            )

        # Relevance gate (see federated-rag/rag/qdrant_retriever.py for rationale):
        # drop chunks whose dense cosine score is below the threshold so an
        # off-topic document never enters the result set.
        dense_results = await client.query_points(
            collection_name=settings.qdrant_collection,
            query=models.Document(text=query, model=settings.qdrant_dense_model),
            using="dense",
            limit=settings.qdrant_top_k,
            query_filter=filter_,
            with_payload=["chunk_id"],
        )
        relevant_ids = [
            (p.payload or {}).get("chunk_id")
            for p in dense_results.points
            if p.score >= settings.qdrant_score_threshold
            and (p.payload or {}).get("chunk_id")
        ]
        if not relevant_ids:
            return []
        relevance_filter = Filter(
            must=[FieldCondition(key="chunk_id", match=MatchAny(any=relevant_ids))]
        )
        filter_ = relevance_filter if filter_ is None else Filter(
            must=[*filter_.must, *relevance_filter.must]
        )

        prefetch = [
            models.Prefetch(
                query=models.Document(text=query, model=settings.qdrant_dense_model),
                using="dense",
                limit=(limit or settings.qdrant_final_k) * 3,
                filter=filter_,
            ),
            models.Prefetch(
                query=models.Document(text=query, model=settings.qdrant_sparse_model),
                using="sparse",
                limit=(limit or settings.qdrant_final_k) * 3,
                filter=filter_,
            ),
        ]
        results = await client.query_points(
            collection_name=settings.qdrant_collection,
            prefetch=prefetch,
            query=models.FusionQuery(fusion=models.Fusion.RRF),
            limit=limit or settings.qdrant_final_k,
            with_payload=True,
        )
        out: list[dict[str, Any]] = []
        for pt in results.points:
            payload = pt.payload or {}
            out.append(
                {
                    "chunk_id": payload.get("chunk_id"),
                    "text": payload.get("text", ""),
                    "metadata": {k: v for k, v in payload.items() if k not in ("text", "chunk_id")},
                    "score": pt.score,
                }
            )
        return out

    async def fetch_by_chunk_ids(self, chunk_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch the authoritative payload for specific chunk_ids from the store of record.

        Content-integrity control (RaaS poisoning, A2d): the TEXT served into the LLM
        context for an authorized chunk MUST come from this division's trusted Qdrant
        store, never verbatim from an external retriever. ``check_auth`` calls this to
        re-source text for the fused/authorized chunk_ids; a chunk_id absent here (e.g.
        one only an external RaaS surfaced) yields nothing, so attacker-controlled text
        cannot reach the prompt. Returns ``{chunk_id: {text, metadata}}`` for the ids
        that exist in the trusted collection; missing ids are simply absent.
        """
        if not chunk_ids:
            return {}
        client = await self._client_conn()
        points = await client.retrieve(
            collection_name=settings.qdrant_collection,
            ids=[_chunk_uuid(cid) for cid in chunk_ids],
            with_payload=True,
        )
        out: dict[str, dict[str, Any]] = {}
        for pt in points:
            payload = pt.payload or {}
            cid = payload.get("chunk_id")
            if not cid:
                continue
            out[cid] = {
                "text": payload.get("text", ""),
                "metadata": {k: v for k, v in payload.items() if k not in ("text", "chunk_id")},
            }
        return out

    async def upsert_chunks(self, chunks: list[dict[str, Any]]) -> None:
        """Embed + upsert chunks. Mirrors cluster-A: explicit FastEmbed vectors.

        qdrant-client 1.16 mis-assigns batched lazy models.Document inference
        across points (distinct ids collapse to one), so we embed explicitly.
        """
        client = await self._client_conn()
        from fastembed import SparseTextEmbedding, TextEmbedding

        dense_model = TextEmbedding(model_name=settings.qdrant_dense_model)
        sparse_model = SparseTextEmbedding(model_name=settings.qdrant_sparse_model)
        texts = [chunk["text"] for chunk in chunks]
        dense_vecs = list(dense_model.embed(texts))
        sparse_vecs = list(sparse_model.embed(texts))

        points = [
            models.PointStruct(
                id=_chunk_uuid(chunk["chunk_id"]),
                payload={
                    "text": chunk["text"],
                    "chunk_id": chunk["chunk_id"],
                    **chunk.get("metadata", {}),
                },
                vector={
                    "dense": dvec.tolist(),
                    "sparse": models.SparseVector(
                        indices=svec.indices.tolist(),
                        values=svec.values.tolist(),
                    ),
                },
            )
            for chunk, dvec, svec in zip(chunks, dense_vecs, sparse_vecs)
        ]
        await client.upsert(collection_name=settings.qdrant_collection, points=points)

    async def close(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None
