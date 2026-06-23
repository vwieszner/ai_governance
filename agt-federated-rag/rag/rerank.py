"""Optional reranking stage after RRF fusion — a precision lever for retrieval.

RRF fusion orders chunks by reciprocal-rank across retrievers; it doesn't model query-passage
semantic relevance. A reranker (cross-encoder) re-scores the fused candidates against the query
and keeps the best ``top_k`` — materially lifting precision@k and letting us pass a smaller, more
relevant context to the LLM.

Pluggable, mirroring ``embedding_provider`` (``settings.reranker_provider``):
  - ``none`` (default): no reranking; the RRF order stands. Zero cost, zero deps.
  - ``api``: an OpenAI-compatible / NVIDIA NIM reranking endpoint (``/v1/ranking``).
  - ``local``: a FastEmbed cross-encoder (``TextCrossEncoder``), in-process.

GOVERNANCE: a reranker only REORDERS already-retrieved candidates and keeps a subset — it never
widens access (check_auth still authorizes every surviving chunk per-chunk) and never changes the
served text (re-sourced from the trusted store). It is a relevance lever, not an auth surface.
A reranker failure degrades to the original RRF order (never crashes retrieval).
"""
from __future__ import annotations

from typing import Any, Protocol

import structlog

from config import settings

log = structlog.get_logger(__name__)


class Reranker(Protocol):
    name: str
    async def rerank(self, query: str, chunks: list[dict[str, Any]], top_k: int) -> list[dict[str, Any]]: ...


class _ApiReranker:
    """NVIDIA-NIM-style reranking endpoint. POST {model, query:{text}, passages:[{text}]} ->
    {rankings:[{index, logit}]} ordered best-first. The base/key fall back to the embedding/LLM
    endpoint so one NIM deployment can serve chat, embeddings, and reranking with one config."""

    name = "api"

    def __init__(self) -> None:
        self._base = (settings.reranker_api_base or settings.embedding_api_base
                      or settings.openai_api_base).rstrip("/")
        self._key = settings.reranker_api_key or settings.embedding_api_key or settings.openai_api_key
        self._model = settings.reranker_model

    async def rerank(self, query: str, chunks: list[dict[str, Any]], top_k: int) -> list[dict[str, Any]]:
        import httpx

        passages = [{"text": (c.get("text") or "")[:2048]} for c in chunks]
        body = {"model": self._model, "query": {"text": query}, "passages": passages}
        headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        async with httpx.AsyncClient(timeout=settings.retriever_timeout_seconds + 5.0) as client:
            r = await client.post(f"{self._base}/ranking", json=body, headers=headers)
            r.raise_for_status()
            rankings = r.json().get("rankings", [])
        order = [item["index"] for item in rankings if 0 <= item.get("index", -1) < len(chunks)]
        ranked = [chunks[i] for i in order] or chunks
        return ranked[:top_k]


class _LocalReranker:
    """In-process FastEmbed cross-encoder (TextCrossEncoder)."""

    name = "local"

    def __init__(self) -> None:
        from fastembed.rerank.cross_encoder import TextCrossEncoder  # lazy
        self._model = TextCrossEncoder(model_name=settings.reranker_model)

    async def rerank(self, query: str, chunks: list[dict[str, Any]], top_k: int) -> list[dict[str, Any]]:
        import asyncio

        docs = [(c.get("text") or "") for c in chunks]

        def _score() -> list[float]:
            return list(self._model.rerank(query, docs))

        scores = await asyncio.to_thread(_score)
        ranked = [c for _, c in sorted(zip(scores, chunks), key=lambda t: t[0], reverse=True)]
        return ranked[:top_k]


_reranker: Reranker | None = None
_resolved = False


def get_reranker() -> Reranker | None:
    """The configured reranker (cached), or None when reranking is disabled/unavailable."""
    global _reranker, _resolved
    if _resolved:
        return _reranker
    provider = (settings.reranker_provider or "none").lower()
    try:
        if provider == "api":
            _reranker = _ApiReranker()
        elif provider == "local":
            _reranker = _LocalReranker()
        else:
            _reranker = None
    except Exception as exc:  # noqa: BLE001 — misconfigured reranker must not break retrieval
        log.warning("reranker_init_failed_disabled", provider=provider, error=str(exc))
        _reranker = None
    if _reranker is not None:
        log.info("reranker_active", provider=_reranker.name, model=settings.reranker_model)
    _resolved = True
    return _reranker


def reset_reranker() -> None:
    """Drop the cached reranker (tests / config reload)."""
    global _reranker, _resolved
    _reranker, _resolved = None, False
