"""Pluggable DENSE embedding backend (local FastEmbed OR a served /embeddings API).

WHY THIS EXISTS
    The dense embedding model (BAAI/bge-large-en-v1.5, ~1.3GB ONNX) downloads into the
    pod on first use, which fails on Kubernetes. This module makes the DENSE embedding
    pluggable: keep local FastEmbed as the default, ADD an OpenAI-compatible /embeddings
    backend (e.g. NVIDIA NIM nvidia/nv-embedqa-e5-v5) so a division can offload the model
    to a served endpoint. The SPARSE BM25 vector stays LOCAL in both modes (it's tiny) —
    this module only handles the dense side.

GOVERNANCE
    In api mode the query/chunk text egresses to the embedding endpoint, exactly like the
    LLM call, so the SAME two guards the RaaS adapter uses apply (rag/retriever.py):
      • residency (residency.assert_inference_allowed): residency_mode=local refuses an
        external embedding base — the text must stay in-boundary.
      • SSRF denylist (_is_egress_unsafe_raas_host): the cloud-metadata IP / link-local /
        loopback targets are ALWAYS refused, regardless of residency_mode.
    Both are reused (not duplicated) from rag/retriever.py + residency.py.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

import structlog

from config import settings

log = structlog.get_logger(__name__)

# Module singleton for the local FastEmbed dense model. Instantiating TextEmbedding loads
# the ONNX model from disk (and downloads it on first use), so we build it once and reuse
# it across calls rather than per-call (which would re-load the model every upsert/query).
_local_dense_model: Any | None = None


def _get_local_dense_model() -> Any:
    """Lazily construct + cache the FastEmbed dense model (module singleton)."""
    global _local_dense_model
    if _local_dense_model is None:
        from fastembed import TextEmbedding

        _local_dense_model = TextEmbedding(model_name=settings.qdrant_dense_model)
    return _local_dense_model


def _assert_api_egress_allowed(base_url: str) -> None:
    """Apply the SAME two guards the RaaS adapter uses before egressing text to the
    embedding API: the SSRF denylist (always) and the residency in-boundary check.

    Raises:
        RuntimeError: the base is a cloud-metadata/link-local/loopback SSRF target, or
            residency_mode=local but the base is an external (out-of-boundary) endpoint.
    """
    # SSRF denylist (A2-SSRF) — refuse cloud-metadata / link-local / loopback REGARDLESS
    # of residency_mode (reuse the RaaS guard rather than duplicate the IP logic).
    from rag.retriever import _is_egress_unsafe_raas_host

    if _is_egress_unsafe_raas_host(base_url):
        host = urlparse(base_url).hostname or base_url
        raise RuntimeError(
            f"refusing embedding endpoint: host {host!r} is a cloud-metadata / link-local / "
            f"loopback address and is never a valid embedding target (SSRF)."
        )
    # Residency: in local mode an external embedding base must be refused (the text the
    # query/chunks contain must stay in-boundary). Reuse the M6 inference guard.
    from residency import assert_inference_allowed

    assert_inference_allowed(base_url, "embeddings")


async def _embed_dense_local(texts: list[str]) -> list[list[float]]:
    """Local FastEmbed dense embedding. The cached model's .embed() is synchronous and
    CPU-bound, so run it in a thread to avoid blocking the event loop.

    The local model (bge-large) is SYMMETRIC, so input_type doesn't apply here — the caller
    passes it for the api backend; the local path embeds queries and passages identically."""
    model = _get_local_dense_model()

    def _run() -> list[list[float]]:
        return [vec.tolist() for vec in model.embed(texts)]

    return await asyncio.to_thread(_run)


async def _embed_dense_api(texts: list[str], input_type: str) -> list[list[float]]:
    """OpenAI-compatible /embeddings POST. Egress is guarded (residency + SSRF) first.

    For asymmetric models (settings.embedding_asymmetric, e.g. NVIDIA nv-embedqa) the
    required ``input_type`` ("query" | "passage") is included in the body; for symmetric
    OpenAI-compatible models it is omitted (they reject the unknown field)."""
    import httpx

    base = settings.effective_embedding_base
    _assert_api_egress_allowed(base)
    headers = {"Content-Type": "application/json"}
    key = settings.effective_embedding_key
    if key:
        headers["Authorization"] = f"Bearer {key}"
    body: dict[str, Any] = {"model": settings.embedding_model, "input": texts}
    if settings.embedding_asymmetric:
        body["input_type"] = input_type
        # NVIDIA nv-embedqa rejects inputs over its 512-token window unless told how to
        # truncate; "END" keeps the head of long chunks. Empty string omits it (symmetric
        # OpenAI models reject the unknown field). See settings.embedding_truncate.
        if settings.embedding_truncate:
            body["truncate"] = settings.embedding_truncate
    async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
        resp = await client.post(f"{base}/embeddings", json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    try:
        items = data["data"]
        vectors = [item["embedding"] for item in items]
    except (KeyError, TypeError) as exc:
        raise RuntimeError(
            f"embedding API returned an unexpected shape (expected OpenAI "
            f"{{'data': [{{'embedding': [...]}}]}}): {exc}"
        ) from exc
    return vectors


async def embed_dense(texts: list[str], *, input_type: str = "passage") -> list[list[float]]:
    """Embed ``texts`` into DENSE vectors using the configured provider.

    Dispatches on ``settings.embedding_provider``:
      • "local" (default): cached FastEmbed TextEmbedding, run off-loop in a thread.
      • "api": OpenAI-compatible POST {base}/embeddings, guarded by residency + SSRF.

    ``input_type`` ("query" | "passage", default "passage") is sent ONLY to an asymmetric
    api backend (settings.embedding_asymmetric) — embed CHUNKS as "passage" and QUERIES as
    "query" (the wrong type degrades retrieval). The local/symmetric paths ignore it.

    Returns one ``settings.qdrant_dense_size``-float vector per input text (same order).
    Raises RuntimeError on a vector-dimension mismatch (a wrong served model / config),
    so a mis-sized embedding fails loud instead of silently corrupting the collection.
    """
    if input_type not in ("query", "passage"):
        raise ValueError(f"input_type must be 'query' or 'passage', got {input_type!r}")
    if not texts:
        return []
    if settings.embedding_provider == "api":
        vectors = await _embed_dense_api(texts, input_type)
    else:
        vectors = await _embed_dense_local(texts)

    expected = settings.qdrant_dense_size
    if len(vectors) != len(texts):
        raise RuntimeError(
            f"embedding provider {settings.embedding_provider!r} returned {len(vectors)} "
            f"vectors for {len(texts)} inputs"
        )
    for vec in vectors:
        if len(vec) != expected:
            raise RuntimeError(
                f"embedding provider {settings.embedding_provider!r} returned a "
                f"{len(vec)}-dim vector but qdrant_dense_size={expected} is expected "
                f"(check embedding_model / qdrant_dense_size)."
            )
    return vectors
