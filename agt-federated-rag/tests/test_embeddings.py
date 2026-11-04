"""Tests for the pluggable DENSE embedding backend (rag/embeddings.py).

Covers: api-mode maps data[].embedding correctly; dimension-mismatch raises; the residency
guard (local mode + external base raises, in-boundary base allowed); the SSRF denylist
(cloud-metadata IP always refused). Local mode is covered by monkeypatching the FastEmbed
singleton so no model download / network happens in tests.
"""
from __future__ import annotations

import httpx
import pytest

import rag.embeddings as E
from config import settings


# ── httpx fake (mirrors tests/test_retriever.py) ──────────────────────────────

class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _fake_client(capture: dict, payload):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json, headers):
            capture["url"] = url
            capture["json"] = json
            capture["headers"] = headers
            return _FakeResp(payload)

    return _Client


def _dim_vec(n: int) -> list[float]:
    return [0.1] * n


# ── api mode: response mapping ────────────────────────────────────────────────

async def test_api_mode_maps_data_embedding_in_order(monkeypatch):
    """api mode POSTs to {base}/embeddings and maps data[i].embedding -> vectors[i]."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "https://emb.internal/v1")
    monkeypatch.setattr(settings, "embedding_api_key", "emb-key")
    monkeypatch.setattr(settings, "embedding_model", "nvidia/nv-embedqa-e5-v5")
    monkeypatch.setattr(settings, "embedding_asymmetric", True)
    monkeypatch.setattr(settings, "residency_mode", "external")
    dim = settings.qdrant_dense_size
    capture: dict = {}
    payload = {"data": [
        {"embedding": _dim_vec(dim), "index": 0},
        {"embedding": [0.2] * dim, "index": 1},
    ]}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(capture, payload))

    out = await E.embed_dense(["a", "b"])

    assert capture["url"] == "https://emb.internal/v1/embeddings"
    assert capture["headers"]["Authorization"] == "Bearer emb-key"
    # input_type defaults to "passage" (chunk-side); asymmetric model carries it, plus the
    # default truncate="END" (nv-embedqa 400s on >512-token chunks without it).
    assert capture["json"] == {
        "model": "nvidia/nv-embedqa-e5-v5", "input": ["a", "b"],
        "input_type": "passage", "truncate": "END",
    }
    assert len(out) == 2
    assert out[0] == _dim_vec(dim)
    assert out[1] == [0.2] * dim


async def test_api_mode_asymmetric_input_type_query_vs_passage(monkeypatch):
    """Asymmetric model: input_type="query" is sent for queries, "passage" for chunks."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "https://emb.internal/v1")
    monkeypatch.setattr(settings, "embedding_asymmetric", True)
    monkeypatch.setattr(settings, "residency_mode", "external")
    dim = settings.qdrant_dense_size
    capture: dict = {}
    monkeypatch.setattr(
        httpx, "AsyncClient",
        _fake_client(capture, {"data": [{"embedding": _dim_vec(dim)}]}),
    )

    await E.embed_dense(["a question"], input_type="query")
    assert capture["json"]["input_type"] == "query"

    await E.embed_dense(["a chunk"], input_type="passage")
    assert capture["json"]["input_type"] == "passage"


async def test_api_mode_symmetric_omits_input_type(monkeypatch):
    """Symmetric model (embedding_asymmetric=False): input_type is OMITTED from the body
    (OpenAI-compatible models reject the unknown field)."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "https://emb.internal/v1")
    monkeypatch.setattr(settings, "embedding_model", "text-embedding-3-small")
    monkeypatch.setattr(settings, "embedding_asymmetric", False)
    monkeypatch.setattr(settings, "residency_mode", "external")
    dim = settings.qdrant_dense_size
    capture: dict = {}
    monkeypatch.setattr(
        httpx, "AsyncClient",
        _fake_client(capture, {"data": [{"embedding": _dim_vec(dim)}]}),
    )

    # Even though a non-default input_type is passed, it must NOT appear in the body.
    await E.embed_dense(["q"], input_type="query")
    assert "input_type" not in capture["json"]
    assert capture["json"] == {"model": "text-embedding-3-small", "input": ["q"]}


async def test_embed_dense_rejects_invalid_input_type(monkeypatch):
    """An input_type other than query/passage is a programming error -> ValueError."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    with pytest.raises(ValueError, match="input_type"):
        await E.embed_dense(["x"], input_type="document")


async def test_api_mode_truncate_present_when_asymmetric_set_else_absent(monkeypatch):
    """`truncate` is in the body when asymmetric + embedding_truncate is set (nv-embedqa
    400s on >512-token chunks without it), and ABSENT when embedding_truncate="" or when
    the model is symmetric (OpenAI models reject the unknown field)."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "https://emb.internal/v1")
    monkeypatch.setattr(settings, "residency_mode", "external")
    dim = settings.qdrant_dense_size
    capture: dict = {}
    monkeypatch.setattr(
        httpx, "AsyncClient",
        _fake_client(capture, {"data": [{"embedding": _dim_vec(dim)}]}),
    )

    # asymmetric + truncate set -> truncate carried with the configured value.
    monkeypatch.setattr(settings, "embedding_asymmetric", True)
    monkeypatch.setattr(settings, "embedding_truncate", "END")
    await E.embed_dense(["x"], input_type="passage")
    assert capture["json"]["truncate"] == "END"

    # asymmetric + truncate empty -> truncate omitted (but input_type still present).
    monkeypatch.setattr(settings, "embedding_truncate", "")
    await E.embed_dense(["x"], input_type="passage")
    assert "truncate" not in capture["json"]
    assert capture["json"]["input_type"] == "passage"

    # symmetric -> truncate omitted regardless of embedding_truncate.
    monkeypatch.setattr(settings, "embedding_asymmetric", False)
    monkeypatch.setattr(settings, "embedding_truncate", "END")
    await E.embed_dense(["x"], input_type="passage")
    assert "truncate" not in capture["json"]


async def test_api_mode_falls_back_to_openai_base_and_key(monkeypatch):
    """Empty embedding_api_base/key fall back to openai_api_base/openai_api_key."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "")
    monkeypatch.setattr(settings, "embedding_api_key", "")
    monkeypatch.setattr(settings, "openai_api_base", "https://nim.internal/v1")
    monkeypatch.setattr(settings, "openai_api_key", "nim-key")
    monkeypatch.setattr(settings, "residency_mode", "external")
    dim = settings.qdrant_dense_size
    capture: dict = {}
    monkeypatch.setattr(
        httpx, "AsyncClient",
        _fake_client(capture, {"data": [{"embedding": _dim_vec(dim)}]}),
    )

    await E.embed_dense(["only"])

    assert capture["url"] == "https://nim.internal/v1/embeddings"
    assert capture["headers"]["Authorization"] == "Bearer nim-key"


async def test_api_mode_dimension_mismatch_raises(monkeypatch):
    """A served vector whose length != qdrant_dense_size fails loud (mis-sized model)."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "https://emb.internal/v1")
    monkeypatch.setattr(settings, "residency_mode", "external")
    bad = settings.qdrant_dense_size - 1
    monkeypatch.setattr(
        httpx, "AsyncClient",
        _fake_client({}, {"data": [{"embedding": _dim_vec(bad)}]}),
    )
    with pytest.raises(RuntimeError, match="dim"):
        await E.embed_dense(["x"])


async def test_api_mode_unexpected_shape_raises(monkeypatch):
    """A non-OpenAI response shape raises a clear RuntimeError rather than a KeyError."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "https://emb.internal/v1")
    monkeypatch.setattr(settings, "residency_mode", "external")
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client({}, {"unexpected": []}))
    with pytest.raises(RuntimeError, match="unexpected shape"):
        await E.embed_dense(["x"])


# ── api mode: residency + SSRF guards (reused from the RaaS path) ──────────────

async def test_api_mode_local_residency_external_base_raises(monkeypatch):
    """residency_mode=local refuses an external embedding base (text must stay in-boundary)."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "https://public.example.com/v1")
    monkeypatch.setattr(settings, "residency_mode", "local")
    # Guard must trip BEFORE any HTTP call; fail the test if a POST is attempted.
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client({}, {"data": []}))
    with pytest.raises(RuntimeError):
        await E.embed_dense(["x"])


async def test_api_mode_local_residency_inboundary_base_allowed(monkeypatch):
    """An in-boundary (k8s service-DNS) embedding base is permitted even in local mode."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "http://emb.svc.cluster.local:8000/v1")
    monkeypatch.setattr(settings, "residency_mode", "local")
    dim = settings.qdrant_dense_size
    capture: dict = {}
    monkeypatch.setattr(
        httpx, "AsyncClient",
        _fake_client(capture, {"data": [{"embedding": _dim_vec(dim)}]}),
    )
    out = await E.embed_dense(["x"])  # must not raise
    assert capture["url"] == "http://emb.svc.cluster.local:8000/v1/embeddings"
    assert len(out) == 1


async def test_api_mode_refuses_cloud_metadata_ip_in_external_mode(monkeypatch):
    """The cloud-metadata IP is ALWAYS refused (SSRF denylist) — even in external mode,
    where the residency guard is a no-op. Reuses the RaaS _is_egress_unsafe_raas_host guard."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "embedding_api_base", "http://169.254.169.254/latest/v1")
    monkeypatch.setattr(settings, "residency_mode", "external")  # residency guard off
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client({}, {"data": []}))
    with pytest.raises(RuntimeError):
        await E.embed_dense(["x"])


async def test_api_mode_refuses_loopback_by_name(monkeypatch):
    """`localhost` is the same loopback target `127.0.0.1` is refused for — refused too
    (previously a bypass of the SSRF denylist by spelling the host as a name)."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(settings, "residency_mode", "external")
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client({}, {"data": []}))
    for base in ("http://localhost:4000/v1", "http://127.0.0.1:4000/v1"):
        monkeypatch.setattr(settings, "embedding_api_base", base)
        with pytest.raises(RuntimeError, match="SSRF"):
            await E.embed_dense(["x"])


# ── local mode (FastEmbed singleton monkeypatched — no model download) ─────────

class _FakeVec:
    """Stand-in for a numpy array with .tolist() (what FastEmbed yields)."""

    def __init__(self, data):
        self._data = data

    def tolist(self):
        return list(self._data)


class _FakeLocalModel:
    def __init__(self, dim: int):
        self._dim = dim
        self.calls: list[list[str]] = []

    def embed(self, texts):
        self.calls.append(list(texts))
        for _ in texts:
            yield _FakeVec([0.5] * self._dim)


async def test_local_mode_uses_cached_fastembed_singleton(monkeypatch):
    """local mode returns .tolist() vectors from the FastEmbed model run off-loop."""
    monkeypatch.setattr(settings, "embedding_provider", "local")
    dim = settings.qdrant_dense_size
    fake = _FakeLocalModel(dim)
    # Monkeypatch the module singleton so no ONNX model is loaded / downloaded.
    monkeypatch.setattr(E, "_local_dense_model", fake)

    out = await E.embed_dense(["a", "b"])

    assert fake.calls == [["a", "b"]]
    assert out == [[0.5] * dim, [0.5] * dim]


async def test_empty_input_short_circuits(monkeypatch):
    """No texts -> no provider call, empty result."""
    monkeypatch.setattr(settings, "embedding_provider", "api")
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client({}, {"data": []}))
    assert await E.embed_dense([]) == []
