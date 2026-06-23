"""Pluggable reranker — disabled by default, provider selection, reorder contract, degrade."""
from __future__ import annotations

import pytest

import rag.rerank as RR
from config import settings


@pytest.fixture(autouse=True)
def _reset():
    RR.reset_reranker()
    yield
    RR.reset_reranker()


def test_disabled_by_default(monkeypatch):
    monkeypatch.setattr(settings, "reranker_provider", "none")
    assert RR.get_reranker() is None


def test_api_provider_selected_without_network(monkeypatch):
    # _ApiReranker.__init__ only reads config (no network), so selection is testable offline.
    monkeypatch.setattr(settings, "reranker_provider", "api")
    rr = RR.get_reranker()
    assert rr is not None and rr.name == "api"
    assert RR.get_reranker() is rr           # cached


def test_init_failure_disables_not_crashes(monkeypatch):
    monkeypatch.setattr(settings, "reranker_provider", "local")  # FastEmbed cross-encoder absent in test
    # A missing/broken backend must degrade to None, never raise out of get_reranker().
    assert RR.get_reranker() is None


@pytest.mark.asyncio
async def test_reranker_reorders_and_truncates():
    class _Fake:
        name = "fake"

        async def rerank(self, query, chunks, top_k):
            # pretend relevance is reverse of input order
            return list(reversed(chunks))[:top_k]

    chunks = [{"text": f"c{i}", "chunk_id": str(i)} for i in range(5)]
    out = await _Fake().rerank("q", chunks, 2)
    assert [c["text"] for c in out] == ["c4", "c3"]


@pytest.mark.asyncio
async def test_api_reranker_uses_endpoint_ranking(monkeypatch):
    monkeypatch.setattr(settings, "reranker_provider", "api")
    monkeypatch.setattr(settings, "reranker_api_base", "http://rr.local")
    rr = RR.get_reranker()

    class _Resp:
        def raise_for_status(self): ...
        def json(self): return {"rankings": [{"index": 2}, {"index": 0}, {"index": 1}]}

    class _Client:
        def __init__(self, *a, **k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return _Resp()

    monkeypatch.setattr("httpx.AsyncClient", _Client)
    chunks = [{"text": "a"}, {"text": "b"}, {"text": "c"}]
    out = await rr.rerank("q", chunks, top_k=2)
    assert [c["text"] for c in out] == ["c", "a"], "reordered by the endpoint's rankings, top_k=2"
