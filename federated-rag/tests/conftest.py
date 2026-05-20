"""Shared pytest fixtures for all flow tests.

Fixes applied:
  M-6  — mock_openfga_allowed.batch_decide now returns a dict with ALLOWED
          decisions for each chunk_id that is passed in, instead of returning
          an empty dict {}.  The previous empty return caused check_auth to
          classify zero chunks as ALLOWED, routing Flow A to LOCAL_DENIED.
  T-3  — API fixtures use httpx.AsyncClient with ASGITransport for async-safe
          test client instead of starlette's synchronous TestClient.
  M3-6 — session-scoped event_loop fixture removed (deprecated/removed in
          pytest-asyncio >= 0.21 / 0.23).  asyncio_mode = "auto" and
          asyncio_default_fixture_loop_scope = "session" are set in
          pyproject.toml instead, which is the correct way to share one loop
          across all async tests.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Test users ─────────────────────────────────────────────────────────────────

@pytest.fixture
def alice_user_id() -> str:
    return "alice"


@pytest.fixture
def alice_token() -> str:
    """Fake JWT — token validation is mocked in all tests."""
    return "eyJ.fake.alice"


@pytest.fixture
def alice_claims(alice_user_id: str) -> dict:
    return {"sub": alice_user_id, "email": "alice@example.com"}


# ── Mock: OpenFGA ──────────────────────────────────────────────────────────────

@pytest.fixture
def mock_openfga_allowed():
    """
    OpenFGA always returns ALLOWED.

    FIX M-6: batch_decide must return a non-empty dict so check_auth sets
    allowed_chunk_ids correctly and routes to LOCAL_ALLOWED.
    """
    from auth.openfga import AuthzDecision
    with patch("agent.nodes._get_openfga") as mock:
        auth = AsyncMock()
        # M-6 FIX: return ALLOWED for every chunk_id passed in
        auth.batch_decide = AsyncMock(
            side_effect=lambda uid, cids: {c: AuthzDecision.ALLOWED for c in cids}
        )
        auth.decide = AsyncMock(return_value=AuthzDecision.ALLOWED)
        auth.get_allowed_chunks = AsyncMock(side_effect=lambda uid, cids: cids)
        auth.get_chunk_owner = AsyncMock(return_value="bob")
        mock.return_value = auth
        yield auth


@pytest.fixture
def mock_openfga_needs_approval():
    """OpenFGA returns NEEDS_APPROVAL for all chunks."""
    from auth.openfga import AuthzDecision
    with patch("agent.nodes._get_openfga") as mock:
        auth = AsyncMock()
        auth.batch_decide = AsyncMock(
            side_effect=lambda uid, cids: {c: AuthzDecision.NEEDS_APPROVAL for c in cids}
        )
        auth.decide = AsyncMock(return_value=AuthzDecision.NEEDS_APPROVAL)
        auth.get_allowed_chunks = AsyncMock(return_value=[])
        auth.get_chunk_owner = AsyncMock(return_value="bob")
        auth.set_pending_approval = AsyncMock()
        auth.grant_viewer = AsyncMock()
        auth.revoke_pending_approval = AsyncMock()
        mock.return_value = auth
        yield auth


@pytest.fixture
def mock_openfga_denied():
    """OpenFGA returns DENIED (triggers remote lookup)."""
    from auth.openfga import AuthzDecision
    with patch("agent.nodes._get_openfga") as mock:
        auth = AsyncMock()
        auth.batch_decide = AsyncMock(
            side_effect=lambda uid, cids: {c: AuthzDecision.DENIED for c in cids}
        )
        auth.decide = AsyncMock(return_value=AuthzDecision.DENIED)
        auth.get_allowed_chunks = AsyncMock(return_value=[])
        mock.return_value = auth
        yield auth


# ── Mock: Qdrant + Neo4j ───────────────────────────────────────────────────────

@pytest.fixture
def mock_rag_results():
    """Returns plausible RAG results for any query."""
    sample_chunks = [
        {
            "chunk_id": f"chunk-{i:04d}",
            "text": f"Sample content chunk {i}. This contains relevant information about the query topic.",
            "metadata": {"source": "test_doc.txt", "chunk_index": i},
            "score": 0.9 - i * 0.05,
        }
        for i in range(5)
    ]
    with patch("agent.nodes._get_qdrant") as mock_q, \
         patch("agent.nodes._get_graph") as mock_g:
        qdrant = AsyncMock()
        qdrant.retrieve = AsyncMock(return_value=sample_chunks)
        graph = AsyncMock()
        graph.retrieve_context = AsyncMock(return_value=sample_chunks[:2])
        mock_q.return_value = qdrant
        mock_g.return_value = graph
        yield sample_chunks


# ── Mock: LLM ─────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_llm():
    with patch("agent.nodes._get_llm") as mock:
        llm = AsyncMock()
        response = MagicMock()
        response.content = "This is a generated answer based on the context provided."
        llm.ainvoke = AsyncMock(return_value=response)
        mock.return_value = llm
        yield llm


# ── Mock: token validation ─────────────────────────────────────────────────────

@pytest.fixture
def mock_token_validation(alice_claims: dict):
    with patch("auth.token_exchange.validate_token", new_callable=AsyncMock) as mock:
        mock.return_value = alice_claims
        yield mock


# ── Mock: Temporal ────────────────────────────────────────────────────────────

@pytest.fixture
def mock_temporal():
    """Patches the Temporal singleton in agent.nodes so no real connection is made."""
    with patch("agent.nodes._get_temporal", new_callable=AsyncMock) as mock_get:
        client = AsyncMock()
        client.start_workflow = AsyncMock(return_value=AsyncMock())
        mock_get.return_value = client
        yield client


# ── T-3: Async HTTP client for API tests ──────────────────────────────────────

@pytest.fixture
async def async_client():
    """
    T-3 FIX: httpx.AsyncClient with ASGITransport instead of starlette's
    synchronous TestClient, which can deadlock in async test contexts.
    """
    import httpx
    from httpx import ASGITransport
    from api.main import app

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client
