"""Regression tests for the four defects surfaced by the agile-team review.

1. Embedder-aware score threshold — api mode must not inherit the bge-tuned 0.55 default
   (which silently drops every nv-embedqa hit → empty answers).
2. Rate limiter must DEGRADE (in-process) on a Redis error, not fail OPEN.
3. The per-peer federation rate limit is enforceable with a custom limit/prefix.
4. The replay-nonce guard uses a SHARED store (cross-replica) and degrades to in-process
   only when Redis is down.
"""
from __future__ import annotations

import time

import pytest

from config import Settings


# ── 1. Embedder-aware score threshold ───────────────────────────────────────────────────
def test_api_mode_lowers_default_score_threshold():
    s = Settings(embedding_provider="api")
    assert s.qdrant_score_threshold == 0.25, "api mode must drop the bge 0.55 default to 0.25"


def test_api_mode_honors_explicit_threshold():
    s = Settings(embedding_provider="api", qdrant_score_threshold=0.5)
    assert s.qdrant_score_threshold == 0.5, "an explicit threshold must be honored in api mode"


def test_local_mode_keeps_bge_default():
    s = Settings(embedding_provider="local")
    assert s.qdrant_score_threshold == 0.55, "local (bge) mode keeps its tuned default"


# ── 2. Rate limiter degrades, not fail-open ─────────────────────────────────────────────
@pytest.mark.asyncio
async def test_rate_limit_degrades_to_local_when_redis_down(monkeypatch):
    import api.main as m

    async def _boom():
        raise RuntimeError("redis unreachable")

    monkeypatch.setattr(m, "_get_redis", _boom)
    m._local_rl_counts.clear()
    subject = "degrade-subject"
    # cap=3: first three pass, the fourth must be blocked locally (NOT allowed through).
    for _ in range(3):
        await m._check_rate_limit(subject, limit=3, prefix="testlimit")
    with pytest.raises(m.HTTPException) as ei:
        await m._check_rate_limit(subject, limit=3, prefix="testlimit")
    assert ei.value.status_code == 429


@pytest.mark.asyncio
async def test_peer_limit_uses_separate_namespace(monkeypatch):
    import api.main as m

    async def _boom():
        raise RuntimeError("redis unreachable")

    monkeypatch.setattr(m, "_get_redis", _boom)
    m._local_rl_counts.clear()
    # Same subject, different prefixes → independent budgets (user vs peer don't collide).
    await m._check_rate_limit("did:mesh:x", limit=1, prefix="peerlimit")
    await m._check_rate_limit("did:mesh:x", limit=1, prefix="ratelimit")  # different bucket, ok
    with pytest.raises(m.HTTPException):
        await m._check_rate_limit("did:mesh:x", limit=1, prefix="peerlimit")  # peer bucket full


# ── 3 & 4. Shared replay-nonce store ────────────────────────────────────────────────────
class _FakeRedis:
    """Minimal Redis stand-in implementing SET ... NX EX semantics."""

    def __init__(self) -> None:
        self.keys: set[str] = set()

    async def set(self, key, value, nx=False, ex=None):  # noqa: ANN001
        if nx and key in self.keys:
            return None          # key exists → NX fails (replay)
        self.keys.add(key)
        return True


@pytest.mark.asyncio
async def test_shared_nonce_store_detects_cross_replica_replay(monkeypatch):
    import mesh.agent_identity as ai

    fake = _FakeRedis()
    monkeypatch.setattr(ai, "_redis", fake)  # _get_redis returns this shared fake

    did, nonce = "did:mesh:peerA", "nonce-shared-1"
    assert await ai._seen_nonce_redis(did, nonce) is True, "first sighting is fresh"
    # A DIFFERENT replica (same shared store) sees the SAME nonce again → replay.
    assert await ai._seen_nonce_redis(did, nonce) is False, "replay detected via shared store"


@pytest.mark.asyncio
async def test_nonce_guard_degrades_to_inprocess_when_redis_down(monkeypatch):
    import mesh.agent_identity as ai

    async def _boom():
        raise RuntimeError("redis unreachable")

    monkeypatch.setattr(ai, "_get_redis", _boom)
    ai._seen_nonces.clear()
    payload = {"ts": int(time.time()), "nonce": "nonce-fallback-1"}
    did = "did:mesh:peerB"
    # Redis down → _seen_nonce_redis returns None → the in-process guard still works.
    assert await ai._check_freshness_and_nonce(payload, did) is True, "first is accepted"
    assert await ai._check_freshness_and_nonce(payload, did) is False, "replay caught in-process"
