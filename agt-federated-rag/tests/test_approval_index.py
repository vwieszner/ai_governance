"""Redis-backed approval-inbox index tests (inbox reliability fix).

Pins: a recorded request appears in the approver's list and not in another approver's;
remove() drops it; failures are swallowed (inbox indexing must never break approvals).
"""
from __future__ import annotations

import asyncio


class _FakeRedis:
    def __init__(self): self.h = {}
    async def hset(self, key, field, val): self.h.setdefault(key, {})[field] = val
    async def hgetall(self, key): return dict(self.h.get(key, {}))
    async def hdel(self, key, field): self.h.get(key, {}).pop(field, None)
    async def expire(self, key, ttl): pass


def _patch(monkeypatch):
    import approval_index
    fake = _FakeRedis()
    async def get(): return fake
    monkeypatch.setattr(approval_index, "_get_redis", get)
    return approval_index


def test_record_then_list_for_approver(monkeypatch):
    ai = _patch(monkeypatch)
    asyncio.run(ai.record("bob@x|ns", "req-1", "alice@y|ns", "what is q4 revenue?"))
    items = asyncio.run(ai.list_for("bob@x|ns"))
    assert len(items) == 1
    assert items[0]["request_id"] == "req-1"
    assert items[0]["requester_id"] == "alice@y|ns"
    assert items[0]["query"] == "what is q4 revenue?"


def test_record_carries_contributing_sources(monkeypatch):
    # A mosaic clearance has no chunk metadata: the inbox entry carries the contributing
    # source names / labels so the approver isn't approving blind. Old callers → [].
    ai = _patch(monkeypatch)
    srcs = ["alpha: hr_compensation_data.txt [hr]", "peer beta (did:mesh:b): [financial]"]
    asyncio.run(ai.record("bob@x|ns", "req-m", "alice@y|ns", "pay vs revenue?", sources=srcs))
    asyncio.run(ai.record("bob@x|ns", "req-o", "alice@y|ns", "q"))
    by_id = {i["request_id"]: i for i in asyncio.run(ai.list_for("bob@x|ns"))}
    assert by_id["req-m"]["sources"] == srcs
    assert by_id["req-o"]["sources"] == []


def test_other_approver_sees_nothing(monkeypatch):
    ai = _patch(monkeypatch)
    asyncio.run(ai.record("bob@x|ns", "req-1", "alice@y|ns", "q"))
    assert asyncio.run(ai.list_for("carol@x|ns")) == []


def test_remove_drops_from_inbox(monkeypatch):
    ai = _patch(monkeypatch)
    asyncio.run(ai.record("bob@x|ns", "req-1", "alice@y|ns", "q"))
    asyncio.run(ai.remove("bob@x|ns", "req-1"))
    assert asyncio.run(ai.list_for("bob@x|ns")) == []


def test_record_failure_is_swallowed(monkeypatch):
    import approval_index
    async def boom():
        raise RuntimeError("redis down")
    monkeypatch.setattr(approval_index, "_get_redis", boom)
    # must not raise — approval workflow start cannot be broken by an index failure
    asyncio.run(approval_index.record("bob@x|ns", "r", "a", "q"))
    assert asyncio.run(approval_index.list_for("bob@x|ns")) == []
