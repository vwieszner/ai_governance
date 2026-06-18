"""NFR-6 bounded-lookup proving tests.

NFR-6 requires that the hot inbox lookup stay BOUNDED — independent of how many open
approvals exist — so the approver inbox can't degrade under load. The Redis-backed
approval index (approval_index.py) replaced the old O(open-requests) Temporal visibility
scan with a single point read keyed by (division, approver). These tests pin that the
read shape does NOT grow with N: one Redis HGETALL against one key, whatever the inbox
size.

The discovery registry's lookup is, by contrast, an in-memory linear scan (not a bounded
point read), so that case is skipped with a documented reason rather than asserted falsely.

Hermetic: a counting fake Redis records the number/shape of calls; no live Redis.
"""
from __future__ import annotations

import pytest


class _CountingRedis:
    """Fake aioredis that counts the read calls and records the keys touched."""

    def __init__(self) -> None:
        self.h: dict[str, dict] = {}
        self.hgetall_calls = 0
        self.hset_calls = 0
        self.keys_read: set[str] = set()

    async def hset(self, key, field, val):
        self.hset_calls += 1
        self.h.setdefault(key, {})[field] = val

    async def hgetall(self, key):
        self.hgetall_calls += 1
        self.keys_read.add(key)
        return dict(self.h.get(key, {}))

    async def hdel(self, key, field):
        self.h.get(key, {}).pop(field, None)

    async def expire(self, key, ttl):
        pass


def _patch(monkeypatch) -> tuple:
    import approval_index

    fake = _CountingRedis()

    async def _get():
        return fake

    monkeypatch.setattr(approval_index, "_get_redis", _get)
    return approval_index, fake


async def test_inbox_lookup_bounded(monkeypatch):
    """list_for() is a single O(1)-shaped point read regardless of the inbox size.

    Record a LARGE number of pending requests for one approver, then read the inbox: the
    lookup must issue exactly ONE HGETALL against exactly ONE key — it does not scan, page,
    or fan out per open request. (HGETALL returns the whole hash in one round trip; the
    point being proven is that the number of Redis OPERATIONS for the lookup is constant in
    the number of open approvals, which is the NFR-6 guarantee.)
    """
    from config import settings

    ai, fake = _patch(monkeypatch)
    approver = "bob@example.com|alpha"

    n = 250
    for i in range(n):
        await ai.record(approver, f"req-{i}", "alice@example.com|alpha", "what is q4 revenue?")

    items = await ai.list_for(approver)

    assert len(items) == n                       # all entries are returned …
    assert fake.hgetall_calls == 1               # … in exactly one point read …
    assert fake.keys_read == {                   # … against one (division, approver) key.
        f"approvals:pending:{settings.division_id}:{approver}"
    }


async def test_inbox_lookup_constant_across_sizes(monkeypatch):
    """The read shape is the SAME whether the inbox holds 1 or many entries.

    Two reads — one over a 1-entry inbox, one over a 100-entry inbox — must each cost a
    single HGETALL. This pins that lookup cost is decoupled from N (no per-entry call grows
    the read).
    """
    ai, fake = _patch(monkeypatch)

    await ai.record("small@example.com|alpha", "r0", "alice@example.com|alpha", "q")
    await ai.list_for("small@example.com|alpha")
    calls_after_small = fake.hgetall_calls
    assert calls_after_small == 1

    for i in range(100):
        await ai.record("big@example.com|alpha", f"r{i}", "alice@example.com|alpha", "q")
    await ai.list_for("big@example.com|alpha")
    # The second lookup adds exactly ONE more read — not one-per-entry.
    assert fake.hgetall_calls == calls_after_small + 1


def test_discovery_lookup_bounded():
    """Discovery capability lookup is an in-memory LINEAR scan, not a bounded point read.

    discovery.registry.DiscoveryRegistry.find() iterates over every live entry
    (``_live()`` filters the full dict, then filters again by capability), so its cost is
    O(registered peers). That is acceptable for a control-plane registry of a handful of
    federation partners, but it is NOT the NFR-6 bounded-lookup control — the bounded
    hot-path lookup is the Redis approval index proved above. Skipped rather than asserting
    a bound the code does not provide.
    """
    pytest.skip(
        "discovery.registry.find() is an O(N) in-memory scan over live entries, not a "
        "bounded point read; NFR-6 bounded lookup is the Redis approval index "
        "(test_inbox_lookup_bounded)."
    )
