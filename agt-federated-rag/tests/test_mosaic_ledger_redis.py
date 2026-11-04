"""Shared (Redis) mosaic release ledger: multi-replica visibility, expiry, fail-closed.

Hermetic: a minimal in-memory stand-in for the redis.asyncio commands the ledger uses
(LRANGE + a transactional RPUSH/LTRIM/EXPIRE pipeline). Two ``RedisReleaseLedger``
instances pointed at ONE store model two replicas of the same division behind an HPA.
The live proof against a real Redis is in PROJECT_STATUS / the change's report.
"""
from __future__ import annotations

import json

import pytest

from agent import context_guard as cg

BETA_DID = "did:mesh:beta-test"
HR = cg.Contribution(origin=cg.LOCAL_ORIGIN, division="alpha", labels=frozenset({"hr"}),
                     sources=("hr_compensation_data.txt",))
FIN = cg.Contribution(origin=BETA_DID, division="beta", labels=frozenset({"financial"}))


class _Store:
    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}
        self.ttl: dict[str, int] = {}
        self.calls = 0
        self.down = False


class _Pipe:
    def __init__(self, r: "_FakeRedis") -> None:
        self._r, self._ops = r, []

    def rpush(self, k, v): self._ops.append(("rpush", k, v))
    def ltrim(self, k, a, b): self._ops.append(("ltrim", k, a, b))
    def expire(self, k, s): self._ops.append(("expire", k, s))

    async def execute(self):
        st = self._r.store
        st.calls += 1
        if st.down:
            raise ConnectionError("Error 111 connecting to redis:6379. Connection refused.")
        for op, k, *a in self._ops:
            if op == "rpush":
                st.lists.setdefault(k, []).append(a[0])
            elif op == "ltrim":
                lst = st.lists.get(k, [])
                st.lists[k] = lst[a[0]:] if a[1] == -1 else lst[a[0]:a[1] + 1]
            else:
                st.ttl[k] = a[0]
        return [True] * len(self._ops)


class _FakeRedis:
    """One client per replica; replicas share the ``_Store`` (the division's Redis)."""

    def __init__(self, store: _Store) -> None:
        self.store = store

    async def lrange(self, k, a, b):
        self.store.calls += 1
        if self.store.down:
            raise ConnectionError("Error 111 connecting to redis:6379. Connection refused.")
        return list(self.store.lists.get(k, []))

    def pipeline(self, transaction=True):
        return _Pipe(self)


def _replicas(store: _Store, n: int = 2, division: str = "alpha"):
    return [cg.RedisReleaseLedger("redis://unused", division, client=_FakeRedis(store))
            for _ in range(n)]


async def test_two_replicas_share_one_view():
    store = _Store()
    a, b = _replicas(store)
    assert await a.arecord("alice|ns", HR, 900, now=1000.0)          # HR via replica A
    assert await b.arecord("alice|ns", FIN, 900, now=1001.0)         # Finance via replica B
    # Each replica sees the OTHER replica's release from the other origin.
    assert await b.aothers("alice|ns", BETA_DID, 900, now=1002.0) == [HR]
    assert await a.aothers("alice|ns", cg.LOCAL_ORIGIN, 900, now=1002.0) == [FIN]
    assert await a.aothers("bob|ns", BETA_DID, 900, now=1002.0) == []
    # Key per division + principal, TTL = window, provenance only.
    assert set(store.lists) == {"agt:mosaic:alpha:alice|ns"}
    assert store.ttl["agt:mosaic:alpha:alice|ns"] == 900
    row = json.loads(store.lists["agt:mosaic:alpha:alice|ns"][0])
    assert set(row) == {"ts", "origin", "division", "labels", "sources", "verified"}
    assert row["labels"] == ["hr"] and row["sources"] == ["hr_compensation_data.txt"]


async def test_replica_split_mosaic_is_caught_by_the_guard():
    """The bypass this fixes: HR from replica A, Finance from replica B → still escalates."""
    store = _Store()
    a, b = _replicas(store)
    cfg = cg.load_config(str(cg._PKG_ROOT / "agent" / "policies" / "aggregation"
                             / "context-aggregation.yaml"))
    await a.arecord("alice|ns", HR, cfg.window_seconds)
    d = cg.evaluate_combined([], [FIN] + await b.aothers("alice|ns", BETA_DID,
                                                         cfg.window_seconds), cfg)
    assert d.outcome == cg.Outcome.ESCALATE
    assert d.clearance_ids == ("mosaic-hr-finance",)


async def test_division_isolation_and_bound():
    store = _Store()
    (a,) = _replicas(store, 1, "alpha")
    (g,) = _replicas(store, 1, "gamma")
    await a.arecord("u", HR, 900, now=1.0)
    assert await g.aothers("u", BETA_DID, 900, now=2.0) == []        # other division's key
    for i in range(100):
        await a.arecord("u", FIN, 900, now=float(i))
    assert len(store.lists["agt:mosaic:alpha:u"]) == cg.RedisReleaseLedger._MAX_PER_USER


async def test_window_filter_on_read():
    store = _Store()
    a, b = _replicas(store)
    await a.arecord("u", HR, 900, now=1000.0)
    assert await b.aothers("u", BETA_DID, 900, now=1900.0) == [HR]   # edge of window
    assert await b.aothers("u", BETA_DID, 900, now=1901.0) == []     # expired
    assert await b.aothers("u", BETA_DID, 60, now=1100.0) == []      # shorter window


async def test_window_zero_never_touches_redis():
    store = _Store()
    store.down = True                                                # would raise if touched
    (a,) = _replicas(store, 1)
    assert await a.aothers("u", BETA_DID, 0) == []
    assert await a.arecord("u", HR, 0) is False
    assert store.calls == 0


async def test_redis_down_read_raises_write_is_logged_not_raised():
    store = _Store()
    store.down = True
    (a,) = _replicas(store, 1)
    with pytest.raises(cg.LedgerUnavailableError):
        await a.aothers("u", BETA_DID, 900)
    assert await a.arecord("u", HR, 900) is False                    # no exception


def test_fail_closed_rewrite():
    cfg = cg.load_config(str(cg._PKG_ROOT / "agent" / "policies" / "aggregation"
                             / "context-aggregation.yaml"))
    alone = cg.evaluate_combined([], [FIN], cfg)
    assert alone.outcome == cg.Outcome.ALLOW                         # Finance alone is fine
    d = cg.fail_closed_ledger_unavailable(alone)
    assert d.outcome == cg.Outcome.ESCALATE and d.reason == "ledger_unavailable:escalate"
    assert d.clearance_ids == (cg.ledger_unavailable_clearance_id({"financial"}),)
    assert any("ledger store unreachable" in s for s in d.sources)
    nolabel = cg.GuardDecision(cg.Outcome.ALLOW, "ok")
    assert cg.fail_closed_ledger_unavailable(nolabel) is nolabel     # nothing to combine
    deny = cg.GuardDecision(cg.Outcome.DENY, "rule:x", labels=frozenset({"hr"}))
    assert cg.fail_closed_ledger_unavailable(deny) is deny


# ── Through the real guard (nodes): replicas + outage ─────────────────────────

class _Auth:
    def __init__(self, cleared=frozenset()):
        self.cleared = set(cleared)

    async def batch_decide(self, user, ids, groups=None):
        from auth.openfga import AuthzDecision
        return {i: (AuthzDecision.ALLOWED if i in self.cleared else AuthzDecision.DENIED)
                for i in ids}


def _peer_state():
    return {"query": "q", "user_id": "alice|ns", "task_id": "t", "fused_chunks": [],
            "allowed_chunk_ids": [], "pending_chunk_ids": [], "user_groups": [],
            "peer_status": "completed", "peer_answer": "Q4 revenue $4.2M",
            "peer_did": BETA_DID, "peer_division": "beta", "peer_data_labels": ["financial"],
            "peer_labels_verified": True, "check_only": False}


def _use_redis(monkeypatch, store, auth=None):
    from agent import nodes
    from config import settings
    monkeypatch.setattr(settings, "mosaic_ledger_backend", "redis")
    monkeypatch.setattr(cg, "_REDIS_LEDGERS", {})
    real = cg.RedisReleaseLedger

    def _factory(url, division, **kw):          # each call = a fresh "replica" client
        return real(url, division, client=_FakeRedis(store))
    monkeypatch.setattr(cg, "RedisReleaseLedger", _factory)

    async def _fga():
        return auth or _Auth()
    monkeypatch.setattr(nodes, "_get_openfga", _fga)
    return nodes


HR_CHUNK = {"chunk_id": "hr1", "metadata": {"source": "hr_compensation_data.txt"}}
PLAIN_CHUNK = {"chunk_id": "p1", "metadata": {"source": "bias_testing_requirements.txt"}}


async def test_nodes_guard_replica_split_escalates(monkeypatch):
    from agent.state import FlowDecision
    from config import settings
    store = _Store()
    nodes = _use_redis(monkeypatch, store)
    key = f"agt:mosaic:{settings.division_id}:alice|ns"
    # Replica A: HR released locally (allowed alone) → recorded in the SHARED ledger.
    out = await nodes._guard_context_combination(
        {"user_id": "alice|ns", "task_id": "t1"}, _Auth(), ["hr1"], [HR_CHUNK])
    assert out is None and len(store.lists[key]) == 1
    cg._REDIS_LEDGERS.clear()                                        # replica B: new client
    out = await nodes._guard_peer_answer(_peer_state())
    assert out["flow"] == FlowDecision.LOCAL_NEEDS_APPROVAL
    assert out["pending_chunk_ids"] == ["mosaic-hr-finance"]
    assert out["answer"] is None and out["peer_answer"] is None


async def test_nodes_guard_redis_down_fails_closed(monkeypatch):
    from agent.state import FlowDecision
    store = _Store()
    store.down = True
    nodes = _use_redis(monkeypatch, store)
    out = await nodes._guard_peer_answer(_peer_state())
    assert out["flow"] == FlowDecision.LOCAL_NEEDS_APPROVAL          # NOT released
    assert out["pending_chunk_ids"] == [cg.ledger_unavailable_clearance_id({"financial"})]
    assert out["answer"] is None and out["peer_answer"] is None
    # Unlabelled local context has nothing to combine: still flows.
    assert await nodes._guard_context_combination(
        {"user_id": "alice|ns", "task_id": "t2"}, _Auth(), ["p1"], [PLAIN_CHUNK]) is None
    # A label-set clearance (approved) lets that release through; the failed write is
    # logged, not raised.
    cleared = _Auth({cg.ledger_unavailable_clearance_id({"hr"})})
    assert await nodes._guard_context_combination(
        {"user_id": "alice|ns", "task_id": "t3"}, cleared, ["hr1"], [HR_CHUNK]) is None
