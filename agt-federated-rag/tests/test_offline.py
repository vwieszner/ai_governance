"""FR-6 — offline, account-bound delivery of the approval outcome (the PRD headline).

These hermetic unit tests pin the durable per-user outcome inbox + the GET /inbox
regenerate-at-delivery path + cross-division delivery, without live Redis / OpenFGA /
pipeline. A fake async Redis backs outcome_store; the governed pipeline (run_query) and
the bearer/principal dependencies are stubbed exactly as the existing suite does
(cf. test_approval_index, test_killswitch, test_approval_poll).

Covered (plan-named):
  * test_outcome_durable_when_offline       — the record exists with NO open tab / poll
  * test_retrievable_next_login_no_ttl_cap  — long retention, no short TTL
  * test_declined_message                   — denial delivers a clear "declined" message
  * test_regenerated_at_delivery            — /inbox re-runs the pipeline / re-checks authz
  * test_cross_division_delivery            — peer callback writes the REQUESTER's store
"""
from __future__ import annotations

import asyncio
import json

import outcome_store
from api import main


# ── Fake async Redis (hash + string ops used by outcome_store) ─────────────────

class _FakeRedis:
    def __init__(self) -> None:
        self.h: dict[str, dict] = {}      # hashes (inbox)
        self.kv: dict[str, str] = {}      # strings (badge)
        self.ttls: dict[str, int] = {}    # last expire() seconds per key

    async def hset(self, key, field, val):
        self.h.setdefault(key, {})[field] = val

    async def hget(self, key, field):
        return self.h.get(key, {}).get(field)

    async def hgetall(self, key):
        return dict(self.h.get(key, {}))

    async def hdel(self, key, field):
        self.h.get(key, {}).pop(field, None)

    async def expire(self, key, ttl):
        self.ttls[key] = ttl

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, val):
        self.kv[key] = val

    async def incr(self, key):
        self.kv[key] = str(int(self.kv.get(key, 0)) + 1)
        return int(self.kv[key])

    async def decr(self, key):
        self.kv[key] = str(int(self.kv.get(key, 0)) - 1)
        return int(self.kv[key])

    async def setex(self, key, ttl, val):
        self.kv[key] = val
        self.ttls[key] = ttl


def _patch_store_redis(monkeypatch) -> _FakeRedis:
    """Point BOTH outcome_store and api.main's redis getters at one fake instance."""
    fake = _FakeRedis()

    async def _get():
        return fake

    monkeypatch.setattr(outcome_store, "_get_redis", _get)
    monkeypatch.setattr(outcome_store, "_redis", fake, raising=False)
    monkeypatch.setattr(main, "_get_redis", _get)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    return fake


_ALICE = "alice@example.com|aaaaaaaaaaaaaaaa"
_BOB = "bob@example.com|aaaaaaaaaaaaaaaa"
_CLAIMS = {"sub": "kc-uuid", "email": "alice@example.com", "email_verified": True,
           "iss": "http://localhost:9002/realms/rag"}


# ── 1. durable when offline (no poll, written directly, survives "no open tab") ─

def test_outcome_durable_when_offline(monkeypatch):
    """The outcome is written to the durable store WITHOUT any live poll, and is then
    retrievable by identity alone — i.e. it does not depend on an open tab/SSE stream."""
    _patch_store_redis(monkeypatch)

    # Write a parked outcome the way /query parking does — no client involved.
    asyncio.run(outcome_store.put(_ALICE, "task-1", "what is the q4 revenue?", "pending"))

    # Retrieve it later by identity only (the "next login" read).
    items = asyncio.run(outcome_store.list_outcomes(_ALICE))
    assert len(items) == 1
    assert items[0]["task_id"] == "task-1"
    assert items[0]["question"] == "what is the q4 revenue?"
    assert items[0]["status"] == "pending"
    assert items[0]["acknowledged"] is False

    # Another user does NOT see alice's outcome (per-principal isolation / IDOR safety).
    assert asyncio.run(outcome_store.list_outcomes(_BOB)) == []


# ── 2. retrievable next login, NO short TTL ────────────────────────────────────

def test_retrievable_next_login_no_ttl_cap(monkeypatch):
    """The retention floor is LONG (>> the approval window) and never a short TTL —
    so 'next login' can be days later. The TTL is (re)set on each write."""
    fake = _patch_store_redis(monkeypatch)

    asyncio.run(outcome_store.put(_ALICE, "task-1", "q", "pending"))

    key = outcome_store._key(_ALICE)
    assert key in fake.ttls
    # Far longer than the default 24h approval window — and equal to the module retention
    # constant, proving there is no short cap (the old 1h Redis TTL was the bug).
    assert fake.ttls[key] == outcome_store.OUTCOME_RETENTION_SECONDS
    assert outcome_store.OUTCOME_RETENTION_SECONDS >= 7 * 24 * 3600
    # Sanity: it is NOT the short task TTL that caused the original "offline → nothing" bug.
    assert outcome_store.OUTCOME_RETENTION_SECONDS > main.settings.task_ttl_seconds


# ── 3. denial → clear "declined" message (FR-6.3) ──────────────────────────────

def test_declined_message(monkeypatch):
    """A denial record with no question (terminal) delivers a clear declined message via
    GET /inbox, and never re-runs the pipeline (nothing to regenerate)."""
    _patch_store_redis(monkeypatch)

    # A denial outcome (as the cross-division callback writes one) — terminal, no question.
    asyncio.run(outcome_store.put(_ALICE, "task-9", "", "denied",
                                  answer_or_message="Access denied. Reason: policy."))

    async def boom_run_query(**kw):
        raise AssertionError("a terminal denial must NOT re-run the governed pipeline")

    monkeypatch.setattr(main.agent_graph, "run_query", boom_run_query)
    monkeypatch.setattr(main, "principal", lambda claims: _ALICE)

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    async def no_rl(subject):
        return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rl)

    resp = asyncio.run(main.inbox(authorization="Bearer tok"))
    body = json.loads(bytes(resp.body).decode())
    assert len(body["items"]) == 1
    it = body["items"][0]
    assert it["status"] == "denied"
    assert "denied" in it["message"].lower() or "declined" in it["message"].lower()


# ── 4. regenerate-at-delivery — /inbox re-runs the pipeline & re-checks authz ──

def test_regenerated_at_delivery(monkeypatch):
    """For a pending record carrying a question, GET /inbox RE-RUNS the governed pipeline
    (check_only) at delivery. A grant that is live → 'completed' with a freshly regenerated
    answer; the SAME record once authorization is revoked → 'declined' (no stale answer)."""
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "task-2", "what is the q4 revenue?", "pending"))

    monkeypatch.setattr(main, "principal", lambda claims: _ALICE)

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    async def no_rl(subject):
        return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rl)

    seen = {"check_only": None, "query": None, "user_id": None}

    # First delivery: authorization is GRANTED → pipeline returns an allowed answer.
    async def grant_run_query(**kw):
        seen["check_only"] = kw.get("check_only")
        seen["query"] = kw.get("query")
        seen["user_id"] = kw.get("user_id")
        return {"flow": "LOCAL_ALLOWED", "answer": "Q4 revenue was $42M."}
    monkeypatch.setattr(main.agent_graph, "run_query", grant_run_query)

    resp = asyncio.run(main.inbox(authorization="Bearer tok"))
    body = json.loads(bytes(resp.body).decode())
    it = body["items"][0]
    assert it["status"] == "completed"
    assert it["answer"] == "Q4 revenue was $42M."
    # Proves it actually went through the governed pipeline as a re-auth re-check.
    assert seen["check_only"] is True
    assert seen["query"] == "what is the q4 revenue?"
    assert seen["user_id"] == _ALICE

    # Second delivery: the grant has since been REVOKED → no access → declined, NOT a stale
    # answer. The same durable record now delivers a denial because authz is re-checked live.
    async def revoked_run_query(**kw):
        return {"flow": "LOCAL_DENIED", "answer": ""}
    monkeypatch.setattr(main.agent_graph, "run_query", revoked_run_query)

    resp2 = asyncio.run(main.inbox(authorization="Bearer tok"))
    body2 = json.loads(bytes(resp2.body).decode())
    it2 = body2["items"][0]
    assert it2["status"] == "denied"
    assert "answer" not in it2          # fail-closed: no stale answer leaked


# ── 5. cross-division delivery — peer callback writes the REQUESTER's store ────

def test_cross_division_delivery(monkeypatch):
    """An approval DECIDED in division B reaches alice's account in division A: the
    DID-verified peer callback (handled in alice's HOME division) writes the outcome to
    HER durable store, keyed by the original task's recorded requester principal, with the
    full question for regeneration at delivery."""
    fake = _patch_store_redis(monkeypatch)

    # The original /query task in alice's division recorded HER as the owner + the question,
    # and (since it federated to peer B) the delegate DID + federated flag the callback binds to.
    async def fake_load(task_id):
        assert task_id == "alice-task-7"
        return {"_owner_id": _ALICE, "query_full": "what does division B know about X?",
                "_federated": True, "_delegate_did": "did:peer:b"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        return None
    monkeypatch.setattr(main, "_update_task", fake_update)

    # Pass the DID signature / trust / policy gates (verified elsewhere — not under test).
    async def fake_verify_signed(payload):
        return (True, "did:peer:b")
    monkeypatch.setattr(main.agent_identity, "verify_signed_message", fake_verify_signed)

    async def fake_verify_peer(did):
        return (True, 0.99)
    monkeypatch.setattr(main.agent_identity, "verify_peer_identity", fake_verify_peer)
    monkeypatch.setattr(main.settings, "agent_trust_threshold", 0.5)

    async def fake_enforce(action, ctx):
        return None
    monkeypatch.setattr(main.agent_nodes, "_enforce", fake_enforce)

    # The peer's signed callback: an APPROVED decision for alice's task.
    class _Req:
        async def json(self):
            return {
                "_agentmesh": {"sender_did": "did:peer:b"},
                "status": {"state": "completed", "message": "Access approved."},
                "decision": "approved",
            }

    resp = asyncio.run(main.task_callback("alice-task-7", _Req()))
    assert resp.status_code == 202

    # The outcome now lives in alice's HOME-division store, keyed by HER principal,
    # as a regeneration-capable pending record (no stale answer baked in).
    items = asyncio.run(outcome_store.list_outcomes(_ALICE))
    assert len(items) == 1
    assert items[0]["task_id"] == "alice-task-7"
    assert items[0]["question"] == "what does division B know about X?"
    assert items[0]["status"] == "pending"
    assert items[0]["answer_or_message"] == ""     # no answer stored — regenerated at /inbox
    # And the in-app badge was raised for alice (FR-6.5).
    assert int(fake.kv.get(outcome_store._badge_key(_ALICE), 0)) == 1


# ── 6. cross-division DENIAL → declined record in the requester's store ────────

def test_cross_division_denial_records_declined(monkeypatch):
    """A cross-division DENIAL callback records a 'denied' outcome carrying the declined
    message in alice's home store (FR-6.3 across divisions)."""
    _patch_store_redis(monkeypatch)

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "secret B data?",
                "_federated": True, "_delegate_did": "did:peer:b"}
    monkeypatch.setattr(main, "_load_task", fake_load)
    monkeypatch.setattr(main, "_update_task", lambda *a, **k: _noop())

    async def fake_verify_signed(payload):
        return (True, "did:peer:b")
    monkeypatch.setattr(main.agent_identity, "verify_signed_message", fake_verify_signed)

    async def fake_verify_peer(did):
        return (True, 0.99)
    monkeypatch.setattr(main.agent_identity, "verify_peer_identity", fake_verify_peer)
    monkeypatch.setattr(main.settings, "agent_trust_threshold", 0.5)

    async def fake_enforce(action, ctx):
        return None
    monkeypatch.setattr(main.agent_nodes, "_enforce", fake_enforce)

    class _Req:
        async def json(self):
            return {
                "_agentmesh": {"sender_did": "did:peer:b"},
                "status": {"state": "failed", "message": "Access denied. Reason: confidential."},
                "decision": "denied",
            }

    resp = asyncio.run(main.task_callback("alice-task-8", _Req()))
    assert resp.status_code == 202

    items = asyncio.run(outcome_store.list_outcomes(_ALICE))
    assert len(items) == 1
    assert items[0]["status"] == "denied"
    assert "denied" in items[0]["answer_or_message"].lower()


async def _noop():
    return None


# ── 7. acknowledge clears the item from the default next-login view ────────────

def test_acknowledge_clears_item(monkeypatch):
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "task-3", "q", "pending"))
    asyncio.run(outcome_store.bump_badge(_ALICE))
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == 1

    monkeypatch.setattr(main, "principal", lambda claims: _ALICE)

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    resp = asyncio.run(main.inbox_acknowledge("task-3", authorization="Bearer tok"))
    assert json.loads(bytes(resp.body).decode())["acknowledged"] is True

    # Cleared from the default view, badge decremented, but record retained (durable ack).
    assert asyncio.run(outcome_store.list_outcomes(_ALICE)) == []
    assert asyncio.run(outcome_store.list_outcomes(_ALICE, include_acknowledged=True)) != []
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == 0


# ── 8. inbox IDOR safety — a caller only ever reads their OWN inbox ────────────

def test_inbox_is_per_principal(monkeypatch):
    """GET /inbox keys strictly on the caller's namespaced principal — bob cannot see
    alice's outcomes even though they share a division/store."""
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "task-1", "alice secret q", "pending"))

    # Caller authenticates as BOB.
    monkeypatch.setattr(main, "principal", lambda claims: _BOB)

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    async def no_rl(subject):
        return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rl)

    async def boom_run_query(**kw):
        raise AssertionError("bob has no outcomes — the pipeline must not be reached")
    monkeypatch.setattr(main.agent_graph, "run_query", boom_run_query)

    resp = asyncio.run(main.inbox(authorization="Bearer tok"))
    body = json.loads(bytes(resp.body).decode())
    assert body["items"] == []


# ── 9. callback task↔delegate binding (callback-injection guard) ───────────────
# Red-team REDTEAM_offline.md attack 3: task_callback authenticates the peer SIGNATURE but
# never checks that the task_id was federated to THAT peer (or federated at all). The fix
# binds the callback to the delegate DID + federated flag recorded at park time.

def _pass_callback_gates(monkeypatch, signer="did:peer:b"):
    """Make a single TRUSTED peer's signed callback clear every auth gate in task_callback
    (signature + registry trust + AGT policy) so the binding check is what's under test."""
    async def fake_verify_signed(payload):
        return (True, signer)
    monkeypatch.setattr(main.agent_identity, "verify_signed_message", fake_verify_signed)

    async def fake_verify_peer(did):
        return (True, 0.99)
    monkeypatch.setattr(main.agent_identity, "verify_peer_identity", fake_verify_peer)
    monkeypatch.setattr(main.settings, "agent_trust_threshold", 0.5)

    async def fake_enforce(action, ctx):
        return None
    monkeypatch.setattr(main.agent_nodes, "_enforce", fake_enforce)


class _SignedCallback:
    """A signature-VERIFIED (per _pass_callback_gates) peer callback body."""
    def __init__(self, sender="did:peer:b", state="completed", decision="approved",
                 message="Access approved."):
        self._body = {
            "_agentmesh": {"sender_did": sender},
            "status": {"state": state, "message": message},
            "decision": decision,
        }

    async def json(self):
        return self._body


def test_callback_on_unfederated_task_is_rejected(monkeypatch):
    """A purely-LOCAL task (never federated) must NOT accept a peer callback: a trusted
    peer cannot inject an outcome/badge onto a task it has no claim to. Rejected 403, no write."""
    _patch_store_redis(monkeypatch)
    _pass_callback_gates(monkeypatch, signer="did:peer:b")

    async def fake_load(task_id):
        # No _federated / _delegate_did — this was a local /query, no peer involved.
        return {"_owner_id": _ALICE, "query_full": "alice's purely-local question"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        raise AssertionError("unbound callback must not even touch task state")
    monkeypatch.setattr(main, "_update_task", fake_update)

    raised = False
    try:
        asyncio.run(main.task_callback("alice-local-task", _SignedCallback()))
    except Exception as exc:
        raised = True
        assert getattr(exc, "status_code", None) == 403
    assert raised, "callback for an unfederated task must be rejected"
    # No outcome was injected into alice's store.
    assert asyncio.run(outcome_store.list_outcomes(_ALICE)) == []


def test_callback_from_non_delegate_peer_is_rejected(monkeypatch):
    """A federated task delegated to peer B must NOT accept a callback signed by a DIFFERENT
    trusted peer C — even a denial — so peer C cannot DoS alice's pending delivery."""
    _patch_store_redis(monkeypatch)
    # The task federated to peer B; the callback is signed by peer C (also trusted).
    _pass_callback_gates(monkeypatch, signer="did:peer:c")

    # Alice's legitimate pending (regenerate-and-deliver) record exists.
    asyncio.run(outcome_store.put(_ALICE, "alice-task-real", "real q", "pending"))

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "real q",
                "_federated": True, "_delegate_did": "did:peer:b"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        raise AssertionError("non-delegate callback must not touch task state")
    monkeypatch.setattr(main, "_update_task", fake_update)

    cb = _SignedCallback(sender="did:peer:c", state="failed", decision="denied",
                         message="Access denied.")
    raised = False
    try:
        asyncio.run(main.task_callback("alice-task-real", cb))
    except Exception as exc:
        raised = True
        assert getattr(exc, "status_code", None) == 403
    assert raised, "callback from a non-delegate peer must be rejected"
    # Alice's real pending delivery is untouched — not overwritten by a terminal denial.
    rec = asyncio.run(outcome_store.list_outcomes(_ALICE))[0]
    assert rec["status"] == "pending", "non-delegate peer must not overwrite the victim's delivery"


def test_callback_from_bound_delegate_still_delivers(monkeypatch):
    """The LEGIT path still works: the delegate peer the task was federated to delivers an
    approved outcome to the requester's store (the binding does not block real deliveries)."""
    fake = _patch_store_redis(monkeypatch)
    _pass_callback_gates(monkeypatch, signer="did:peer:b")

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "what does B know about X?",
                "_federated": True, "_delegate_did": "did:peer:b"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        return None
    monkeypatch.setattr(main, "_update_task", fake_update)

    resp = asyncio.run(main.task_callback("alice-task-7", _SignedCallback()))
    assert resp.status_code == 202
    items = asyncio.run(outcome_store.list_outcomes(_ALICE))
    assert len(items) == 1 and items[0]["status"] == "pending"
    assert int(fake.kv.get(outcome_store._badge_key(_ALICE), 0)) == 1


# ── 10. denial confusion — decision and state must AGREE to deliver ────────────
# Red-team attack 3b: `if decision == "approved" or state == "completed"` lets a
# decision="denied" + state="completed" land in the DELIVER branch (drops the denial).

def test_callback_denied_decision_records_denial_even_if_state_completed(monkeypatch):
    """decision='denied' must record a DENIAL even when state='completed' — the more
    permissive signal must not win. Deliverable only when BOTH agree (approved + completed)."""
    _patch_store_redis(monkeypatch)
    _pass_callback_gates(monkeypatch, signer="did:peer:b")

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "confidential?",
                "_federated": True, "_delegate_did": "did:peer:b"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        return None
    monkeypatch.setattr(main, "_update_task", fake_update)

    cb = _SignedCallback(state="completed", decision="denied",
                         message="Access denied. Reason: confidential.")
    resp = asyncio.run(main.task_callback("alice-task-x", cb))
    assert resp.status_code == 202

    items = asyncio.run(outcome_store.list_outcomes(_ALICE))
    assert len(items) == 1
    assert items[0]["status"] == "denied", \
        "decision='denied' must record a denial regardless of state"
    assert "denied" in items[0]["answer_or_message"].lower()


# ── 11. callback replay idempotency — a terminal/acked outcome is not resurrected ──
# Red-team attack 3c: a replayed signed callback overwrote the record (put resets
# acknowledged=False) and re-bumped the badge. The fix skips the write when a
# terminal/acknowledged outcome already exists for that task.

def test_callback_replay_does_not_resurrect_acked_outcome(monkeypatch):
    """alice acked an outcome; a replayed signed callback must NOT overwrite it back into the
    unacknowledged view nor re-bump the badge (idempotent on a delivered task)."""
    _patch_store_redis(monkeypatch)
    _pass_callback_gates(monkeypatch, signer="did:peer:b")

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "q",
                "_federated": True, "_delegate_did": "did:peer:b"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        return None
    monkeypatch.setattr(main, "_update_task", fake_update)

    # First callback delivers; alice acks it (clears it from the view).
    asyncio.run(main.task_callback("alice-task-r", _SignedCallback()))
    asyncio.run(outcome_store.acknowledge(_ALICE, "alice-task-r"))
    assert asyncio.run(outcome_store.list_outcomes(_ALICE)) == []
    badge_before = asyncio.run(outcome_store.read_badge(_ALICE))

    # Replay the SAME signed callback.
    resp = asyncio.run(main.task_callback("alice-task-r", _SignedCallback()))
    assert resp.status_code == 202

    # The acked record stays acked — not resurrected — and the badge is unchanged.
    assert asyncio.run(outcome_store.list_outcomes(_ALICE)) == [], \
        "replay must not resurrect an acknowledged outcome"
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == badge_before


def test_callback_replay_does_not_resurrect_terminal_denial(monkeypatch):
    """A replayed denial callback must not re-write an existing terminal denial (idempotent)."""
    _patch_store_redis(monkeypatch)
    _pass_callback_gates(monkeypatch, signer="did:peer:b")

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "q",
                "_federated": True, "_delegate_did": "did:peer:b"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        return None
    monkeypatch.setattr(main, "_update_task", fake_update)

    cb = _SignedCallback(state="failed", decision="denied", message="Access denied.")
    asyncio.run(main.task_callback("alice-task-d", cb))
    badge_before = asyncio.run(outcome_store.read_badge(_ALICE))
    # Replay.
    asyncio.run(main.task_callback("alice-task-d", cb))
    # Still exactly one terminal denial; badge not re-bumped.
    items = asyncio.run(outcome_store.list_outcomes(_ALICE))
    assert len(items) == 1 and items[0]["status"] == "denied"
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == badge_before


# ── 12. badge derived from unacked record count (no phantom positive) ──────────
# Red-team attack 4: bump_badge is a free-running counter bumped on park + resolution +
# each callback while ack decrements once → phantom positive badge with an empty view.
# The fix derives the badge from the count of UNACKNOWLEDGED records.

def test_badge_is_derived_from_unacked_records(monkeypatch):
    """A double-bump of a single outcome must NOT leave a phantom positive badge: the badge
    is the count of unacknowledged records, so after acking the one record it reads 0."""
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "t", "q", "pending"))
    # Even with several stray bumps of the free-running counter…
    asyncio.run(outcome_store.bump_badge(_ALICE))
    asyncio.run(outcome_store.bump_badge(_ALICE))
    asyncio.run(outcome_store.bump_badge(_ALICE))
    # …the badge reflects the ONE unacknowledged record, not the counter.
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == 1
    # After acking the only record, the view is empty AND the badge is 0 (no phantom count).
    asyncio.run(outcome_store.acknowledge(_ALICE, "t"))
    assert asyncio.run(outcome_store.list_outcomes(_ALICE)) == []
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == 0


def test_badge_counts_multiple_unacked_outcomes(monkeypatch):
    """Two distinct unacknowledged outcomes → badge 2; acking one → badge 1 (tracks records)."""
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "t1", "q1", "pending"))
    asyncio.run(outcome_store.put(_ALICE, "t2", "q2", "denied", answer_or_message="no"))
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == 2
    asyncio.run(outcome_store.acknowledge(_ALICE, "t1"))
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == 1
