"""Red-team probes against FR-6 offline delivery / inbox (outcome_store + api/main + activities).

ADVERSARIAL. Each probe exercises the REAL functions/endpoints with a stubbed async Redis
(same technique as tests/test_offline.py) and asserts the ATTACKER's desired outcome — so a
PASS here means the attack SUCCEEDED (the code is VULNERABLE) and a FAIL means the code DEFENDED.

Run:  .venv/Scripts/python.exe -m pytest redteam/probe_offline.py -v
(from agt-federated-rag/ ; add the dir to sys.path the way the suite's conftest does)

Probe map (attack-goal → function):
  A3a  callback_injects_outcome_on_unfederated_task   — single trusted peer seeds an outcome
                                                          into a victim's store for a task that
                                                          was NEVER delegated to it (no task↔peer
                                                          binding).  -> VULNERABLE if it lands.
  A3b  callback_denial_confusion_state_overrides_decision — decision="denied" but state="completed"
                                                          is recorded as deliverable (pending), not
                                                          denied.  -> confusion.
  A3c  callback_replay_overwrites_terminal_outcome     — a second (replayed) callback overwrites an
                                                          already-acknowledged/terminal outcome.
  A2   stale_leak_regenerate_is_real                   — confirm /inbox truly re-runs the pipeline
                                                          (control / sanity that A2 is DEFENDED).
  A1   inbox_idor_cross_principal                      — confirm principal keying blocks IDOR
                                                          (control).
  A4   badge_underflow / denial_surfaces_completed     — badge/ack abuse + denied-as-completed.
"""
from __future__ import annotations

import asyncio
import json

import outcome_store
from api import main


# ── Fake async Redis (mirrors tests/test_offline.py) ───────────────────────────

class _FakeRedis:
    def __init__(self) -> None:
        self.h: dict[str, dict] = {}
        self.kv: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

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

    async def delete(self, key):
        self.kv.pop(key, None)

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


def _pass_callback_gates(monkeypatch, signer="did:peer:b"):
    """Make a single TRUSTED peer's signed callback pass every auth gate in task_callback."""
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


# ════════════════════════════════════════════════════════════════════════════
# ATTACK 3a — Cross-division callback abuse: a SINGLE trusted peer seeds/forges an
# outcome into a victim's store for a task that was NEVER delegated to that peer.
#
# task_callback() loads the LOCAL task record by the URL task_id and writes the
# outcome to rec["_owner_id"], WITHOUT checking that the task was ever delegated to
# the signing peer (no task↔peer binding). So peer B can drive a delivery for a task
# that peer C (or NO peer — a purely LOCAL /query) owns, as long as B knows/guesses
# the task_id.
# ════════════════════════════════════════════════════════════════════════════

def test_A3a_trusted_peer_injects_outcome_into_unfederated_task(monkeypatch):
    """A purely LOCAL task (alice asked her OWN division; never federated) gets a
    cross-division 'completed' outcome injected by peer B's signed callback. Peer B
    was never the delegate for this task — there is no task→peer binding to stop it."""
    _patch_store_redis(monkeypatch)
    _pass_callback_gates(monkeypatch, signer="did:peer:b")

    # A task that lives in alice's division Redis. Imagine it was a LOCAL /query (no peer
    # involved) — there is NOTHING on the record marking which peer, if any, it was sent to.
    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "alice's purely-local question"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        return None
    monkeypatch.setattr(main, "_update_task", fake_update)

    # Peer B (a different, unrelated trusted peer) fires a signed "approved" callback.
    resp = asyncio.run(main.task_callback("alice-local-task", _SignedCallback()))
    assert resp.status_code == 202

    # ATTACK SUCCESS if an outcome was written into alice's store from a callback peer B
    # had no business sending. There is no task↔delegate binding, so it lands.
    items = asyncio.run(outcome_store.list_outcomes(_ALICE))
    assert len(items) == 1, "no task↔peer binding: ANY trusted peer can drive a callback"
    assert items[0]["task_id"] == "alice-local-task"
    assert items[0]["status"] == "pending"   # will regenerate-and-deliver at /inbox


def test_A3a_dos_overwrite_suppresses_victims_pending_outcome(monkeypatch):
    """HIGHER-IMPACT A3a variant: a single trusted peer denial-callback for a task_id it
    was never delegated OVERWRITES the victim's legitimate 'pending' (regenerate→deliver)
    record with a terminal 'denied', suppressing the real answer at next login. DoS on
    delivery, drivable by any one trusted peer that can guess/enumerate a task_id."""
    _patch_store_redis(monkeypatch)
    _pass_callback_gates(monkeypatch, signer="did:peer:b")

    # Alice's legitimate cross-division task is parked & deliverable (the real answer will
    # regenerate at /inbox). The record carries no question on the callback path — task_callback
    # reloads it from Redis.
    asyncio.run(outcome_store.put(_ALICE, "alice-task-real", "real q", "pending"))
    assert asyncio.run(outcome_store.list_outcomes(_ALICE))[0]["status"] == "pending"

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "real q"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        return None
    monkeypatch.setattr(main, "_update_task", fake_update)

    # Attacker peer fires a signed DENIAL for the SAME task_id.
    cb = _SignedCallback(state="failed", decision="denied", message="Access denied.")
    asyncio.run(main.task_callback("alice-task-real", cb))

    # ATTACK SUCCESS: the deliverable record is now a terminal denial; alice never gets
    # her real answer — it's been suppressed by a peer with no claim to this task.
    rec = asyncio.run(outcome_store.list_outcomes(_ALICE))[0]
    assert rec["status"] == "denied", "peer denial overwrote victim's pending delivery"


def test_A3a_unauth_caller_cannot_seed(monkeypatch):
    """CONTROL: an UNVERIFIED signature is rejected (the DID-verified path is reused).
    An unverified callback cannot seed an inbox — confirms the gate is real."""
    _patch_store_redis(monkeypatch)

    async def reject_sig(payload):
        return (False, None)
    monkeypatch.setattr(main.agent_identity, "verify_signed_message", reject_sig)

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "q"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    raised = False
    try:
        asyncio.run(main.task_callback("alice-task", _SignedCallback()))
    except Exception as exc:  # HTTPException(401)
        raised = True
        assert getattr(exc, "status_code", None) == 401
    assert raised, "unsigned callback must be rejected"
    assert asyncio.run(outcome_store.list_outcomes(_ALICE)) == []


# ════════════════════════════════════════════════════════════════════════════
# ATTACK 3b — DENIAL CONFUSION: a callback with decision="denied" but state="completed"
# is recorded as a DELIVERABLE (pending→regenerate) outcome, NOT a denial.
#
#   task_callback:  if decision == "approved" OR state == "completed":  -> pending(deliver)
# The OR means a peer that says decision="denied" still gets the deliverable branch as
# long as state=="completed". A confused/compromised peer (or a peer whose state machine
# disagrees with its decision field) flips a denial into a delivery.
# ════════════════════════════════════════════════════════════════════════════

def test_A3b_denied_decision_with_completed_state_becomes_deliverable(monkeypatch):
    """decision='denied' should NOT deliver. But state='completed' wins via the OR,
    so the record is 'pending' (regenerate-and-deliver) — denial confusion."""
    _patch_store_redis(monkeypatch)
    _pass_callback_gates(monkeypatch)

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "what does B know about X?"}
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
    # ATTACK SUCCESS: a DENIED decision produced a DELIVERABLE pending record.
    assert items[0]["status"] == "pending", \
        "denial confusion: decision='denied' + state='completed' -> deliverable"
    assert items[0]["answer_or_message"] == "", "delivery branch drops the denial message"


# ════════════════════════════════════════════════════════════════════════════
# ATTACK 3c — REPLAY / OVERWRITE: a trusted peer replays (or re-sends) a callback and
# OVERWRITES an already-resolved/acknowledged outcome, resurrecting it in the inbox.
# outcome_store.put() always overwrites by task_id and resets acknowledged=False; there
# is no nonce/idempotency guard on the callback, so a replay re-arms the badge + record.
# ════════════════════════════════════════════════════════════════════════════

def test_A3c_callback_replay_resurrects_acknowledged_outcome(monkeypatch):
    """alice acknowledged an outcome; a replayed signed callback overwrites it back to
    unacknowledged + re-bumps the badge. No replay/idempotency guard on the callback."""
    fake = _patch_store_redis(monkeypatch)
    _pass_callback_gates(monkeypatch)

    async def fake_load(task_id):
        return {"_owner_id": _ALICE, "query_full": "q"}
    monkeypatch.setattr(main, "_load_task", fake_load)

    async def fake_update(task_id, updates):
        return None
    monkeypatch.setattr(main, "_update_task", fake_update)

    # 1) first callback delivers + alice acks it.
    asyncio.run(main.task_callback("alice-task-r", _SignedCallback()))
    asyncio.run(outcome_store.acknowledge(_ALICE, "alice-task-r"))
    assert asyncio.run(outcome_store.list_outcomes(_ALICE)) == []   # cleared from view

    badge_before = int(fake.kv.get(outcome_store._badge_key(_ALICE), 0))

    # 2) the SAME signed callback is replayed (captured off the wire, or peer retry).
    asyncio.run(main.task_callback("alice-task-r", _SignedCallback()))

    items = asyncio.run(outcome_store.list_outcomes(_ALICE))
    # ATTACK SUCCESS: the acknowledged outcome is resurrected (unacknowledged again)
    # and the badge re-bumped — a replay re-notifies / re-arms with no idempotency guard.
    assert len(items) == 1, "replay overwrote the acknowledged record back into the view"
    assert items[0]["acknowledged"] is False
    badge_after = int(fake.kv.get(outcome_store._badge_key(_ALICE), 0))
    assert badge_after > badge_before, "replay re-bumped the unseen badge"


# ════════════════════════════════════════════════════════════════════════════
# ATTACK 2 — STALE-DATA LEAK: is the answer EVER served without a fresh authz re-check?
# Control probe: prove /inbox re-runs the pipeline and a revoked grant flips to denied.
# (Expected DEFENDED — establishes the regenerate-at-delivery invariant really holds.)
# ════════════════════════════════════════════════════════════════════════════

def test_A2_inbox_regenerates_and_revoke_flips_to_denied(monkeypatch):
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "task-2", "q4 revenue?", "pending"))

    monkeypatch.setattr(main, "principal", lambda claims: _ALICE)

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    async def no_rl(subject):
        return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rl)

    ran = {"n": 0}

    async def grant(**kw):
        ran["n"] += 1
        assert kw.get("check_only") is True
        return {"flow": "LOCAL_ALLOWED", "answer": "Q4 was $42M."}
    monkeypatch.setattr(main.agent_graph, "run_query", grant)

    body = json.loads(bytes(asyncio.run(main.inbox(authorization="Bearer tok")).body).decode())
    assert body["items"][0]["answer"] == "Q4 was $42M."
    assert ran["n"] == 1, "must re-run the pipeline at delivery"

    async def revoked(**kw):
        return {"flow": "LOCAL_DENIED", "answer": ""}
    monkeypatch.setattr(main.agent_graph, "run_query", revoked)
    body2 = json.loads(bytes(asyncio.run(main.inbox(authorization="Bearer tok")).body).decode())
    assert body2["items"][0]["status"] == "denied"
    assert "answer" not in body2["items"][0], "no stale answer after revoke"


def test_A2b_stored_record_never_holds_a_completed_answer(monkeypatch):
    """Confirm put() refuses to persist an answer for a 'completed' record (the
    no-stale-data invariant at the store layer)."""
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "t", "q", "completed",
                                  answer_or_message="SECRET ANSWER LEAK"))
    rec = asyncio.run(outcome_store.get(_ALICE, "t"))
    assert rec["answer_or_message"] == "", "completed record must store NO answer"


# ════════════════════════════════════════════════════════════════════════════
# ATTACK 1 — IDOR: read/ack another user's inbox. Control probe (expected DEFENDED):
# the inbox keys strictly on the caller's namespaced principal.
# ════════════════════════════════════════════════════════════════════════════

def test_A1_inbox_idor_blocked(monkeypatch):
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "task-1", "alice secret", "pending"))

    monkeypatch.setattr(main, "principal", lambda claims: _BOB)   # caller is BOB

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    async def no_rl(subject):
        return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rl)

    async def boom(**kw):
        raise AssertionError("bob has no outcomes; pipeline must not run")
    monkeypatch.setattr(main.agent_graph, "run_query", boom)

    body = json.loads(bytes(asyncio.run(main.inbox(authorization="Bearer tok")).body).decode())
    assert body["items"] == [], "bob must not see alice's inbox"


def test_A1b_ack_idor_is_scoped_to_caller(monkeypatch):
    """ack keys on the caller's principal; bob acking alice's task_id only touches
    bob's (empty) store, never alice's record."""
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "task-1", "alice secret", "pending"))

    monkeypatch.setattr(main, "principal", lambda claims: _BOB)

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    resp = asyncio.run(main.inbox_acknowledge("task-1", authorization="Bearer tok"))
    assert json.loads(bytes(resp.body).decode())["acknowledged"] is False  # nothing in bob's store
    # alice's record is untouched.
    assert asyncio.run(outcome_store.list_outcomes(_ALICE))[0]["acknowledged"] is False


# ════════════════════════════════════════════════════════════════════════════
# ATTACK 4 — BADGE underflow + denied-surfaces-as-completed.
# ════════════════════════════════════════════════════════════════════════════

def test_A4_badge_underflow_via_double_ack_or_stray_ack(monkeypatch):
    """The badge only decrements when >0, so a stray ack can't drive it negative —
    control. But verify a double-bump / single-ack leaves a stuck >0 badge (annoyance,
    not a security break)."""
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "t", "q", "pending"))
    asyncio.run(outcome_store.bump_badge(_ALICE))
    asyncio.run(outcome_store.bump_badge(_ALICE))   # badge=2 but only ONE record
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == 2
    asyncio.run(outcome_store.acknowledge(_ALICE, "t"))
    # Only one record existed; badge is now 1 with an empty view — stuck phantom count.
    assert asyncio.run(outcome_store.read_badge(_ALICE)) == 1
    assert asyncio.run(outcome_store.list_outcomes(_ALICE)) == []


def test_A4b_denied_record_never_surfaces_as_completed(monkeypatch):
    """A terminal denied record (no question) must surface as denied via /inbox, never
    completed. Control — expected DEFENDED."""
    _patch_store_redis(monkeypatch)
    asyncio.run(outcome_store.put(_ALICE, "t", "", "denied",
                                  answer_or_message="Access denied. Reason: policy."))

    monkeypatch.setattr(main, "principal", lambda claims: _ALICE)

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    async def no_rl(subject):
        return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rl)

    async def boom(**kw):
        raise AssertionError("terminal denial must not re-run the pipeline")
    monkeypatch.setattr(main.agent_graph, "run_query", boom)

    body = json.loads(bytes(asyncio.run(main.inbox(authorization="Bearer tok")).body).decode())
    assert body["items"][0]["status"] == "denied"
    assert "answer" not in body["items"][0]
