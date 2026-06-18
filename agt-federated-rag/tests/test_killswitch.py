"""Runtime kill-switch (FR-4.3) — engage/disengage WITHOUT a restart.

The kill-switch was deploy-time only: /query read settings.agent_kill_switch_engaged once at
startup. FR-4.3 wants a live lever. These hermetic tests pin:
  * a runtime engage (Redis flag, or POST /admin/kill-switch) → /query refuses with 503;
  * disengage → /query serves again, in the SAME process (no restart);
  * the deploy-time settings flag remains an always-on OVERRIDE that halts regardless;
  * a Redis error fails CLOSED (engaged), never silently lifting a governance halt;
  * the admin endpoint is admin-gated (non-admin → 403).

Hermetic: a fake async Redis backs _get_redis; the /query handler is driven far enough to
prove the kill check fires (or doesn't) before any auth/retrieval work — run_query is never
reached when engaged.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from api import main


class _FakeRedis:
    def __init__(self): self.kv: dict = {}
    async def get(self, k): return self.kv.get(k)
    async def set(self, k, v): self.kv[k] = v
    async def delete(self, k): self.kv.pop(k, None)
    async def setex(self, k, ttl, v): self.kv[k] = v
    async def expire(self, k, ttl): return True

    async def incr(self, k):
        self.kv[k] = int(self.kv.get(k, 0)) + 1
        return self.kv[k]


def _patch_redis(monkeypatch):
    fake = _FakeRedis()
    async def get_redis(): return fake
    monkeypatch.setattr(main, "_get_redis", get_redis)
    return fake


_ADMIN_CLAIMS = {"sub": "kc-admin", "email": "bob@example.com", "email_verified": True,
                 "iss": "http://localhost:9002/realms/rag",
                 "realm_access": {"roles": ["division-admin"]}}
_MEMBER_CLAIMS = {"sub": "kc-mem", "email": "alice@example.com", "email_verified": True,
                  "iss": "http://localhost:9002/realms/rag",
                  "realm_access": {"roles": ["member"]}}


def _admin_request(body: dict):
    class _Req:
        async def json(self): return body
    return _Req()


# ── the runtime check itself ───────────────────────────────────────────────────

def test_runtime_check_off_by_default(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    assert asyncio.run(main._runtime_kill_switch_engaged()) is False


def test_runtime_redis_flag_engages(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    fake = _patch_redis(monkeypatch)
    fake.kv[main._killswitch_key("alpha")] = "1"
    assert asyncio.run(main._runtime_kill_switch_engaged()) is True


def test_settings_flag_is_override(monkeypatch):
    # Even with NO runtime flag, the deploy-time settings override halts the path.
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", True)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    assert asyncio.run(main._runtime_kill_switch_engaged()) is True


def test_redis_error_fails_closed(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    async def boom(): raise RuntimeError("redis down")
    monkeypatch.setattr(main, "_get_redis", boom)
    # A store we cannot read must not silently lift a halt — fail closed (engaged).
    assert asyncio.run(main._runtime_kill_switch_engaged()) is True


# ── /query honors the runtime flag (engage → 503 → disengage → serves) ─────────

def _run_query_status(monkeypatch):
    """Drive POST /query; return the HTTPException status if it refuses, else 'served'.

    run_query is stubbed to a benign result so a SERVED path doesn't need live infra; if the
    kill check fires first, run_query is never reached.
    """
    async def fake_bearer(auth):
        return ("tok", _MEMBER_CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)
    monkeypatch.setattr(main, "principal", lambda claims: "alice@example.com|ns")
    async def no_rl(subject): return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rl)

    async def fake_run_query(**kw):
        return {"task_id": kw.get("task_id"), "answer": "ok", "status_message": "completed",
                "flow": "LOCAL_ALLOWED"}
    monkeypatch.setattr(main.agent_graph, "run_query", fake_run_query)

    class _Req:
        async def json(self): return {"query": "hello"}

    try:
        resp = asyncio.run(main.query(_Req(), authorization="Bearer tok"))
    except main.HTTPException as ei:
        return ei.status_code
    # Served: /query returns an EventSourceResponse (no kill refusal).
    assert isinstance(resp, main.EventSourceResponse)
    return "served"


def test_query_blocked_when_runtime_engaged_then_served_after_disengage(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    fake = _patch_redis(monkeypatch)

    # engage at runtime → 503
    fake.kv[main._killswitch_key("alpha")] = "1"
    assert _run_query_status(monkeypatch) == 503

    # disengage at runtime → serves again (same process, no restart)
    fake.kv.pop(main._killswitch_key("alpha"), None)
    assert _run_query_status(monkeypatch) == "served"


def test_query_blocked_by_settings_override(monkeypatch):
    # The deploy-time flag still halts /query with no runtime flag present.
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", True)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    assert _run_query_status(monkeypatch) == 503


# ── /a2a/query (cross-division entry) honors the runtime flag too ──────────────

def _run_a2a_status(monkeypatch):
    """Drive POST /a2a/query; return the HTTPException status.

    The handler is DID-authenticated (no bearer). We stub verify_signed_message to fail
    AFTER the kill-check, so: engaged → 503 (kill check fires first, signature never
    reached); disengaged → 401 (kill check passed, control reached signature verification).
    """
    async def fake_verify(payload):
        return (False, None)
    monkeypatch.setattr(main.agent_identity, "verify_signed_message", fake_verify)

    class _Req:
        async def json(self): return {"query": "hello"}

    try:
        asyncio.run(main.a2a_query(_Req()))
    except main.HTTPException as ei:
        return ei.status_code
    raise AssertionError("a2a_query should not return normally with an unsigned payload")


def test_a2a_query_blocked_when_runtime_engaged_then_served_after_disengage(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    fake = _patch_redis(monkeypatch)

    # engage at runtime → 503 (the cross-division entry is halted before signature checks)
    fake.kv[main._killswitch_key("alpha")] = "1"
    assert _run_a2a_status(monkeypatch) == 503

    # disengage → kill-check passes, control reaches signature verification (401 here)
    fake.kv.pop(main._killswitch_key("alpha"), None)
    assert _run_a2a_status(monkeypatch) == 401


def test_a2a_query_blocked_by_settings_override(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", True)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    assert _run_a2a_status(monkeypatch) == 503


# ── POST /admin/kill-switch ────────────────────────────────────────────────────

def test_admin_engage_then_query_blocked(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    fake = _patch_redis(monkeypatch)

    async def fake_bearer(auth): return ("tok", _ADMIN_CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    resp = asyncio.run(main.admin_kill_switch(_admin_request({"engaged": True}),
                                              authorization="Bearer tok"))
    body = json.loads(bytes(resp.body).decode())
    assert body["runtime_engaged"] is True and body["effective_engaged"] is True
    assert fake.kv.get(main._killswitch_key("alpha")) == "1"
    # the flag the admin set now blocks /query (this re-patches _get_bearer_token to a member)
    assert _run_query_status(monkeypatch) == 503

    # disengage clears it — restore the admin bearer (the query path above swapped it out).
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)
    resp2 = asyncio.run(main.admin_kill_switch(_admin_request({"engaged": False}),
                                               authorization="Bearer tok"))
    body2 = json.loads(bytes(resp2.body).decode())
    assert body2["effective_engaged"] is False
    assert main._killswitch_key("alpha") not in fake.kv


def test_admin_disengage_does_not_lift_settings_override(monkeypatch):
    # Settings override is always-on: disengaging the runtime flag must still report halted.
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", True)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)

    async def fake_bearer(auth): return ("tok", _ADMIN_CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    resp = asyncio.run(main.admin_kill_switch(_admin_request({"engaged": False}),
                                              authorization="Bearer tok"))
    body = json.loads(bytes(resp.body).decode())
    assert body["runtime_engaged"] is False
    assert body["settings_override"] is True
    assert body["effective_engaged"] is True             # override still halts


def test_admin_kill_switch_requires_admin_403(monkeypatch):
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    async def fake_bearer(auth): return ("tok", _MEMBER_CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_kill_switch(_admin_request({"engaged": True}),
                                           authorization="Bearer tok"))
    assert ei.value.status_code == 403


def test_admin_kill_switch_bad_body_400(monkeypatch):
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    async def fake_bearer(auth): return ("tok", _ADMIN_CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_kill_switch(_admin_request({"engaged": "yes"}),
                                           authorization="Bearer tok"))
    assert ei.value.status_code == 400
