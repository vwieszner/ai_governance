"""Requester-side approval-poll re-auth guards (GET /tasks/{id}/result, check_only).

The UI polls the result endpoint every ~4 s while a request is parked on approval.
Each poll RE-RUNS the governed pipeline to re-check live OpenFGA authorization — but it
must NEVER start a new Temporal approval workflow or re-write pending tuples, or every
poll would re-notify the data owner (notification spam) and pile up duplicate workflows.

These hermetic guards pin that contract on start_approval:
  * check_only=True  → returns "pending" WITHOUT touching Temporal / OpenFGA / the
    policy gate (short-circuit before any side effect);
  * check_only=False → the normal path still runs the policy gate (_enforce) — the
    short-circuit is strictly conditional and does not weaken the first real request.
"""
from __future__ import annotations

import asyncio

import pytest


def _state(check_only: bool) -> dict:
    return {
        "check_only": check_only,
        "user_id": "alice@example.com|deadbeefdeadbeef",
        "pending_chunk_ids": ["chunk-1"],
        "query": "what is the q4 revenue?",
        "fused_chunks": [],
    }


def test_check_only_short_circuits_before_any_side_effect(monkeypatch):
    from agent import nodes

    async def boom_temporal():
        raise AssertionError("check_only must NOT start a Temporal workflow")

    async def boom_openfga():
        raise AssertionError("check_only must NOT write OpenFGA pending tuples")

    async def boom_enforce(action, ctx):
        raise AssertionError("check_only must short-circuit before the policy gate")

    monkeypatch.setattr(nodes, "_get_temporal", boom_temporal)
    monkeypatch.setattr(nodes, "_get_openfga", boom_openfga)
    monkeypatch.setattr(nodes, "_enforce", boom_enforce)

    out = asyncio.run(nodes.start_approval(_state(check_only=True)))

    assert out["approval_request_id"] is None      # no new request id minted
    assert out["answer"] is None                    # nothing released
    assert "pending" in out["status_message"].lower()


def test_normal_path_still_runs_the_policy_gate(monkeypatch):
    from agent import nodes

    hit = {"enforce": False}

    async def fake_enforce(action, ctx):
        hit["enforce"] = True
        # Stop the node here — we only need to prove the gate is reached on the
        # non-check_only path (so the short-circuit is conditional, not unconditional).
        raise PermissionError("gate reached")

    monkeypatch.setattr(nodes, "_enforce", fake_enforce)

    with pytest.raises(PermissionError):
        asyncio.run(nodes.start_approval(_state(check_only=False)))

    assert hit["enforce"], "the first real approval request must still hit the policy gate"


# ── GET /tasks/{id}/result — ownership (IDOR) guard ───────────────────────────
#
# The result endpoint is the ONLY authenticated read of a parked request's outcome.
# Its single access control is "the caller's namespaced principal must own the task".
# A same-division IDOR isn't constructible from the seed data (only alice@alpha +
# bob@beta, who fail at issuer validation cross-division), so the ownership branch is
# pinned here as a unit test: it must 403 BEFORE re-running the pipeline (no Redis/LLM).

_OWNER = "alice@example.com|aaaaaaaaaaaaaaaa"
_OTHER = "mallory@example.com|bbbbbbbbbbbbbbbb"
_CLAIMS = {"sub": "kc-uuid", "email": "alice@example.com", "email_verified": True,
           "iss": "http://localhost:9002/realms/rag"}


def test_task_result_rejects_non_owner_403(monkeypatch):
    from api import main

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)

    async def fake_load(task_id):
        return {"_owner_id": _OTHER, "query_full": "q4 revenue"}   # owned by someone ELSE

    async def boom_run_query(**kw):
        raise AssertionError("ownership must be enforced BEFORE any pipeline re-run")

    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)
    monkeypatch.setattr(main, "_load_task", fake_load)
    monkeypatch.setattr(main, "principal", lambda claims: _OWNER)   # caller != owner
    monkeypatch.setattr(main.agent_graph, "run_query", boom_run_query)

    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.task_result("task-1", authorization="Bearer tok"))
    assert ei.value.status_code == 403


def test_task_result_unknown_task_404(monkeypatch):
    from api import main

    async def fake_bearer(auth):
        return ("tok", _CLAIMS)

    async def fake_load(task_id):
        return None                                                # no such task

    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)
    monkeypatch.setattr(main, "_load_task", fake_load)
    monkeypatch.setattr(main, "principal", lambda claims: _OWNER)

    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.task_result("nope", authorization="Bearer tok"))
    assert ei.value.status_code == 404
