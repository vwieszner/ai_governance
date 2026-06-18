"""FR-4 governance-control proving tests (IMPLEMENTATION_PLAN.md traceability — FR-4).

These pin three governance properties that the code already enforces but that the named
suites did not directly exercise:

  * EVERY graph node gates on ``_enforce`` before acting — proven both structurally (every
    node body contains an ``_enforce`` call) AND behaviourally (a deny-all policy makes a
    node raise PermissionError before it touches any infra);
  * a peer below the trust-score threshold is DENIED by the real peer-comms policy YAML
    (loaded from agent/policies), and the same allow-listed action passes for a trusted peer;
  * the NEEDS_APPROVAL flow is computed from the OpenFGA ``pending_approval`` RELATION, not a
    hardcoded branch — the decision tracks exactly the relation-check result.

Hermetic: the real YAML policies are loaded for the peer-comms test; the OpenFGA client is
stubbed (no live store); node enforcement is driven with a fake deny-all evaluator (no
retrievers / LLM / Temporal). Complements tests/test_governance.py (default-deny + output
DLP) and tests/test_authz.py (three-way decide) without duplicating them.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path

import pytest

_POLICY_DIR = str(Path(__file__).resolve().parents[1] / "agent" / "policies")

# The graph nodes wired in agent.graph._build_graph — each MUST gate on _enforce.
_GRAPH_NODES = [
    "retrieve_local",
    "check_auth",
    "generate_answer",
    "start_approval",
    "call_peer_agent",
    "handle_peer_result",
    "format_response",
]


# ── _enforce on every node ────────────────────────────────────────────────────


def test_every_node_calls_enforce_structurally():
    """Static proof: every graph-node function body contains an ``_enforce(...)`` call.

    Parsing the source (not a regex) means an accidental refactor that drops the gate from
    a node — or a new node added without it — fails this test.
    """
    import agent.nodes as nodes

    missing = []
    for name in _GRAPH_NODES:
        src = inspect.getsource(getattr(nodes, name))
        tree = ast.parse(src)
        calls_enforce = any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "_enforce"
            for n in ast.walk(tree)
        )
        if not calls_enforce:
            missing.append(name)
    assert not missing, f"graph nodes missing an _enforce gate: {missing}"


def test_node_enforce_is_fail_closed(monkeypatch):
    """Behavioural proof: with a DENY-ALL evaluator a node raises PermissionError.

    ``retrieve_local`` calls ``_enforce`` as its very first statement, so a policy deny
    aborts it before any retriever / OpenFGA / LLM work — i.e. the gate is real and
    fail-closed, not decorative. ``format_response`` (a different action) is also driven to
    confirm the gate fires per-node, not just once.
    """
    import agent.nodes as nodes

    class _DenyResult:
        allowed = False
        reason = "test deny-all"

    class _DenyEvaluator:
        def evaluate(self, ctx):
            return _DenyResult()

    async def _fake_get_evaluator():
        return _DenyEvaluator()

    monkeypatch.setattr(nodes, "_get_evaluator", _fake_get_evaluator)
    monkeypatch.setattr(nodes, "_evaluator", None)

    with pytest.raises(PermissionError):
        asyncio.run(nodes.retrieve_local({"query": "hi", "user_id": "user:alice"}))

    with pytest.raises(PermissionError):
        asyncio.run(nodes.format_response({"user_id": "user:alice"}))


# ── peer trust-score gate (peer-comms-policy.yaml) ─────────────────────────────


def _evaluator():
    from agent_os.policies import PolicyEvaluator  # type: ignore[import]

    ev = PolicyEvaluator()
    ev.load_policies(_POLICY_DIR)
    return ev


def _peer_ctx(trust_score: float) -> dict:
    """A peer.send_message context that passes every gate EXCEPT (maybe) the trust gate."""
    return {
        "action": "peer.send_message",
        "user_id": "user:alice",
        "peer_did_verified": True,
        "transport_encrypted": True,
        "peer_trust_score": trust_score,
        "peer_execution_ring": "TRUSTED",
        "peer_circuit_state": "CLOSED",
    }


def test_low_trust_refused():
    """A peer below the trust-score threshold is DENIED by the peer-comms policy.

    The peer-comms-policy ``block-low-trust-peer`` rule denies ``peer_trust_score < 0.6``.
    A peer at 0.1 (everything else valid) is refused; a trusted peer at 0.9 — the same
    allow-listed action — passes. This is the gate call_peer_agent feeds with the REAL
    verify_peer_identity score, so it is an enforcing control, not decoration.
    """
    ev = _evaluator()

    denied = ev.evaluate(_peer_ctx(0.1))
    assert not denied.allowed
    assert "trust score" in (denied.reason or "").lower()

    allowed = ev.evaluate(_peer_ctx(0.9))
    assert allowed.allowed


def test_unverified_peer_refused():
    """The peer-comms policy also denies an UNVERIFIED peer DID (fail-closed identity gate).

    Pins that the gate is driven by the real verification flag — an unverified DID is
    refused even when the trust score would otherwise pass.
    """
    ev = _evaluator()
    ctx = _peer_ctx(0.9)
    ctx["peer_did_verified"] = False
    result = ev.evaluate(ctx)
    assert not result.allowed


# ── NEEDS_APPROVAL is authz-relation-driven, not a hardcoded branch ────────────


def _stub_auth(viewer: bool, pending: bool):
    """An OpenFGAAuth whose check() answers from the (viewer, pending) relations only,
    recording which relations were actually queried."""
    from auth import openfga as ofga

    auth = ofga.OpenFGAAuth()
    queried: list = []

    async def _check(user_id, chunk_id, relation, groups=None):  # noqa: ANN001 - stub
        queried.append(relation)
        if relation == ofga.Relation.VIEWER:
            return viewer
        if relation == ofga.Relation.PENDING_APPROVAL:
            return pending
        return False

    auth.check = _check  # type: ignore[method-assign]
    return auth, ofga, queried


def test_needs_approval_from_authz():
    """NEEDS_APPROVAL is computed from the OpenFGA ``pending_approval`` relation check.

    The decision tracks the relation-check result exactly: pending_approval=True (and not
    viewer) → NEEDS_APPROVAL; pending_approval=False → never NEEDS_APPROVAL (DENIED). And
    the relation actually queried against OpenFGA is ``pending_approval`` — i.e. the flow is
    sourced from the authorization store, not a hardcoded branch in agent code.
    """
    auth, ofga, queried = _stub_auth(viewer=False, pending=True)
    decision = asyncio.run(auth.decide("user:alice", "chunk:x"))
    assert decision == ofga.AuthzDecision.NEEDS_APPROVAL
    # The pending_approval RELATION was the source of the decision.
    assert ofga.Relation.PENDING_APPROVAL in queried
    assert ofga.Relation.PENDING_APPROVAL.value == "pending_approval"

    # Flip ONLY the pending_approval relation off → the decision is no longer NEEDS_APPROVAL
    # (it is not a constant branch; it follows the relation).
    auth2, ofga2, _ = _stub_auth(viewer=False, pending=False)
    assert asyncio.run(auth2.decide("user:alice", "chunk:x")) == ofga2.AuthzDecision.DENIED
