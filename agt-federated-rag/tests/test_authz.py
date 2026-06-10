"""M1 authorization tests (IMPLEMENTATION_PLAN.md M1, FR-2.x).

Proves the per-chunk ReBAC decision is three-way and DENY-BY-DEFAULT: viewer ->
ALLOWED, pending_approval-only -> NEEDS_APPROVAL, nothing -> DENIED. Deny-by-default
is the safety invariant — no relation means no access, never an implicit allow.
Hermetic: stubs the OpenFGA check() so no live store is needed.
"""
from __future__ import annotations

import asyncio


def _auth(viewer: bool, pending: bool):
    from auth import openfga as ofga

    auth = ofga.OpenFGAAuth()

    async def _check(user_id, chunk_id, relation):  # noqa: ANN001 - stub
        if relation == ofga.Relation.VIEWER:
            return viewer
        if relation == ofga.Relation.PENDING_APPROVAL:
            return pending
        return False

    auth.check = _check  # type: ignore[method-assign]
    return auth, ofga


def test_three_way_decide_deny_by_default():
    auth, ofga = _auth(viewer=True, pending=False)
    assert asyncio.run(auth.decide("user:alice", "chunk:x")) == ofga.AuthzDecision.ALLOWED

    auth, ofga = _auth(viewer=False, pending=True)
    assert asyncio.run(auth.decide("user:alice", "chunk:x")) == ofga.AuthzDecision.NEEDS_APPROVAL

    # No relation at all -> DENIED (deny-by-default; the headline safety invariant).
    auth, ofga = _auth(viewer=False, pending=False)
    assert asyncio.run(auth.decide("user:alice", "chunk:x")) == ofga.AuthzDecision.DENIED


def test_viewer_wins_over_pending():
    # A user who is both a viewer and pending is ALLOWED (viewer is the stronger grant).
    auth, ofga = _auth(viewer=True, pending=True)
    assert asyncio.run(auth.decide("user:alice", "chunk:x")) == ofga.AuthzDecision.ALLOWED
