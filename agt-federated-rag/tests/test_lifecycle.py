"""FR-7 access-lifecycle guards: grant expiry (7.1) and re-ask after revoke (7.3).

The approval grant path (``grant_access_in_openfga``) must honour the
``approval_grant_ttl_seconds`` setting:

* ttl > 0  → the viewer grant is TIME-BOUND — written via ``grant_viewer_until``
  with a FUTURE expiry, never the permanent ``grant_viewer``. Once it lapses the
  requester must re-ask.
* ttl == 0 → legacy/permanent grant via ``grant_viewer`` (the default; behaviour
  must be preserved).

These were silently broken before: the field existed and ``grant_viewer_until``
worked, but the activity always called the PERMANENT ``grant_viewer`` — so every
approved access was forever. These hermetic guards pin the wiring.

The FR-7.3 revoke half (``revoke_viewer`` then ``set_pending_approval``) lives in
the authenticated /revoke endpoint; here we assert the *consequence* the wiring
relies on: a chunk left at pending_approval-only routes a re-ask to NEEDS_APPROVAL.

Hermetic: stubs the OpenFGA client (no live store). ``asyncio_mode=auto`` so async
tests need no marker; sync tests use ``asyncio.run`` to match the existing suite.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone


class _RecordingOpenFGA:
    """Stub OpenFGA singleton that records the grant calls the activity makes.

    Distinguishes the permanent grant (``grant_viewer``) from the time-bound grant
    (``grant_viewer_until``) so a test can assert exactly one path was taken — the
    whole point of the FR-7.1 wiring.
    """

    def __init__(self):
        self.viewer = []         # (user_id, chunk_id) — PERMANENT grants
        self.viewer_until = []   # (user_id, chunk_id, expiry_iso) — TIME-BOUND grants
        self.pending_revoked = []

    async def grant_viewer(self, user_id, chunk_id):
        self.viewer.append((user_id, chunk_id))

    async def grant_viewer_until(self, user_id, chunk_id, expiry_iso):
        self.viewer_until.append((user_id, chunk_id, expiry_iso))

    async def revoke_pending_approval(self, user_id, chunk_id):
        self.pending_revoked.append((user_id, chunk_id))


def _patch_singleton_and_ttl(monkeypatch, ttl):
    """Point the activity at a recording stub and set the grant TTL.

    Returns the stub so the test can inspect which grant path ran.
    """
    from config import settings
    from workflow import activities

    fga = _RecordingOpenFGA()

    async def _fake_get_openfga():
        return fga

    monkeypatch.setattr(activities, "_get_openfga", _fake_get_openfga)
    monkeypatch.setattr(settings, "approval_grant_ttl_seconds", ttl)
    return fga


def test_grant_expires(monkeypatch):
    # ttl > 0 → the approved grant is TIME-BOUND: grant_viewer_until is called with a
    # FUTURE expiry, and the permanent grant_viewer is NOT called.
    from workflow.activities import GrantAccessInput, grant_access_in_openfga

    ttl = 3600
    fga = _patch_singleton_and_ttl(monkeypatch, ttl)

    before = datetime.now(timezone.utc)
    asyncio.run(
        grant_access_in_openfga(
            GrantAccessInput(user_id="user:alice", chunk_ids=["c1", "c2"])
        )
    )

    # Permanent path must NOT be taken.
    assert fga.viewer == []
    # Time-bound path taken once per chunk.
    assert [(u, c) for (u, c, _exp) in fga.viewer_until] == [
        ("user:alice", "c1"),
        ("user:alice", "c2"),
    ]
    # The expiry is a real, parseable, FUTURE timestamp ~now+ttl (same ISO-8601 UTC
    # basis check() compares against — not a tautology).
    for _u, _c, exp_iso in fga.viewer_until:
        exp = datetime.fromisoformat(exp_iso)
        assert exp.tzinfo is not None, "expiry must be timezone-aware (UTC)"
        delta = (exp - before).total_seconds()
        # Future, and within a sane band of now+ttl (allow a little wall-clock slack).
        assert ttl - 5 <= delta <= ttl + 60
        assert exp > before
    # Pending tuples still cleaned up on approval.
    assert fga.pending_revoked == [("user:alice", "c1"), ("user:alice", "c2")]


def test_permanent_grant_when_ttl_zero(monkeypatch):
    # ttl == 0 (default/legacy) → permanent grant_viewer is called, grant_viewer_until
    # is NOT. This preserves the pre-FR-7.1 behaviour.
    from workflow.activities import GrantAccessInput, grant_access_in_openfga

    fga = _patch_singleton_and_ttl(monkeypatch, 0)

    asyncio.run(
        grant_access_in_openfga(
            GrantAccessInput(user_id="user:bob", chunk_ids=["c9"])
        )
    )

    assert fga.viewer == [("user:bob", "c9")]
    assert fga.viewer_until == []
    assert fga.pending_revoked == [("user:bob", "c9")]


def test_reask_reenters_approval():
    # FR-7.3: after a revoke the chunk is set back to pending_approval-only. A re-ask
    # then routes through decide() and must land on NEEDS_APPROVAL (the approval
    # workflow re-enters) — not ALLOWED (no stale viewer reuse), not DENIED.
    from auth import openfga as ofga

    auth = ofga.OpenFGAAuth()

    # Post-revoke state: viewer gone, pending_approval present (what the /revoke endpoint
    # leaves behind via revoke_viewer + set_pending_approval).
    async def _check(user_id, chunk_id, relation, groups=None):  # noqa: ANN001 - stub
        return relation == ofga.Relation.PENDING_APPROVAL

    auth.check = _check  # type: ignore[method-assign]

    decision = asyncio.run(auth.decide("user:alice", "chunk:q4"))
    assert decision == ofga.AuthzDecision.NEEDS_APPROVAL


def test_mosaic_outage_clearance_is_never_permanent(monkeypatch):
    # A clearance approved while the mosaic ledger was unreachable vouches only for that
    # moment: with permanent grants configured (ttl == 0) it is STILL time-bound
    # (mosaic_outage_clearance_ttl_seconds), while an ordinary chunk stays permanent.
    from agent.context_guard import ledger_unavailable_clearance_id
    from config import settings
    from workflow.activities import (OUTAGE_CLEARANCE_PREFIX, GrantAccessInput,
                                     grant_access_in_openfga)

    outage_id = ledger_unavailable_clearance_id(["financial", "hr"])
    assert outage_id.startswith(OUTAGE_CLEARANCE_PREFIX)   # pins the two modules together
    fga = _patch_singleton_and_ttl(monkeypatch, 0)
    monkeypatch.setattr(settings, "mosaic_outage_clearance_ttl_seconds", 900)

    before = datetime.now(timezone.utc)
    asyncio.run(grant_access_in_openfga(
        GrantAccessInput(user_id="user:alice", chunk_ids=["c1", outage_id, "mosaic-hr-finance"])))

    assert fga.viewer == [("user:alice", "c1"), ("user:alice", "mosaic-hr-finance")]
    assert [(u, c) for (u, c, _e) in fga.viewer_until] == [("user:alice", outage_id)]
    delta = (datetime.fromisoformat(fga.viewer_until[0][2]) - before).total_seconds()
    assert 895 <= delta <= 960


def test_mosaic_outage_clearance_takes_shorter_global_ttl(monkeypatch):
    from agent.context_guard import ledger_unavailable_clearance_id
    from config import settings
    from workflow.activities import GrantAccessInput, grant_access_in_openfga

    outage_id = ledger_unavailable_clearance_id(["hr"])
    fga = _patch_singleton_and_ttl(monkeypatch, 300)       # global TTL shorter than 900
    monkeypatch.setattr(settings, "mosaic_outage_clearance_ttl_seconds", 900)
    before = datetime.now(timezone.utc)
    asyncio.run(grant_access_in_openfga(GrantAccessInput(user_id="u", chunk_ids=[outage_id])))
    delta = (datetime.fromisoformat(fga.viewer_until[0][2]) - before).total_seconds()
    assert 295 <= delta <= 360
