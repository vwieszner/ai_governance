"""AgentMesh DID-identity proving tests (IMPLEMENTATION_PLAN.md traceability — mesh).

These pin the zero-trust message-verification controls in mesh.agent_identity that
existing suites name but do not directly exercise:

  * multi-peer DID resolution — the signer's PUBLIC key is taken from the trusted
    peer_trust MAP keyed by the CLAIMED DID, never from the message body; one of N
    trusted peers is resolved correctly;
  * replay rejection — a byte-identical re-send (reused nonce) and a stale timestamp
    are both refused, AFTER signature verification (so the nonce cache can't be poisoned);
  * untrusted-peer rejection — a DID absent from the trust map is refused fail-closed,
    and so is a forged envelope that merely NAMES a trusted DID (the trusted key wins).

Hermetic: real Ed25519 identities are minted in-process (AgentIdentity.create) and the
module-global ``settings``/singletons are swapped for a fake trust map — no live mesh,
no network. Complements tests/test_multipeer.py (which pins the issuer→signer binding in
auth.token_validator) by covering the signature/replay layer in mesh.agent_identity.
"""
from __future__ import annotations

import json
import time
import uuid

import pytest

import mesh.agent_identity as ai
from mesh.agent_identity import AgentIdentity, _canonical_bytes


class _FakeSettings:
    """Stand-in for config.settings holding only what the verify path reads."""

    cluster_id = "test"
    division_id = "test"

    def __init__(self, peer_trust: dict) -> None:
        self.peer_trust = peer_trust


def _trust_entry(identity: AgentIdentity, issuer: str, division_id: str) -> dict:
    return {
        "issuer": issuer,
        "public_jwk": json.dumps(identity.to_jwk(include_private=False)),
        "agent_url": f"http://{division_id}",
        "division_id": division_id,
    }


def _sign_as(identity: AgentIdentity, body: dict | None = None) -> dict:
    """Build a signed message envelope using *identity*'s real Ed25519 key.

    Mirrors sign_outbound_message: a fresh ts+nonce go INSIDE the signed body so the
    signature covers them; the _agentmesh envelope carries the sender DID + signature.
    """
    signed = dict(body or {"query": "hello"})
    signed["ts"] = int(time.time())
    signed["nonce"] = str(uuid.uuid4())
    signature = identity.sign(_canonical_bytes(signed))
    signed["_agentmesh"] = {
        "sender_did": str(identity.did),
        "signature": signature,
        "alg": "EdDSA",
    }
    return signed


@pytest.fixture
def two_peer_trust(monkeypatch):
    """Mint a self identity + two trusted peers (alpha, beta); install a 2-entry map.

    Returns (alpha, beta) whose DIDs are BOTH keys in settings.peer_trust. Resets the
    replay nonce cache and identity-registry singleton so tests don't bleed into each
    other.
    """
    self_id = AgentIdentity.create(name="self", sponsor="self@example.com")
    alpha = AgentIdentity.create(name="alpha", sponsor="alpha@example.com")
    beta = AgentIdentity.create(name="beta", sponsor="beta@example.com")

    trust = {
        str(alpha.did): _trust_entry(alpha, "http://alpha/realms/rag", "alpha"),
        str(beta.did): _trust_entry(beta, "http://beta/realms/rag", "beta"),
    }
    monkeypatch.setattr(ai, "settings", _FakeSettings(trust))
    # Deterministic, isolated module state.
    monkeypatch.setattr(ai, "_seen_nonces", {})
    monkeypatch.setattr(ai, "_identity", self_id)
    monkeypatch.setattr(ai, "_identity_registry", None)
    return alpha, beta


async def test_multi_peer_did_resolution(two_peer_trust):
    """A signer's key is resolved by its CLAIMED DID from the multi-peer trust map.

    With TWO trusted peers configured, a message signed by beta verifies — the
    verifier picks beta's key out of the map by the claimed DID, not alpha's, and not
    any key shipped in the body. The verified signer DID is returned to the caller.
    """
    alpha, beta = two_peer_trust

    ok_beta, did_beta = await ai.verify_signed_message(_sign_as(beta))
    assert ok_beta is True
    assert did_beta == str(beta.did)

    # The OTHER trusted peer also resolves correctly from the same map (N>1 works).
    ok_alpha, did_alpha = await ai.verify_signed_message(_sign_as(alpha))
    assert ok_alpha is True
    assert did_alpha == str(alpha.did)


async def test_multi_peer_key_not_taken_from_message_body(two_peer_trust):
    """Forged: beta SIGNS but the envelope CLAIMS alpha's DID.

    The verifier resolves alpha's key from the trusted map (because the claimed DID is
    alpha) and verifies beta's signature against it — which fails. A message can never
    smuggle its own verification key, so naming a trusted DID is not enough.
    """
    alpha, beta = two_peer_trust

    forged = _sign_as(beta)
    forged.pop("_agentmesh")
    forged["_agentmesh"] = {
        "sender_did": str(alpha.did),               # CLAIM alpha
        "signature": beta.sign(_canonical_bytes(forged)),  # but signed by beta
        "alg": "EdDSA",
    }
    ok, did = await ai.verify_signed_message(forged)
    assert ok is False
    assert did is None


async def test_replay_rejected(two_peer_trust):
    """A byte-identical re-send (reused nonce) and a stale timestamp are both refused."""
    alpha, _beta = two_peer_trust

    msg = _sign_as(alpha)
    ok_first, _ = await ai.verify_signed_message(msg)
    assert ok_first is True                         # first delivery accepted

    # Exact replay of the captured message — same (sender_did, nonce) → rejected.
    ok_replay, _ = await ai.verify_signed_message(msg)
    assert ok_replay is False

    # A fresh nonce but a timestamp outside the freshness window → rejected.
    stale = dict(msg)
    stale.pop("_agentmesh")
    stale["ts"] = int(time.time()) - (ai._REPLAY_MAX_AGE_SECONDS + 60)
    stale["nonce"] = str(uuid.uuid4())
    stale["_agentmesh"] = {
        "sender_did": str(alpha.did),
        "signature": alpha.sign(_canonical_bytes(stale)),
        "alg": "EdDSA",
    }
    ok_stale, _ = await ai.verify_signed_message(stale)
    assert ok_stale is False


async def test_untrusted_peer_rejected(two_peer_trust):
    """A correctly-signed message from a DID that is NOT in the trust map is refused.

    Fail-closed: the membership check in the trusted-peers map is THE data-path trust
    decision, so a real, validly-signed identity that was never configured as a peer is
    rejected before any signature work.
    """
    _alpha, _beta = two_peer_trust
    stranger = AgentIdentity.create(name="stranger", sponsor="stranger@example.com")

    ok, did = await ai.verify_signed_message(_sign_as(stranger))
    assert ok is False
    assert did is None


async def test_untrusted_peer_refused_by_registry(two_peer_trust):
    """verify_peer_identity is fail-closed for a DID outside the trust map, and floors a
    configured peer into the trusted tier.

    A trusted peer (in the map → registered in the IdentityRegistry) verifies with a
    trust score at the library's TIER_TRUSTED_THRESHOLD; a stranger DID returns
    (False, 0.0).
    """
    _alpha, beta = two_peer_trust

    ok_beta, score_beta = await ai.verify_peer_identity(str(beta.did))
    assert ok_beta is True
    assert score_beta >= 0.6                        # trusted-tier floor (peer-comms gate)

    stranger = AgentIdentity.create(name="stranger", sponsor="stranger@example.com")
    ok_stranger, score_stranger = await ai.verify_peer_identity(str(stranger.did))
    assert ok_stranger is False
    assert score_stranger == 0.0
