"""M3 multi-peer trust-map tests (IMPLEMENTATION_PLAN.md M3).

The data-path trust anchor is settings.peer_trust ({peer_did: {issuer, public_jwk,
agent_url, division_id}}). These pin that the per-DID issuer binding — which the M2
security review validated at N=1 — STILL HOLDS at N>1 peers: a trusted peer can only
assert its OWN issuer's users, never another peer's. Plus the back-compat single-peer
fallback and the fail-closed-on-empty-issuer guard the advisor required.
"""
from __future__ import annotations

import json

import pytest

ALPHA_ISS = "http://localhost:9002/realms/rag"
BETA_ISS = "http://localhost:9102/realms/rag"
GAMMA_ISS = "http://localhost:9202/realms/rag"
GAMMA_DID = "did:mesh:gamma0000000000000000000000000000"
BETA_DID = "did:mesh:beta00000000000000000000000000000"


def _claims(iss, email="alice@example.com"):
    return {"iss": iss, "email": email, "email_verified": True, "sub": "x"}


def _map():
    return {
        GAMMA_DID: {"issuer": GAMMA_ISS, "public_jwk": "{}", "agent_url": "http://g", "division_id": "gamma"},
        BETA_DID: {"issuer": BETA_ISS, "public_jwk": "{}", "agent_url": "http://b", "division_id": "beta"},
    }


def test_peer_trust_map_parses_multi(make_settings):
    s = make_settings(peer_trust_map=json.dumps(_map()))
    assert set(s.peer_trust) == {GAMMA_DID, BETA_DID}
    assert s.peer_trust[GAMMA_DID]["issuer"] == GAMMA_ISS
    assert s.peer_trust[BETA_DID]["issuer"] == BETA_ISS


def test_peer_trust_falls_back_to_single_peer(make_settings):
    # One code path: an unset map synthesises a 1-entry map from the legacy PEER_AGENT_*.
    s = make_settings(peer_agent_did=BETA_DID, peer_agent_issuer=BETA_ISS, peer_agent_public_jwk="{}")
    assert list(s.peer_trust) == [BETA_DID]
    assert s.peer_trust[BETA_DID]["issuer"] == BETA_ISS


def test_trusted_peer_cannot_assert_another_peers_user(make_settings):
    # THE M3 discriminating test: alpha trusts BOTH beta and gamma. A gamma-signed
    # envelope asserting a BETA-issuer (or ALPHA-issuer) user is REJECTED, because the
    # receiver binds the assertion issuer to the SIGNER's (gamma's) map issuer.
    from auth.token_validator import assertion_principal
    s = make_settings(peer_trust_map=json.dumps(_map()))
    gamma_bound = s.peer_trust[GAMMA_DID]["issuer"]
    with pytest.raises(ValueError):
        assertion_principal(_claims(BETA_ISS, "ceo@example.com"), gamma_bound)   # gamma → beta's user
    with pytest.raises(ValueError):
        assertion_principal(_claims(ALPHA_ISS), gamma_bound)                     # gamma → alpha's user
    got = assertion_principal(_claims(GAMMA_ISS), gamma_bound)                   # gamma → its OWN user: ok
    assert got.startswith("alice@example.com|")


def test_empty_issuer_entry_fails_closed(make_settings):
    # A half-populated map entry (blank issuer) must NOT widen acceptance.
    from auth.token_validator import assertion_principal
    s = make_settings(peer_trust_map=json.dumps(
        {GAMMA_DID: {"issuer": "", "public_jwk": "{}", "agent_url": "http://g", "division_id": "gamma"}}))
    with pytest.raises(ValueError):
        assertion_principal(_claims(GAMMA_ISS), s.peer_trust[GAMMA_DID]["issuer"])
