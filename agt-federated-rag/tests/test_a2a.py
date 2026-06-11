"""M2 verifiable cross-division identity tests (IMPLEMENTATION_PLAN.md M2, FR-3.6).

Security-hardened design: a cross-division user assertion is NOT the user's raw
home-division token (that would be a replayable bearer credential a compromised
receiving division could replay against the user's HOME APIs). Instead the
originating division forwards the user's already-VALIDATED identity CLAIMS
(sub/email/email_verified/iss) inside the DID-signed, replay-protected peer envelope.
The receiver:
  1. verifies the Ed25519 envelope signature (-> signer DID) + ts/nonce freshness,
  2. binds the asserted `iss` to THAT specific signer (settings.peer_agent_issuer) —
     NOT to the trusted-issuer SET (which in a 3+ division mesh would let a
     compromised-but-trusted peer assert ANOTHER division's user),
  3. derives the OpenFGA principal (verified email, namespaced by the signer-bound iss).

These hermetic tests pin both layers: the namespaced principal and the signer-bound
assertion validation (auth.token_validator.assertion_principal / minimal_assertion_claims).
"""
from __future__ import annotations

import pytest

ALPHA_ISS = "http://localhost:8402/realms/rag"   # division alpha
GAMMA_ISS = "http://localhost:8302/realms/rag"   # a DIFFERENT trusted division


def _claims(iss, email="alice@example.com", verified=True, sub="x"):
    return {"iss": iss, "email": email, "email_verified": verified, "sub": sub}


# ── Namespaced authorization principal (the federated-trust security boundary) ──

def test_principal_is_namespaced_by_issuer():
    from auth.token_validator import principal
    p = principal(_claims(ALPHA_ISS))
    assert p.startswith("alice@example.com|")
    assert len(p.split("|")[1]) == 16            # 16-hex issuer namespace


def test_principal_stable_for_same_issuer_and_email():
    from auth.token_validator import principal
    assert principal(_claims(ALPHA_ISS)) == principal(_claims(ALPHA_ISS))


def test_principal_distinct_across_issuers():
    from auth.token_validator import principal
    assert principal(_claims(ALPHA_ISS)) != principal(_claims(GAMMA_ISS))


def test_principal_requires_verified_email():
    from auth.token_validator import principal
    with pytest.raises(ValueError):
        principal(_claims(ALPHA_ISS, verified=False))     # email_verified=false
    with pytest.raises(ValueError):
        principal({"iss": ALPHA_ISS, "sub": "x"})         # no email at all


def test_seed_principal_matches_runtime_principal():
    # onboard seeds tuples; the agent looks them up at runtime — the two MUST agree
    # byte-for-byte or every authorization silently fails closed.
    from auth.token_validator import principal
    from scripts.onboard_division import _seed_principal
    seeded = _seed_principal("Alice@Example.com", ALPHA_ISS)   # note casing/normalise
    runtime = principal(_claims(ALPHA_ISS, "alice@example.com"))
    assert seeded == runtime


# ── Signer-bound cross-division assertion (no bearer token; no replay) ──────────

def test_minimal_assertion_claims_is_subset_no_token():
    # What the originating division forwards: identity claims only — never a token.
    from auth.token_validator import minimal_assertion_claims
    full = {"iss": ALPHA_ISS, "email": "alice@example.com", "email_verified": True,
            "sub": "abc", "aud": "agent-alpha", "exp": 9999999999, "secret": "leak?"}
    out = minimal_assertion_claims(full)
    assert set(out) == {"sub", "email", "email_verified", "iss"}
    assert "aud" not in out and "exp" not in out and "secret" not in out


def test_assertion_principal_accepts_signer_bound_issuer():
    from auth.token_validator import assertion_principal, principal
    got = assertion_principal(_claims(ALPHA_ISS), expected_issuer=ALPHA_ISS)
    assert got == principal(_claims(ALPHA_ISS))


def test_assertion_principal_rejects_issuer_not_bound_to_signer():
    # THE security property: a (compromised-but-trusted) peer whose bound issuer is
    # alpha asserts a GAMMA user. Even though the claims are well-formed and gamma is
    # a real division, binding the issuer to the SIGNER rejects it — no cross-issuer
    # impersonation. (Set-membership in trusted_issuers would WRONGLY accept this.)
    from auth.token_validator import assertion_principal
    with pytest.raises(ValueError):
        assertion_principal(_claims(GAMMA_ISS, email="ceo@example.com"),
                            expected_issuer=ALPHA_ISS)


def test_assertion_principal_requires_verified_email():
    from auth.token_validator import assertion_principal
    with pytest.raises(ValueError):
        assertion_principal(_claims(ALPHA_ISS, verified=False), expected_issuer=ALPHA_ISS)


def test_assertion_principal_fails_closed_without_bound_issuer():
    # If no issuer is bound to the signer (misconfig), refuse — never fall back to
    # accepting any issuer.
    from auth.token_validator import assertion_principal
    with pytest.raises(ValueError):
        assertion_principal(_claims(ALPHA_ISS), expected_issuer="")


def test_assertion_principal_rejects_non_dict():
    # A raw string (e.g., a forwarded token) must not be accepted as an assertion.
    from auth.token_validator import assertion_principal
    with pytest.raises(ValueError):
        assertion_principal("eyJhbGciOi...", expected_issuer=ALPHA_ISS)  # type: ignore[arg-type]
