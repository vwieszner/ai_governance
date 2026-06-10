"""M2 verifiable cross-division identity tests (IMPLEMENTATION_PLAN.md M2, FR-3.6).

Spike outcome: Keycloak cannot mint a token whose audience is another division's
client (cross-realm audience -> "Audience not found"). So a cross-division user
assertion is the user's HOME-division token, forwarded in the DID-signed peer
envelope, and the receiver validates it against the TRUSTED-ISSUER SET — signature
+ issuer(in trusted set) + expiry + sub, but NOT the receiver's audience. These
tests prove that primitive: a trusted-issuer assertion is accepted; an untrusted
issuer, a forged signature, and an expired assertion are all rejected. The receiver
then re-authorizes the sub via its own OpenFGA (the /a2a/query integration).
Hermetic: real RS256 tokens + mocked JWKS, runs by default.
"""
from __future__ import annotations

import asyncio
import time

import pytest
from jose import JWTError, jwt


def _keypair_and_jwks(kid: str = "peer-key-1"):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jose import jwk

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    jd = jwk.construct(pub, "RS256").to_dict()
    jd.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return priv, {"keys": [jd]}


def _mint(priv, issuer, sub="alice-sub", kid="peer-key-1", aud="agent-alpha", ttl=3600):
    now = int(time.time())
    return jwt.encode({"sub": sub, "iss": issuer, "aud": aud, "iat": now, "exp": now + ttl},
                      priv, algorithm="RS256", headers={"kid": kid})


PEER_ISS = "http://localhost:8102/realms/rag"      # division alpha (a trusted peer)
UNTRUSTED_ISS = "http://evil.example/realms/rag"


def _setup(monkeypatch, make_settings, jwks, trusted=PEER_ISS):
    from auth import token_validator as tv
    s = make_settings(trusted_issuers=trusted, allowed_jwt_algorithms="RS256")
    monkeypatch.setattr(tv, "settings", s)

    async def _fake_fetch(_uri):
        return jwks

    monkeypatch.setattr(tv, "_fetch_jwks_for", _fake_fetch)
    return tv


def test_user_assertion_validated(make_settings, monkeypatch):
    priv, jwks = _keypair_and_jwks()
    tv = _setup(monkeypatch, make_settings, jwks)
    token = _mint(priv, issuer=PEER_ISS, aud="agent-alpha")  # aud is the HOME agent, not us
    claims = asyncio.run(tv.validate_peer_user_assertion(token))
    assert claims["sub"] == "alice-sub"          # validated despite foreign audience


def test_untrusted_issuer_rejected(make_settings, monkeypatch):
    priv, jwks = _keypair_and_jwks()
    tv = _setup(monkeypatch, make_settings, jwks, trusted=PEER_ISS)
    token = _mint(priv, issuer=UNTRUSTED_ISS)     # issuer NOT in the trusted set
    with pytest.raises(JWTError):
        asyncio.run(tv.validate_peer_user_assertion(token))


def test_forged_user_assertion_rejected(make_settings, monkeypatch):
    # Token signed by a DIFFERENT key than the issuer's published JWKS.
    forger_priv, _ = _keypair_and_jwks(kid="peer-key-1")
    _real_priv, real_jwks = _keypair_and_jwks(kid="peer-key-1")
    tv = _setup(monkeypatch, make_settings, real_jwks)
    token = _mint(forger_priv, issuer=PEER_ISS)   # right issuer/kid, wrong key
    with pytest.raises(JWTError):
        asyncio.run(tv.validate_peer_user_assertion(token))


def test_expired_assertion_rejected(make_settings, monkeypatch):
    priv, jwks = _keypair_and_jwks()
    tv = _setup(monkeypatch, make_settings, jwks)
    token = _mint(priv, issuer=PEER_ISS, ttl=-10)  # already expired
    with pytest.raises(JWTError):
        asyncio.run(tv.validate_peer_user_assertion(token))


# ── Namespaced authorization principal (the federated-trust security boundary) ──
#
# The OpenFGA principal is (verified-issuer, email), NOT a bare email/sub. Without
# the issuer namespace, trusting ANY issuer would let it mint email=<anyone> and
# impersonate every user in the federation (email_verified does not help — the
# receiver can't check the home realm actually verified it). These tests pin that
# property: same (iss,email) is stable; a DIFFERENT trusted issuer claiming the same
# email yields a DIFFERENT principal (no impersonation); unverified email is refused.

ALPHA_ISS = "http://localhost:8102/realms/rag"
GAMMA_ISS = "http://localhost:8302/realms/rag"


def _claims(iss, email="alice@example.com", verified=True):
    return {"iss": iss, "email": email, "email_verified": verified, "sub": "x"}


def test_principal_is_namespaced_by_issuer():
    from auth.token_validator import principal
    p = principal(_claims(ALPHA_ISS))
    assert p.startswith("alice@example.com|")
    assert len(p.split("|")[1]) == 16            # 16-hex issuer namespace


def test_principal_stable_for_same_issuer_and_email():
    from auth.token_validator import principal
    assert principal(_claims(ALPHA_ISS)) == principal(_claims(ALPHA_ISS))


def test_trusted_issuer_cannot_impersonate_another_divisions_user():
    # THE security property: gamma is a trusted issuer, but a gamma-signed token
    # claiming alice's email must NOT resolve to alice's alpha principal.
    from auth.token_validator import principal
    alice_at_alpha = principal(_claims(ALPHA_ISS, "alice@example.com"))
    alice_forged_by_gamma = principal(_claims(GAMMA_ISS, "alice@example.com"))
    assert alice_at_alpha != alice_forged_by_gamma  # impersonation blocked


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
