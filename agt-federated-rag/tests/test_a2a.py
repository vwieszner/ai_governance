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
