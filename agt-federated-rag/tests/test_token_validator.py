"""auth.token_validator behaviour pins (PyJWT backend).

python-jose was replaced by PyJWT because of PYSEC-2026-4298 (python-jose <= 3.5.0
accepts a DER-encoded public key as an HMAC secret, so anyone holding the JWKS public
key can forge an HS256 token). These tests pin that the forgery is refused, and that
every behaviour the validator had under python-jose is kept: header-alg allow-list,
JWKS kid lookup with ONE forced refresh on a miss, MED-7 key-alg binding,
aud/iss/exp verification, iat-must-be-an-integer (without a future-iat clock check),
JWTError on any token failure, and AuthServiceUnavailable on a JWKS outage.

Hermetic: throwaway keys, the JWKS fetch is mocked.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ISS = "http://kc.alpha:8080/realms/rag"
AUD = "agent-alpha"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _rsa(kid: str = "k1", *, alg: str | None = "RS256"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    j = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    j.update({"kid": kid, "use": "sig"})
    if alg:
        j["alg"] = alg
    return key, j


def _claims(**over):
    now = int(time.time())
    c = {"sub": "alice-sub", "iss": ISS, "aud": AUD, "iat": now, "exp": now + 600}
    c.update(over)
    return c


def _sign(key, claims, *, kid="k1", alg="RS256") -> str:
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def _forge_hs256(secret: bytes, claims, *, kid="k1") -> str:
    """Hand-rolled HS256 token keyed with *secret* (PyJWT itself refuses asymmetric
    key material as an HMAC secret, so the attacker would not use PyJWT to mint it)."""
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    payload = _b64(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(sig)}"


@pytest.fixture
def tv(make_settings, monkeypatch):
    """token_validator configured for alpha with a JWKS served from a mutable list."""
    from auth import token_validator as mod

    state = {"jwks": {"keys": []}, "fetches": [], "algs": "RS256,ES256"}

    def configure(*, keys, algs="RS256,ES256", rotated_keys=None):
        s = make_settings(oidc_issuer=ISS, agent_client_id=AUD, allowed_jwt_algorithms=algs)
        monkeypatch.setattr(mod, "settings", s)
        state["jwks"] = {"keys": list(keys)}
        state["rotated"] = {"keys": list(rotated_keys)} if rotated_keys is not None else None
        return mod

    async def fake_get_jwks(force_refresh: bool = False):
        state["fetches"].append(force_refresh)
        if force_refresh and state.get("rotated") is not None:
            return state["rotated"]
        return state["jwks"]

    monkeypatch.setattr(mod, "_get_jwks", fake_get_jwks)
    monkeypatch.setattr(mod, "configure", configure, raising=False)
    monkeypatch.setattr(mod, "fetches", state["fetches"], raising=False)
    return mod


def _run(mod, token):
    return asyncio.run(mod.validate_token(token))


def test_jwterror_is_the_pyjwt_base_exception():
    from auth.token_validator import JWTError
    assert JWTError is jwt.PyJWTError
    import api.main as main
    assert main.JWTError is jwt.PyJWTError       # the 401 mapping catches the same type


def test_valid_rs256_token_accepted(tv):
    key, j = _rsa()
    mod = tv.configure(keys=[j])
    assert _run(mod, _sign(key, _claims()))["sub"] == "alice-sub"


def test_valid_es256_token_accepted(tv):
    key = ec.generate_private_key(ec.SECP256R1())
    j = jwt.algorithms.ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
    j.update({"kid": "e1", "alg": "ES256"})
    mod = tv.configure(keys=[j])
    assert _run(mod, _sign(key, _claims(), kid="e1", alg="ES256"))["iss"] == ISS


# ── PYSEC-2026-4298 regression: HS256 keyed with the public key material ──────────


def _public_key_secrets(key):
    pub = key.public_key()
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    pkcs1 = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    return {"der-spki": der, "pem": pem, "der-pkcs1": pkcs1}


@pytest.mark.parametrize("material", ["der-spki", "pem", "der-pkcs1"])
@pytest.mark.parametrize(
    "algs,jwk_alg",
    [
        ("RS256,ES256", "RS256"),   # default deployment posture
        ("RS256,ES256,HS256", "RS256"),   # HS256 mis-allowed: MED-7 key alg binding refuses
        ("RS256,ES256,HS256", None),      # ...and with no key alg: PyJWK refuses RSA-as-HMAC
    ],
)
def test_hs256_forged_with_jwks_public_key_is_rejected(tv, material, algs, jwk_alg):
    key, j = _rsa(alg=jwk_alg)
    mod = tv.configure(keys=[j], algs=algs)
    forged = _forge_hs256(_public_key_secrets(key)[material], _claims())
    with pytest.raises(mod.JWTError):
        _run(mod, forged)


# ── Algorithm allow-list + MED-7 ─────────────────────────────────────────────────


def test_header_alg_outside_allow_list_rejected_before_jwks(tv):
    key, j = _rsa(alg="RS384")
    mod = tv.configure(keys=[j], algs="RS256,ES256")
    with pytest.raises(mod.JWTError, match="not permitted"):
        _run(mod, _sign(key, _claims(), alg="RS384"))
    assert mod.fetches == []                       # refused before any JWKS access


def test_none_alg_rejected(tv):
    _key, j = _rsa()
    mod = tv.configure(keys=[j])
    unsigned = jwt.encode(_claims(), None, algorithm="none", headers={"kid": "k1"})
    with pytest.raises(mod.JWTError):
        _run(mod, unsigned)


def test_med7_key_alg_must_match_header_alg(tv):
    """A JWK published for ES256 is never used to verify an RS256 token with its kid."""
    key, _ = _rsa(kid="k1")
    ec_key = ec.generate_private_key(ec.SECP256R1())
    j = jwt.algorithms.ECAlgorithm.to_jwk(ec_key.public_key(), as_dict=True)
    j.update({"kid": "k1", "alg": "ES256"})
    mod = tv.configure(keys=[j])
    with pytest.raises(mod.JWTError, match="key confusion"):
        _run(mod, _sign(key, _claims()))


def test_missing_kid_rejected(tv):
    key, j = _rsa()
    mod = tv.configure(keys=[j])
    with pytest.raises(mod.JWTError, match="kid"):
        _run(mod, jwt.encode(_claims(), key, algorithm="RS256"))


def test_malformed_token_rejected(tv):
    _key, j = _rsa()
    mod = tv.configure(keys=[j])
    with pytest.raises(mod.JWTError):
        _run(mod, "not-a-jwt")


# ── JWKS kid lookup + one forced refresh ──────────────────────────────────────────


def test_unknown_kid_forces_exactly_one_refresh_then_accepts_rotated_key(tv):
    old_key, old_j = _rsa(kid="old")
    new_key, new_j = _rsa(kid="new")
    mod = tv.configure(keys=[old_j], rotated_keys=[old_j, new_j])
    assert _run(mod, _sign(new_key, _claims(), kid="new"))["sub"] == "alice-sub"
    assert mod.fetches == [False, True]


def test_unknown_kid_after_refresh_rejected(tv):
    _k, j = _rsa(kid="known")
    stranger, _ = _rsa(kid="stranger")
    mod = tv.configure(keys=[j], rotated_keys=[j])
    with pytest.raises(mod.JWTError, match="No JWKS key"):
        _run(mod, _sign(stranger, _claims(), kid="stranger"))
    assert mod.fetches == [False, True]            # one refresh, no loop


# ── Claim verification ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("over", [
    {"aud": "agent-beta"},
    {"iss": "http://kc.beta:8080/realms/rag"},
    {"exp": int(time.time()) - 5},
    {"iat": "yesterday"},
])
def test_bad_claims_rejected(tv, over):
    key, j = _rsa()
    mod = tv.configure(keys=[j])
    with pytest.raises(mod.JWTError):
        _run(mod, _sign(key, _claims(**over)))


def test_missing_aud_rejected(tv):
    """Stricter than python-jose (which skipped a MISSING aud when an audience was
    configured): Keycloak tokens carry the division audience via the audience mapper
    added at onboarding, so an aud-less token is refused."""
    key, j = _rsa()
    mod = tv.configure(keys=[j])
    c = _claims()
    del c["aud"]
    with pytest.raises(mod.JWTError):
        _run(mod, _sign(key, c))


def test_slightly_future_iat_still_accepted(tv):
    """python-jose never compared iat with the local clock; keep that so an IdP whose
    clock runs a little ahead does not lock users out (exp stays strict, no leeway)."""
    key, j = _rsa()
    mod = tv.configure(keys=[j])
    assert _run(mod, _sign(key, _claims(iat=int(time.time()) + 30)))["sub"] == "alice-sub"


def test_wrong_signing_key_rejected(tv):
    _published, j = _rsa(kid="k1")
    attacker, _ = _rsa(kid="k1")
    mod = tv.configure(keys=[j])
    with pytest.raises(mod.JWTError):
        _run(mod, _sign(attacker, _claims()))


# ── JWKS outage → AuthServiceUnavailable ──────────────────────────────────────────


@pytest.mark.parametrize("failure", ["connect", "http500", "not-json"])
def test_jwks_outage_raises_auth_service_unavailable(make_settings, monkeypatch, failure):
    from auth import token_validator as mod

    monkeypatch.setattr(mod, "settings", make_settings(
        oidc_issuer=ISS, agent_client_id=AUD, allowed_jwt_algorithms="RS256"))
    monkeypatch.setattr(mod, "_JWKS_CACHE", None)

    def handler(request):
        if failure == "connect":
            raise httpx.ConnectError("down", request=request)
        if failure == "http500":
            return httpx.Response(500)
        return httpx.Response(200, content=b"<html>")

    real_client = httpx.AsyncClient
    monkeypatch.setattr(mod.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    key, _ = _rsa()
    with pytest.raises(mod.AuthServiceUnavailable):
        asyncio.run(mod.validate_token(_sign(key, _claims())))
