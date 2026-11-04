"""M1 per-division identity tests (IMPLEMENTATION_PLAN.md M1, FR-2.4).

Proves the core multi-division identity guarantee: a JWT minted by ONE division's
Keycloak (its issuer + its agent audience, signed by its key) is accepted by THAT
division's agent and REJECTED by any other division's agent. The rejection is
enforced three independent ways in auth.token_validator.validate_token — issuer
check, audience check, and JWKS signing-key isolation — so cross-division identity
cannot be forged or replayed by mere token possession (the AUD-1 fix: per-division
realms + single-division audience).

Hermetic: signs a real RS256 token with a throwaway key and mocks the JWKS fetch,
so it runs by default with no live Keycloak.
"""
from __future__ import annotations

import asyncio

import pytest
import jwt

from auth.token_validator import JWTError


def _keypair_and_jwks(kid: str = "div-key-1"):
    """Throwaway RSA keypair -> (private PEM, public-JWKS dict for the validator)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    jwk_dict = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk_dict.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return priv_pem, {"keys": [jwk_dict]}


def _mint(priv_pem: str, issuer: str, audience: str, sub: str = "alice-sub", kid: str = "div-key-1") -> str:
    import time
    now = int(time.time())
    return jwt.encode(
        {"sub": sub, "iss": issuer, "aud": audience, "iat": now, "exp": now + 3600},
        priv_pem, algorithm="RS256", headers={"kid": kid},
    )


def _configure(monkeypatch, make_settings, jwks, *, issuer: str, audience: str):
    from auth import token_validator as tv
    s = make_settings(oidc_issuer=issuer, agent_client_id=audience,
                      allowed_jwt_algorithms="RS256")
    monkeypatch.setattr(tv, "settings", s)

    async def _fake_jwks(force_refresh: bool = False):
        return jwks

    monkeypatch.setattr(tv, "_get_jwks", _fake_jwks)
    return tv


DIV_A_ISS = "http://localhost:8102/realms/rag"
DIV_A_AUD = "agent-alpha"
DIV_B_ISS = "http://localhost:8202/realms/rag"
DIV_B_AUD = "agent-beta"


def test_token_scoped_to_division(make_settings, monkeypatch):
    """A division's OWN agent accepts a token minted by its OWN Keycloak."""
    priv, jwks = _keypair_and_jwks()
    token = _mint(priv, issuer=DIV_A_ISS, audience=DIV_A_AUD)
    tv = _configure(monkeypatch, make_settings, jwks, issuer=DIV_A_ISS, audience=DIV_A_AUD)
    claims = asyncio.run(tv.validate_token(token))
    assert claims["sub"] == "alice-sub"


def test_foreign_division_token_rejected_on_issuer_and_audience(make_settings, monkeypatch):
    """Division B's agent REJECTS a division-A token (issuer + audience mismatch).

    Same signing key is in B's mocked JWKS here, to isolate the issuer/audience
    checks; even with a valid signature, the token is refused for the wrong division.
    """
    priv, jwks = _keypair_and_jwks()
    a_token = _mint(priv, issuer=DIV_A_ISS, audience=DIV_A_AUD)
    tv = _configure(monkeypatch, make_settings, jwks, issuer=DIV_B_ISS, audience=DIV_B_AUD)
    with pytest.raises(JWTError):
        asyncio.run(tv.validate_token(a_token))


def test_foreign_division_token_rejected_on_unknown_signing_key(make_settings, monkeypatch):
    """Even ignoring issuer/audience, B's JWKS does not contain A's signing key, so
    A's token cannot be signature-verified by B (key isolation per realm)."""
    a_priv, _a_jwks = _keypair_and_jwks(kid="div-a-key")
    _b_priv, b_jwks = _keypair_and_jwks(kid="div-b-key")   # B publishes a DIFFERENT key
    a_token = _mint(a_priv, issuer=DIV_A_ISS, audience=DIV_A_AUD, kid="div-a-key")
    # Configure B's agent with B's issuer/aud AND B's JWKS (no A key present).
    tv = _configure(monkeypatch, make_settings, b_jwks, issuer=DIV_A_ISS, audience=DIV_A_AUD)
    with pytest.raises(JWTError):
        asyncio.run(tv.validate_token(a_token))


def test_admin_user_lifecycle():
    """FR-2.3 (live; skips if alpha not onboarded/up): the division RBAC realm roles
    exist and are assigned — alice=member, bob=data-owner+division-admin."""
    import json

    import httpx

    from scripts.onboard_division import GENERATED_DIR

    gd = GENERATED_DIR / "alpha"
    sp, ep = gd / "secrets.json", gd / "div-alpha.env"
    if not (sp.exists() and ep.exists()):
        pytest.skip("alpha not onboarded")
    sec = json.loads(sp.read_text(encoding="utf-8"))
    env = {k.strip(): v.strip() for k, _, v in
           (ln.partition("=") for ln in ep.read_text(encoding="utf-8").splitlines() if "=" in ln)}
    kc = f"http://localhost:{env['DIV_KEYCLOAK_PORT']}"
    try:
        tok = httpx.post(f"{kc}/realms/master/protocol/openid-connect/token",
                         data={"grant_type": "password", "client_id": "admin-cli",
                               "username": "admin", "password": sec["keycloak_admin_password"]},
                         timeout=5).json()["access_token"]
    except Exception:
        pytest.skip("alpha keycloak not reachable")
    h = {"Authorization": f"Bearer {tok}"}

    def _user_roles(username: str) -> set[str]:
        uid = httpx.get(f"{kc}/admin/realms/rag/users",
                        params={"username": username, "exact": "true"}, headers=h).json()[0]["id"]
        return {r["name"] for r in
                httpx.get(f"{kc}/admin/realms/rag/users/{uid}/role-mappings/realm", headers=h).json()}

    all_roles = {r["name"] for r in httpx.get(f"{kc}/admin/realms/rag/roles", headers=h).json()}
    assert {"member", "data-owner", "division-admin"} <= all_roles
    assert "member" in _user_roles("alice")
    assert {"data-owner", "division-admin"} <= _user_roles("bob")
