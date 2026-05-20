"""
RFC 8693 OAuth 2.0 Token Exchange.

Pattern (per CoSAI / Stacklok ToolHive guidance):
  1. User authenticates → user JWT (sub = user_id)
  2. Agent presents its own client credentials + user JWT
  3. Authorization server returns a delegated token with:
       sub = user_id   (the original user)
       act = agent_id  (this agent's identity)
       aud = target    (the downstream service/agent)

The downstream service authorizes on `sub` (the user) but logs/rate-limits on `act` (the agent).
Never forward the raw user token to downstream services.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
import structlog
from jose import JWTError, jwk, jwt

from config import settings

log = structlog.get_logger(__name__)

_JWKS_CACHE: dict[str, Any] = {}
_JWKS_CACHE_TTL: float = 3600.0
_jwks_fetched_at: float = 0.0


@dataclass
class DelegatedToken:
    access_token: str
    token_type: str
    expires_in: int
    issued_token_type: str = "urn:ietf:params:oauth:token-type:access_token"


async def exchange_token(
    user_token: str,
    target_audience: str,
) -> DelegatedToken:
    """
    Perform RFC 8693 token exchange.

    Args:
        user_token      : The user's JWT (subject_token).
        target_audience : The downstream service URL / audience claim.

    Returns:
        DelegatedToken with the exchanged token.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            settings.oidc_token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": user_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": target_audience,
                "scope": "openid profile",
                # Agent authenticates itself via client_credentials
                "client_id": settings.agent_client_id,
                "client_secret": settings.agent_client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()

    return DelegatedToken(
        access_token=data["access_token"],
        token_type=data.get("token_type", "Bearer"),
        expires_in=data.get("expires_in", 3600),
        issued_token_type=data.get(
            "issued_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
    )


async def _fetch_jwks() -> dict[str, Any]:
    global _jwks_fetched_at, _JWKS_CACHE
    now = time.monotonic()
    if _JWKS_CACHE and (now - _jwks_fetched_at) < _JWKS_CACHE_TTL:
        return _JWKS_CACHE
    async with httpx.AsyncClient() as client:
        resp = await client.get(settings.oidc_jwks_uri)
        resp.raise_for_status()
        _JWKS_CACHE = resp.json()
        _jwks_fetched_at = now
    return _JWKS_CACHE


async def validate_token(token: str) -> dict[str, Any]:
    """
    Validate a JWT (user or delegated) and return its claims.

    Raises JWTError on invalid/expired tokens.
    """
    jwks = await _fetch_jwks()
    # Get the key ID from the token header
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    signing_key = None
    for key_data in jwks.get("keys", []):
        if not kid or key_data.get("kid") == kid:
            signing_key = jwk.construct(key_data)
            break

    if signing_key is None:
        raise JWTError("No matching signing key found in JWKS")

    claims: dict[str, Any] = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256", "ES256"],
        audience=settings.agent_client_id,
        issuer=settings.oidc_issuer,
        options={"verify_aud": False},  # relax audience for cross-cluster tokens
    )
    return claims


def extract_user_id(claims: dict[str, Any]) -> str:
    """Extract the user ID from token claims (sub field)."""
    return str(claims.get("sub", ""))


def extract_act_id(claims: dict[str, Any]) -> str | None:
    """Extract the acting agent ID from RFC 8693 'act' claim."""
    act = claims.get("act")
    if isinstance(act, dict):
        return act.get("sub")
    return None
