"""
RFC 8693 OAuth 2.0 Token Exchange + JWT validation.

FIX C-1: audience is now strictly validated against a configurable list.
FIX H-5: JWKS cache protected by asyncio.Lock — no thundering herd at TTL boundary.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx
import structlog
from jose import JWTError, jwk, jwt

from config import settings

log = structlog.get_logger(__name__)

# ── JWKS cache (H-5 fix: protected by lock) ───────────────────────────────────
_JWKS_CACHE: dict[str, Any] = {}
_JWKS_CACHE_TTL: float = 3600.0
_jwks_fetched_at: float = 0.0
_jwks_lock: asyncio.Lock | None = None   # created lazily (can't instantiate at import time)


def _get_jwks_lock() -> asyncio.Lock:
    global _jwks_lock
    if _jwks_lock is None:
        _jwks_lock = asyncio.Lock()
    return _jwks_lock


@dataclass
class DelegatedToken:
    access_token: str
    token_type: str
    expires_in: int
    issued_token_type: str = "urn:ietf:params:oauth:token-type:access_token"


async def exchange_token(user_token: str, target_audience: str) -> DelegatedToken:
    """
    Perform RFC 8693 token exchange.

    The resulting token has:
      sub = original user ID
      act = this agent's client ID
      aud = target_audience (the downstream service)
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
    """Fetch JWKS with double-checked locking to prevent thundering herd (H-5)."""
    global _jwks_fetched_at, _JWKS_CACHE

    now = time.monotonic()
    # Fast path — no lock needed if cache is fresh
    if _JWKS_CACHE and (now - _jwks_fetched_at) < _JWKS_CACHE_TTL:
        return _JWKS_CACHE

    # Slow path — acquire lock and re-check
    async with _get_jwks_lock():
        now = time.monotonic()
        if _JWKS_CACHE and (now - _jwks_fetched_at) < _JWKS_CACHE_TTL:
            return _JWKS_CACHE   # another coroutine already refreshed it

        log.info("jwks_refresh", uri=settings.oidc_jwks_uri)
        async with httpx.AsyncClient() as client:
            resp = await client.get(settings.oidc_jwks_uri, timeout=10.0)
            resp.raise_for_status()
            new_cache = resp.json()

        # Atomic update — assign both in sequence while holding the lock
        _JWKS_CACHE = new_cache
        _jwks_fetched_at = time.monotonic()

    return _JWKS_CACHE


async def validate_token(token: str) -> dict[str, Any]:
    """
    Validate a JWT and return its claims.

    FIX C-1: audience is strictly validated against the agent's own client ID
    AND its own public URL (to accept delegated cross-cluster tokens).
    verify_aud is always True — no bypass.

    Raises JWTError on invalid / expired / wrong-audience tokens.
    """
    jwks = await _fetch_jwks()
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    signing_key = None
    for key_data in jwks.get("keys", []):
        if not kid or key_data.get("kid") == kid:
            signing_key = jwk.construct(key_data)
            break

    if signing_key is None:
        raise JWTError("No matching signing key found in JWKS")

    # Accept tokens whose audience is this agent's client ID OR this agent's URL
    # (delegated tokens from the peer cluster use the agent URL as audience)
    valid_audiences = [settings.agent_client_id, str(settings.agent_url)]

    claims: dict[str, Any] = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256", "ES256"],
        audience=valid_audiences,
        issuer=settings.oidc_issuer,
        options={"verify_aud": True},   # FIX C-1: ALWAYS validate audience
    )
    return claims


def extract_user_id(claims: dict[str, Any]) -> str:
    return str(claims.get("sub", ""))


def extract_act_id(claims: dict[str, Any]) -> str | None:
    act = claims.get("act")
    if isinstance(act, dict):
        return act.get("sub")
    return None


def extract_client_id(claims: dict[str, Any]) -> str | None:
    """Extract the OAuth client ID (azp or client_id claim)."""
    return claims.get("azp") or claims.get("client_id")
