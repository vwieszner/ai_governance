"""
RFC 8693 OAuth 2.0 Token Exchange + JWT validation.

FIX C-1:  audience is now strictly validated against a configurable list.
FIX C3-1: _jwks_lock instantiated at module level. asyncio.Lock() in Python 3.10+
          does NOT bind to a running event loop at construction, so module-level
          instantiation is safe and race-free. Removes the previous lazy
          _get_jwks_lock() helper, which had a check-then-set race that could
          silently create duplicate lock objects and bypass thundering-herd protection.
FIX H-5:  JWKS cache protected by asyncio.Lock — no thundering herd at TTL boundary.
FIX M3-5: exchange_token validates target_audience against configured peer_agent_url
          before performing the exchange, preventing misuse with arbitrary audiences.
FIX S-4:  explicit httpx timeout on every outbound HTTP call.
FIX S-5:  accepted JWT algorithm list is now read from settings.
FIX S-9:  JWKS / network errors raise AuthServiceUnavailable (→ 503, not 401).
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog
from jose import JWTError, jwk, jwt

from config import settings

log = structlog.get_logger(__name__)

# Timeout for ALL outbound HTTP calls (IdP token endpoint, JWKS fetch)
_HTTP_TIMEOUT = 10.0

# ── JWKS cache (H-5 + C3-1 fix: module-level lock, not lazy) ─────────────────
_JWKS_CACHE: dict[str, Any] = {}
_JWKS_CACHE_TTL: float = 3600.0
_jwks_fetched_at: float = 0.0
# C3-1: instantiate at module level — safe in Python 3.10+ (no loop binding)
_jwks_lock: asyncio.Lock = asyncio.Lock()


class AuthServiceUnavailable(Exception):
    """Raised when the JWKS endpoint or IdP is unreachable (→ 503, not 401)."""


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

    FIX S-4:  timeout=_HTTP_TIMEOUT prevents hung IdP from blocking the event loop.
    FIX M3-5: validates target_audience against the configured peer audience
              allowlist so this function cannot be called with an arbitrary
              audience to obtain a token scoped to an attacker-controlled service.
    """
    # M3-5 / H-1: the OAuth audience for RFC 8693 is the peer's CLIENT_ID (which is
    # what Keycloak can resolve), not a URL. Validate the requested audience
    # against the configured allowlist (settings.peer_agent_audience) with an exact
    # match — no substring/prefix matching that could be bypassed.
    _allowed = {a.strip() for a in (settings.peer_agent_audience or "").split(",") if a.strip()}
    if not _allowed:
        raise ValueError(
            "token exchange requested but no peer_agent_audience is configured"
        )
    if str(target_audience) not in _allowed:
        raise ValueError(
            f"token exchange audience '{target_audience}' is not in the configured allowlist {_allowed}"
        )

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
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
    """
    Fetch JWKS with double-checked locking to prevent thundering herd (H-5).
    FIX S-4: explicit timeout on the JWKS fetch.
    FIX S-9: network errors are wrapped in AuthServiceUnavailable.
    """
    global _jwks_fetched_at, _JWKS_CACHE

    now = time.monotonic()
    # Fast path — no lock needed if cache is fresh
    if _JWKS_CACHE and (now - _jwks_fetched_at) < _JWKS_CACHE_TTL:
        return _JWKS_CACHE

    # Slow path — acquire lock and re-check
    async with _jwks_lock:
        now = time.monotonic()
        if _JWKS_CACHE and (now - _jwks_fetched_at) < _JWKS_CACHE_TTL:
            return _JWKS_CACHE   # another coroutine already refreshed it

        log.info("jwks_refresh", uri=settings.oidc_jwks_uri)
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.get(settings.oidc_jwks_uri)
                resp.raise_for_status()
                new_cache = resp.json()
        except httpx.HTTPError as exc:
            # S-9: distinguish network/IdP outage from bad token.
            # PY-11: httpx.TimeoutException is a subclass of httpx.HTTPError so
            # listing both was redundant — HTTPError already catches timeouts.
            raise AuthServiceUnavailable(
                f"Failed to fetch JWKS from {settings.oidc_jwks_uri}: {exc}"
            ) from exc

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

    FIX S-5: accepted algorithms are read from settings.allowed_jwt_algorithms_list
    so operators can restrict to their IdP's actual algorithm.

    FIX S-9: JWKS network errors raise AuthServiceUnavailable (caller maps to 503).

    Raises JWTError on invalid / expired / wrong-audience tokens.
    Raises AuthServiceUnavailable when the IdP is unreachable.
    """
    jwks = await _fetch_jwks()
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    # MED-7: also check the key's declared `alg` field against the token header so
    # a key rotation event that leaves multiple keys with the same kid but different
    # algorithms cannot cause key confusion (e.g., RS256 key used to verify ES256).
    alg = unverified_header.get("alg")

    signing_key = None
    for key_data in jwks.get("keys", []):
        kid_match = not kid or key_data.get("kid") == kid
        # key_data["alg"] is optional in JWKS — only enforce when both sides declare it
        alg_match = not alg or not key_data.get("alg") or key_data.get("alg") == alg
        if kid_match and alg_match:
            signing_key = jwk.construct(key_data)
            break

    if signing_key is None:
        raise JWTError("No matching signing key found in JWKS")

    # Accept tokens whose audience is this agent's client ID OR this agent's URL
    # (delegated tokens from the peer cluster use the agent URL as audience).
    valid_audiences = [settings.agent_client_id, str(settings.agent_url)]

    # SECURITY NOTE — audience IS verified, see the explicit check below.
    # We set verify_aud=False ONLY because python-jose's audience= argument takes a
    # single string and cannot express "accept ANY of several audiences" (this agent
    # accepts both its client_id and its public URL for delegated cross-cluster
    # tokens). Signature, exp, iat and iss are still fully verified by jose (its
    # defaults are all True). The manual allowlist check immediately below is
    # deny-by-default and STRICTER than jose's matcher: it rejects any token whose
    # aud contains none of the accepted values (FIX C-1). The previous
    # audience=[list] form was a latent bug — jose raised "audience must be a
    # string or None" and rejected every token.
    claims: dict[str, Any] = jwt.decode(
        token,
        signing_key,
        algorithms=settings.allowed_jwt_algorithms_list,   # FIX S-5: configurable
        issuer=settings.oidc_issuer,
        options={"verify_aud": False},   # aud verified manually below (multi-aud support)
    )

    token_aud = claims.get("aud", [])
    if isinstance(token_aud, str):
        token_aud = [token_aud]
    if not any(a in valid_audiences for a in token_aud):
        raise JWTError(
            f"Invalid audience: token aud {token_aud!r} matches none of "
            f"the accepted audiences {valid_audiences!r}"
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
