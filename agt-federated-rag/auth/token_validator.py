"""JWT validation for human user tokens issued by Keycloak.

This module validates *user* JWTs only.  Agent-to-agent identity is handled
by the AGT mesh layer (DIDs + IATP); this module is not involved in that path.

Design decisions:

MED-7 (key confusion prevention):
    When selecting a signing key from the JWKS by kid, we additionally verify
    that the key's 'alg' field matches the algorithm declared in the JWT header.
    An attacker who controls a key with a matching kid but different algorithm
    cannot use it to forge tokens.

LOW-5 (missing sub claim):
    RFC 7519 §4.1.2 makes 'sub' optional, but our system uses it as the primary
    user identifier.  We raise ValueError (not a silent fallback to an empty
    string) if 'sub' is absent, surfacing mis-configured tokens early.

H-1 note:
    Token exchange (RFC 8693) was removed from this project — AGT DIDs replace
    the agent-to-agent identity use case.  This module therefore handles only
    inbound user token validation.

JWKS cache:
    We cache the JWKS response for 3600 seconds (one hour) to avoid a network
    call on every request.  The cache is invalidated eagerly if a kid lookup
    fails, allowing key rotation without a restart.  An asyncio.Lock guards
    double-checked locking so concurrent requests don't stampede the JWKS
    endpoint on cache miss.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog
from jose import JWTError, jwk, jwt  # type: ignore[import]
from jose.exceptions import JWKError  # type: ignore[import]

from config import settings

log = structlog.get_logger(__name__)

# ── JWKS cache ─────────────────────────────────────────────────────────────────
_JWKS_CACHE: dict[str, Any] | None = None
_JWKS_CACHED_AT: float = 0.0
_JWKS_TTL: float = 3600.0
_JWKS_LOCK: asyncio.Lock = asyncio.Lock()

# ── Custom exceptions ──────────────────────────────────────────────────────────


class AuthServiceUnavailable(Exception):
    """Raised when the JWKS endpoint cannot be reached or returns a non-200 status."""


# ── JWKS fetching & caching ────────────────────────────────────────────────────


async def _fetch_jwks() -> dict[str, Any]:
    """Fetch the JWKS from the configured endpoint.

    Raises:
        AuthServiceUnavailable: If the HTTP request fails or returns non-200.
    """
    log.info("jwks.fetch", uri=settings.oidc_jwks_uri)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(settings.oidc_jwks_uri)
    except httpx.RequestError as exc:
        raise AuthServiceUnavailable(
            f"JWKS endpoint unreachable: {settings.oidc_jwks_uri}"
        ) from exc

    if resp.status_code != 200:
        raise AuthServiceUnavailable(
            f"JWKS endpoint returned HTTP {resp.status_code}: {settings.oidc_jwks_uri}"
        )

    try:
        data: dict[str, Any] = resp.json()
    except Exception as exc:
        raise AuthServiceUnavailable("JWKS response is not valid JSON") from exc

    log.debug("jwks.fetched", key_count=len(data.get("keys", [])))
    return data


async def _get_jwks(force_refresh: bool = False) -> dict[str, Any]:
    """Return cached JWKS, fetching from the endpoint if stale or forced.

    Uses double-checked asyncio.Lock to prevent cache-stampede on concurrent
    requests.
    """
    global _JWKS_CACHE, _JWKS_CACHED_AT

    now = time.monotonic()
    if not force_refresh and _JWKS_CACHE is not None and (now - _JWKS_CACHED_AT) < _JWKS_TTL:
        return _JWKS_CACHE

    async with _JWKS_LOCK:
        now = time.monotonic()
        if not force_refresh and _JWKS_CACHE is not None and (now - _JWKS_CACHED_AT) < _JWKS_TTL:
            return _JWKS_CACHE
        data = await _fetch_jwks()
        _JWKS_CACHE = data
        _JWKS_CACHED_AT = now
    return _JWKS_CACHE  # type: ignore[return-value]


# ── Key lookup ─────────────────────────────────────────────────────────────────


def _find_key(
    jwks: dict[str, Any],
    kid: str,
    header_alg: str,
) -> Any:
    """Find the JWK matching *kid* and verify its declared algorithm.

    MED-7: we check the key's 'alg' field (if present) against the JWT header
    algorithm to prevent algorithm-substitution attacks.  Keys that have an
    explicit 'alg' field must match *header_alg*; keys without an 'alg' field
    are accepted for any algorithm in the allow-list.

    Returns:
        A jose JWK key object.

    Raises:
        JWTError: If no matching key is found or the algorithm is rejected.
    """
    allowed_algs = settings.allowed_jwt_algorithms_list
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") != kid:
            continue
        # MED-7 fix: algorithm field check.
        key_alg = key_data.get("alg")
        if key_alg is not None and key_alg != header_alg:
            raise JWTError(
                f"Key kid={kid!r} has alg={key_alg!r} but JWT header declares alg={header_alg!r}; "
                "refusing to verify (key confusion protection)"
            )
        if header_alg not in allowed_algs:
            raise JWTError(
                f"JWT algorithm {header_alg!r} is not in the allowed list: {allowed_algs}"
            )
        try:
            return jwk.construct(key_data, algorithm=header_alg)
        except JWKError as exc:
            raise JWTError(f"Failed to construct JWK for kid={kid!r}: {exc}") from exc

    raise JWTError(f"No JWKS key found for kid={kid!r}")


# ── Public API ─────────────────────────────────────────────────────────────────


async def validate_token(token: str) -> dict:
    """Validate a Keycloak-issued JWT and return the verified claims dict.

    Steps:
        1. Decode the JWT header (unverified) to extract kid and alg.
        2. Fetch JWKS (from cache or endpoint).
        3. Locate the signing key — MED-7: verify key alg matches header alg.
        4. Verify signature, issuer, audience, and expiry via python-jose.
        5. On kid-not-found, eagerly refresh the JWKS cache once and retry
           (supports key rotation without restarting the service).

    Args:
        token: Raw JWT string (Bearer token from the HTTP Authorization header).

    Returns:
        Verified claims dict.

    Raises:
        JWTError:               Signature invalid, token expired, or claims fail.
        AuthServiceUnavailable: JWKS endpoint unreachable.
        ValueError:             JWT header is malformed.
    """
    # Step 1: unverified header decode to extract kid + alg.
    try:
        header: dict = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise JWTError(f"Cannot decode JWT header: {exc}") from exc

    kid: str | None = header.get("kid")
    header_alg: str = header.get("alg", "")

    if not kid:
        raise JWTError("JWT header is missing 'kid' field")
    if not header_alg:
        raise JWTError("JWT header is missing 'alg' field")

    allowed_algs = settings.allowed_jwt_algorithms_list
    if header_alg not in allowed_algs:
        raise JWTError(
            f"JWT header algorithm {header_alg!r} is not permitted; "
            f"allowed: {allowed_algs}"
        )

    # Step 2 + 3: fetch JWKS and find key.
    jwks = await _get_jwks()
    try:
        key = _find_key(jwks, kid, header_alg)
    except JWTError:
        # Key not found — may be a new key after rotation; refresh cache once.
        log.info("jwks.kid_not_found_refreshing", kid=kid)
        jwks = await _get_jwks(force_refresh=True)
        key = _find_key(jwks, kid, header_alg)  # let JWTError propagate on second miss

    # Step 4: full verification.
    try:
        claims: dict = jwt.decode(
            token,
            key,
            algorithms=[header_alg],
            audience=settings.agent_client_id,
            issuer=settings.oidc_issuer,
            options={"verify_exp": True, "verify_iat": True},
        )
    except JWTError:
        log.warning("jwt.validation_failed", kid=kid, alg=header_alg)
        raise

    log.debug(
        "jwt.validated",
        sub=claims.get("sub"),
        iss=claims.get("iss"),
        aud=claims.get("aud"),
    )
    return claims


# ── Claim extraction helpers ───────────────────────────────────────────────────


def extract_user_id(claims: dict) -> str:
    """Extract the user identifier from verified JWT claims.

    Uses the 'sub' (subject) claim as the canonical user ID.

    Raises:
        ValueError: If the 'sub' claim is absent (LOW-5 fix).
    """
    sub = claims.get("sub")
    if not sub:
        raise ValueError(
            "'sub' claim is absent from JWT — cannot determine user identity. "
            "Ensure the Keycloak client is configured to include the subject claim."
        )
    return str(sub)


def extract_client_id(claims: dict) -> str | None:
    """Extract the OAuth2 client ID from JWT claims.

    Keycloak embeds this in 'azp' (authorised party) or 'client_id'.
    Returns None if neither claim is present.
    """
    return claims.get("azp") or claims.get("client_id") or None
