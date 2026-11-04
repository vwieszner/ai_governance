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

JWT library:
    PyJWT (``jwt``) — python-jose was removed (PYSEC-2026-4298: HS256 forgery with
    DER-encoded public keys, no fixed release; it also pulled the unmaintained
    ``ecdsa``). ``JWTError`` below is an alias of ``jwt.PyJWTError`` so every
    signature / claim / key failure is ONE exception type for callers (→ 401).
    HS256-with-public-key confusion is refused three independent ways: the
    algorithm allow-list (default RS256,ES256), the MED-7 key ``alg`` check, and
    PyJWK refusing to build an HMAC key from a non-``oct`` JWK.
"""
from __future__ import annotations

import asyncio
import hashlib
import math
import time
from typing import Any

import httpx
import jwt
import structlog

from config import settings

log = structlog.get_logger(__name__)

# One exception type for every token failure (malformed header, unknown kid, key/alg
# mismatch, bad signature, expired, wrong iss/aud). Callers map it to HTTP 401.
JWTError = jwt.PyJWTError

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
        The verification key (a ``cryptography`` public-key object) built from the JWK.

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
            # algorithm=header_alg forces the key family: PyJWK refuses to build e.g. an
            # HMAC key from an RSA/EC JWK (kty must be 'oct'), so a public key can never
            # be repurposed as an HS256 secret.
            return jwt.PyJWK(key_data, algorithm=header_alg).key
        except (jwt.PyJWTError, ValueError, TypeError) as exc:
            raise JWTError(f"Failed to construct JWK for kid={kid!r}: {exc}") from exc

    raise JWTError(f"No JWKS key found for kid={kid!r}")


def _check_iat_is_integer(claims: dict) -> None:
    """``iat``, when present, must be an integer (RFC 7519 NumericDate)."""
    if "iat" not in claims:
        return
    try:
        int(claims["iat"])
    except (ValueError, TypeError, OverflowError):
        raise jwt.InvalidIssuedAtError("Issued At claim (iat) must be an integer.") from None


# ── Public API ─────────────────────────────────────────────────────────────────


async def validate_token(token: str) -> dict:
    """Validate a Keycloak-issued JWT and return the verified claims dict.

    Steps:
        1. Decode the JWT header (unverified) to extract kid and alg.
        2. Fetch JWKS (from cache or endpoint).
        3. Locate the signing key — MED-7: verify key alg matches header alg.
        4. Verify signature, issuer, audience, expiry and iat via PyJWT.
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

    # Step 4: full verification. iat semantics are kept exactly as before (python-jose):
    # if present it must be an integer, but it is NOT compared against the local clock —
    # PyJWT's own iat check would reject a token issued a second "in the future" by an IdP
    # whose clock runs slightly ahead (no leeway is used, so exp stays strict).
    try:
        claims: dict = jwt.decode(
            token,
            key,
            algorithms=[header_alg],
            audience=settings.agent_client_id,
            issuer=settings.oidc_issuer,
            options={"verify_signature": True, "verify_exp": True, "verify_iat": False,
                     "verify_aud": True, "verify_iss": True},
        )
        _check_iat_is_integer(claims)
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


# ── Cross-division user assertion (M2, FR-3.6) ─────────────────────────────────


def minimal_assertion_claims(claims: dict) -> dict:
    """The minimal verified-identity subset the ORIGINATING division forwards to a
    peer as the cross-division user assertion.

    M2 (FR-3.6), security-hardened: we deliberately do NOT forward the user's raw
    home-division access token. A raw token is a replayable bearer credential — a
    compromised receiving division could replay it against the user's HOME APIs for
    its whole TTL. Instead we forward only the identity claims the home division has
    ALREADY validated; they travel inside the DID-signed, replay-protected envelope
    (so they are authenticated as coming from the home agent) and the receiver binds
    the asserted issuer to that signing peer (see assertion_principal). Nothing
    replayable leaves the home division.

    Includes only: ``sub`` (audit), ``email`` + ``email_verified`` (the principal
    subject), ``iss`` (issuer binding).
    """
    return {
        "sub": claims.get("sub"),
        "email": claims.get("email"),
        "email_verified": claims.get("email_verified"),
        "iss": claims.get("iss"),
    }


def assertion_principal(assertion: dict, expected_issuer: str) -> str:
    """Validate a DID-signed cross-division user assertion and return its OpenFGA
    principal. The assertion is a claims dict (see minimal_assertion_claims) carried
    in the DID-signed, replay-protected peer envelope — authenticity + freshness come
    from the envelope's Ed25519 signature + ts/nonce, NOT from a bearer token.

    SECURITY — signer-specific issuer binding: ``assertion['iss']`` MUST equal
    ``expected_issuer`` (the issuer bound to the SPECIFIC signing peer DID by the
    caller — settings.peer_agent_issuer / a DID→issuer map). Binding to the signer
    (not to the trusted-issuer SET) is what prevents a compromised-but-trusted peer
    from asserting ANOTHER division's user (which set-membership would allow in a 3+
    division mesh). principal() then namespaces by the (now signer-bound) issuer.

    NOTE: this is the ISSUER-BINDING core. The full receive path uses
    :func:`validate_cross_division_assertion`, which additionally enforces the
    recipient binding (``aud`` == this division's DID) and short expiry (``exp``)
    added by the sender (mesh.peer_client._bind_user_assertion). Both are layered;
    neither weakens the other.

    TRUST MODEL (be precise — this is delegated/VOUCHED identity, not receiver-verified):
    the email/email_verified in the assertion are NOT re-verified against the home
    Keycloak here (Keycloak cannot mint a token whose audience is the receiver, so there
    is no receiver-verifiable home token — that constraint is what forced this design).
    They are VOUCHED by the home division's DID-authenticated agent. Consequence: a
    compromised-but-trusted peer can assert ANY identity WITHIN ITS OWN namespace
    (issuer), e.g. a fabricated email — but the issuer binding above confines that blast
    radius to the peer's own users; it can never reach across divisions. This is the
    standard vouched cross-trust-domain delegation model and is strictly safer than
    forwarding the user's raw (replayable) token. Authenticity of the assertion itself
    is cryptographic: the envelope carrying it is Ed25519 DID-signed + ts/nonce fresh.

    Raises ValueError on any failure (callers fail closed).
    """
    if not isinstance(assertion, dict):
        raise ValueError("user assertion must be a claims object, not a token/string")
    if not expected_issuer:
        raise ValueError("no issuer is bound to the signing peer — cannot accept assertion")
    iss = str(assertion.get("iss", ""))
    if iss != expected_issuer:
        raise ValueError(
            f"assertion issuer {iss!r} is not the issuer bound to the signing peer "
            f"({expected_issuer!r}) — refusing (cross-issuer impersonation guard)"
        )
    return principal(assertion)


# Maximum forward clock skew (seconds) tolerated on the assertion's `exp`. The
# assertion already rides inside the envelope's ±5-min ts/nonce freshness window,
# so this only absorbs small clock drift between divisions; it does not extend the
# sender's short TTL into a meaningful replay window.
_ASSERTION_EXP_SKEW_SECONDS = 60


def validate_cross_division_assertion(
    assertion: dict,
    expected_issuer: str,
    expected_audience: str,
    *,
    now: float | None = None,
) -> str:
    """Validate a RECIPIENT-BOUND, time-limited cross-division user assertion and
    return its OpenFGA principal (FR-3.6). This is the full receive-side check used by
    /a2a/query; it composes three independent bindings, ALL fail-closed:

      1. RECIPIENT BINDING — ``assertion['aud']`` MUST equal ``expected_audience``
         (THIS division's own DID, read from mesh.agent_identity). An assertion the
         home division minted for division B carries ``aud`` = B's DID, so B cannot
         forward it to C (and C, checking its own DID, rejects it). This is what makes
         the assertion non-replayable ACROSS recipients, on top of the envelope's
         per-message ts/nonce replay guard.
      2. EXPIRY — ``assertion['exp']`` (unix seconds, set by the sender) MUST NOT be in
         the past (with a small ``_ASSERTION_EXP_SKEW_SECONDS`` clock-skew allowance).
         A missing/0/non-numeric ``exp`` is rejected (no unbounded-lifetime assertions).
      3. ISSUER BINDING — delegated via :func:`assertion_principal`: ``iss`` MUST equal
         the issuer bound to the SIGNING peer's DID (see that function), and the email
         must be verified. This is the cross-issuer impersonation guard.

    The caller MUST have already cryptographically verified the carrying envelope
    (Ed25519 signature + ts/nonce freshness) and resolved both ``expected_issuer`` and
    the signer's DID for ``expected_audience``-comparison BEFORE calling this. This
    function does not re-do envelope verification; it validates the assertion's own
    recipient/expiry/issuer bindings.

    Raises ValueError on ANY failure (callers fail closed → 401/403).
    """
    if not isinstance(assertion, dict):
        raise ValueError("user assertion must be a claims object, not a token/string")
    if not expected_audience:
        raise ValueError("no audience (self DID) provided — cannot validate recipient binding")

    # 1. Recipient binding: aud must be THIS division's DID.
    aud = str(assertion.get("aud", ""))
    if aud != expected_audience:
        raise ValueError(
            f"assertion audience {aud!r} is not this division ({expected_audience!r}) — "
            "refusing (recipient-binding / cross-recipient replay guard)"
        )

    # 2. Expiry: exp must be present, numeric, FINITE, and not in the past (small skew
    #    allowed). math.isfinite rejects inf/-inf/NaN: without it, float('inf') / float('nan')
    #    (and a JSON `1e400` that json.loads coerces to inf) sail past the `<= 0` guard
    #    (inf<=0 and nan<=0 are both False) and then the `current > exp` comparison is always
    #    False (current > inf, current > nan) — i.e. a never-expiring assertion, defeating the
    #    short-exp bound this layer exists to enforce. Finite-only keeps the contract: a 300.0
    #    exp is still accepted; inf/nan/0/negative/bool are all refused.
    raw_exp = assertion.get("exp")
    if (
        not isinstance(raw_exp, (int, float))
        or isinstance(raw_exp, bool)
        or not math.isfinite(raw_exp)
        or raw_exp <= 0
    ):
        raise ValueError("assertion is missing a valid 'exp' — refusing (no unbounded assertions)")
    current = time.time() if now is None else now
    if current > float(raw_exp) + _ASSERTION_EXP_SKEW_SECONDS:
        raise ValueError(
            f"assertion expired (exp={int(raw_exp)}, now={int(current)}) — refusing (expiry guard)"
        )

    # 3. Issuer binding + verified-email + namespaced principal.
    return assertion_principal(assertion, expected_issuer)


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


def issuer_namespace(iss: str) -> str:
    """Stable, OpenFGA-safe namespace derived from the *verified* issuer.

    SECURITY (federated trust): the authorization principal is namespaced by the
    issuer that signed the token so trusting one issuer can NEVER let it vouch for
    another issuer's users. Without this, a single compromised/malicious trusted
    issuer could mint ``email=ceo@other-division`` and impersonate anyone in the
    federation — ``email_verified`` does NOT close this (the receiver cannot check
    that the *home* issuer truly verified the email; it only attests it did).

    Derived from a hash so it needs no cross-division label-agreement config and
    contains only OpenFGA-safe characters. Issuer is normalised (trailing slash
    stripped) so the seed-time and runtime forms match byte-for-byte.
    """
    return hashlib.sha256(iss.rstrip("/").encode("utf-8")).hexdigest()[:16]


def principal(claims: dict) -> str:
    """Canonical federated authorization principal for OpenFGA.

    Format: ``<subject>|<issuer-namespace>`` — e.g.
    ``alice@example.com|56b707f1d1087268``. The lower-cased subject is the stable,
    human-readable, cross-division identifier; the issuer-namespace (see
    :func:`issuer_namespace`) scopes it so an issuer can only vouch for ITS OWN users.

    The SUBJECT claim is configurable (``settings.principal_claim``, default ``email``)
    so this works against any OIDC IdP — Keycloak ``email``, Entra ``preferred_username``/
    ``upn``, etc. When the subject claim is ``email`` and ``settings.require_verified_principal``
    is true (the default, hardened posture), ``email_verified == true`` is also required.

    The STRENGTH of the claims depends on how the caller obtained them:
      - Local ``/query``: claims come from :func:`validate_token` — cryptographically
        verified against the home IdP JWKS.
      - Cross-division ``/a2a/query``: claims come from a peer's DID-signed assertion via
        :func:`assertion_principal` — VOUCHED by the DID-authenticated home agent (see that
        function's trust-model note); ``iss`` is bound to the signing peer.
    Callers MUST pass claims from one of those paths, never the raw envelope's
    ``source_division``/``user_id``.

    Raises:
        ValueError: if ``iss`` or the configured subject claim is absent (or, for an
        email subject under the verified policy, if the email is unverified).
    """
    iss = claims.get("iss")
    if not iss:
        raise ValueError("token missing 'iss' claim — cannot namespace principal")
    claim_name = settings.principal_claim
    subject = claims.get(claim_name)
    if not subject:
        raise ValueError(
            f"token missing '{claim_name}' claim — the authorization principal requires it. "
            f"Configure the IdP to emit '{claim_name}', or set PRINCIPAL_CLAIM to a claim it does emit."
        )
    # email_verified is an email-specific assurance; enforce it only for an email subject
    # under the configured policy (keeps the hardened Keycloak default, but lets an IdP
    # that uses upn/preferred_username — and emits no email_verified — work).
    if settings.require_verified_principal and claim_name == "email":
        if claims.get("email_verified") is not True:
            raise ValueError(
                "token 'email' is not verified (email_verified != true) — refusing to "
                "build an authorization principal from an unverified email."
            )
    return f"{str(subject).strip().lower()}|{issuer_namespace(str(iss))}"


def extract_groups(claims: dict) -> list[str]:
    """The user's group memberships from the configured ``settings.groups_claim``.

    Maps an IdP's groups/roles (AD security groups via Keycloak/Entra/Okta) to OpenFGA
    ``group`` ids. Used by the data path as LIVE contextual ``group#member`` tuples so a
    user inherits a group's baseline document access with no per-user tuple — and loses it
    the instant the IdP drops them from the group (the next token simply omits it).

    Accepts a list claim or a single string. Normalises: trims whitespace, drops empties,
    and strips a leading ``/`` (Keycloak emits group *paths* like ``/finance``). Returns
    [] when the claim is absent/empty, so group support is opt-in and never fails closed
    on a token that simply has no groups.
    """
    raw = claims.get(settings.groups_claim)
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return []
    out: list[str] = []
    for g in raw:
        if isinstance(g, str) and g.strip():
            out.append(g.strip().lstrip("/"))
    # Defence: if a division declares a recognised-group allowlist, drop any group not on
    # it BEFORE it can grant access — so a misconfigured IdP mapper (or a user-influenced
    # group claim) can't escalate via an unexpected group. Empty allowlist = accept all.
    allow = settings.recognized_groups_set
    if allow:
        dropped = [g for g in out if g not in allow]
        if dropped:
            log.warning("groups_claim_filtered", dropped=dropped, agt_audit=True)
        out = [g for g in out if g in allow]
    return out


def extract_client_id(claims: dict) -> str | None:
    """Extract the OAuth2 client ID from JWT claims.

    Keycloak embeds this in 'azp' (authorised party) or 'client_id'.
    Returns None if neither claim is present.
    """
    return claims.get("azp") or claims.get("client_id") or None
