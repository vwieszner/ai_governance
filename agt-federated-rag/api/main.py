"""FastAPI application for the AGT federated RAG agent.

Exposes:
  GET  /health                         Kubernetes liveness/readiness probe
  GET  /.well-known/agent-card.json    A2A-compatible AgentCard
  GET  /identity                       Returns this agent's DID (for peer config)
  POST /query                          Main query endpoint (SSE streaming)
  POST /tasks/{task_id}/callback       Peer agent callback (DID-authenticated)
  GET  /approve/{request_id}           Approval deep-link (HMAC-protected)

Governance:
  - AGT SREMiddleware tracks request-level SLO compliance.
  - All agent-to-agent calls are authenticated via AgentMesh DIDs.
  - User tokens (Keycloak JWTs) are validated via auth.token_validator.
  - AGT policy denials surface as HTTP 403.

Security notes:
  - Body-size enforcement uses pure ASGI (never buffers SSE responses).
  - Redis singleton is initialised under double-checked locking (HIGH-1 pattern).
  - HMAC validation uses hmac.compare_digest (timing-safe).
  - /approve never echoes request_id or decision in the response (LOW-3).
  - General exceptions never leak internal details to callers.
  - task_id / request_id are validated to alphanumeric + hyphen only.
"""
from __future__ import annotations

# Use the OS trust store for TLS BEFORE any SSL context is created (the bundled
# certifi CA does not include the NVIDIA endpoint's issuer on this host).
import truststore
truststore.inject_into_ssl()

import asyncio
import hashlib
import hmac as hmac_lib
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import redis.asyncio as aioredis
import structlog
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from jose import JWTError
from sse_starlette.sse import EventSourceResponse
from temporalio.client import Client as TemporalClient

import agent.graph as agent_graph
import agent.nodes as agent_nodes
import mesh.agent_identity as agent_identity
from auth.token_validator import (
    AuthServiceUnavailable,
    extract_groups,
    issuer_namespace,
    minimal_assertion_claims,
    principal,
    validate_cross_division_assertion,
    validate_token,
)
from config import settings
from sre import SREMiddleware
from workflow.approval import ApprovalDecisionSignal

log = structlog.get_logger(__name__)

# ── Safe ID regex (compile once) ──────────────────────────────────────────────
_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9\-]+$")
_SAFE_REQUEST_ID_RE = re.compile(r"[^a-zA-Z0-9\-]")


def _validate_safe_id(value: str, field_name: str = "id") -> None:
    """Reject IDs that contain characters outside alphanumeric + hyphen."""
    if not value or not _SAFE_ID_RE.match(value):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field_name}: must contain only alphanumeric characters and hyphens",
        )


# ── Body size middleware (pure ASGI — never buffers SSE responses) ────────────

class _BodyTooLargeError(Exception):
    """Internal sentinel raised when the body limit is exceeded; 413 already sent."""


class _LimitBodySizeMiddleware:
    """
    Raw ASGI middleware that enforces a maximum request body size without
    buffering the response.  Safe for SSE streaming endpoints because only
    the receive channel (request body) is intercepted; the send channel
    (response) is passed through untouched.

    Fast path: rejects immediately on Content-Length header.
    Slow path: accumulates chunked body bytes inside receive_wrapper().
    """

    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Fast path: Content-Length header present
        headers = dict(scope.get("headers", []))
        cl_header = headers.get(b"content-length")
        if cl_header:
            try:
                if int(cl_header) > self.max_bytes:
                    body = b"Request body too large"
                    await send({
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [
                            (b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": body,
                        "more_body": False,
                    })
                    return
            except ValueError:
                pass  # malformed header — let the framework handle it

        # Slow path: count bytes for chunked / streaming uploads
        total_received = 0

        async def receive_wrapper() -> Any:
            nonlocal total_received
            message = await receive()
            if message["type"] == "http.request":
                total_received += len(message.get("body", b""))
                if total_received > self.max_bytes:
                    body = b"Request body too large"
                    await send({
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [
                            (b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": body,
                        "more_body": False,
                    })
                    raise _BodyTooLargeError()
            return message

        try:
            await self.app(scope, receive_wrapper, send)
        except _BodyTooLargeError:
            pass  # 413 already sent above


# ── Request correlation ID middleware ─────────────────────────────────────────

class _CorrelationIdMiddleware:
    """
    Pure ASGI middleware that:
      1. Reads X-Request-ID from the incoming request (if present).
      2. Generates a new UUID4 if the header is absent.
      3. Sanitises the value (alphanumeric + hyphens, max 64 chars).
      4. Binds it to the structlog context for the duration of the request.
      5. Adds X-Request-ID to every response so callers can trace end-to-end.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        raw_id = headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        if raw_id:
            request_id = _SAFE_REQUEST_ID_RE.sub("", raw_id)[:64] or str(uuid.uuid4())
        else:
            request_id = str(uuid.uuid4())

        structlog.contextvars.bind_contextvars(request_id=request_id)

        async def send_with_header(message: Any) -> None:
            if message["type"] == "http.response.start":
                headers_list = list(message.get("headers", []))
                headers_list.append((b"x-request-id", request_id.encode("ascii")))
                message = {**message, "headers": headers_list}
            await send(message)

        try:
            await self.app(scope, receive, send_with_header)
        finally:
            structlog.contextvars.unbind_contextvars("request_id")


# ── Non-finite JSON number guard (trust boundary) ─────────────────────────────


def _has_non_finite_number(obj: Any) -> bool:
    """True if ``obj`` (a json.loads result) contains a non-finite float anywhere.

    Python's default json.loads accepts the non-standard tokens ``Infinity`` /
    ``-Infinity`` / ``NaN`` AND silently coerces an overflowing literal like ``1e400`` to
    ``float('inf')`` — in BOTH cases the value lands as a Python ``float('inf'/'nan')``. An
    ``exp`` of inf/nan would slip past the assertion expiry guard (never-expiring assertion),
    so we walk the parsed structure and reject any non-finite number at the trust boundary.
    """
    import math
    if isinstance(obj, float):
        return not math.isfinite(obj)
    if isinstance(obj, dict):
        return any(_has_non_finite_number(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_has_non_finite_number(v) for v in obj)
    return False


# Cap (in bits) on any integer in an OUTBOUND tool result. CPython refuses to str()/json-
# serialize an int wider than ``sys.get_int_max_str_digits()`` (default 4300 DIGITS ≈ 14284
# bits) and raises ValueError mid-serialization. We bound by bit_length WELL below that so an
# oversized result (e.g. pow(2, 50000)) is caught as a clean tool FAILURE before it can blow
# up json.dumps inside JSONResponse.render() and surface as an uncaught HTTP 500.
_MAX_RESULT_INT_BITS = 8192


def _result_is_json_safe(obj: Any) -> bool:
    """True if a tool result can be SAFELY serialized by JSONResponse (allow_nan=False).

    Defence-in-depth for the /a2a/tool result path (F2): a governed tool's OUTPUT — not just
    the request body — must serialize, or json.dumps raises mid-``render()`` (AFTER the handler
    returns) and the contract's signed status="failed" degrades into an uncaught 500. Rejects:
      * any non-finite float anywhere (inf/nan — JSONResponse uses allow_nan=False), and
      * any int wider than ``_MAX_RESULT_INT_BITS`` (CPython's int→str digit limit).
    Walks dicts/lists recursively. A False result routes through _signed_tool_failure."""
    if isinstance(obj, bool):
        return True
    if isinstance(obj, float):
        import math
        return math.isfinite(obj)
    if isinstance(obj, int):
        return obj.bit_length() <= _MAX_RESULT_INT_BITS
    if isinstance(obj, dict):
        return all(_result_is_json_safe(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return all(_result_is_json_safe(v) for v in obj)
    return True


def _loads_finite(raw: bytes | str) -> Any:
    """json.loads that REFUSES non-finite numbers anywhere in the document.

    Used at the /a2a/query trust boundary (after Starlette's default-settings parse) and as
    a standalone strict parser. parse_constant rejects the named tokens
    ``Infinity``/``-Infinity``/``NaN``; the parsed result is then walked for any ``1e400``-style
    overflow that the default float parser turns into ``inf``.
    """
    import json

    def _no_constant(_tok: str) -> float:
        raise ValueError("non-finite JSON constant rejected")

    data = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
    parsed = json.loads(data, parse_constant=_no_constant)
    if _has_non_finite_number(parsed):
        raise ValueError("non-finite JSON number rejected")
    return parsed


# ── Redis task store (double-checked locking singleton) ───────────────────────

_redis: aioredis.Redis | None = None  # type: ignore[type-arg]
_redis_lock: asyncio.Lock = asyncio.Lock()


async def _get_redis() -> aioredis.Redis:  # type: ignore[type-arg]
    """Return (or initialise) the Redis connection singleton.

    Uses double-checked locking (HIGH-1 pattern) to prevent stampede on
    cold start when many concurrent requests race to initialise the client.
    """
    global _redis
    if _redis is not None:
        return _redis
    async with _redis_lock:
        if _redis is None:
            _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
            log.info("redis_connected", url=settings.redis_url)
    return _redis


async def _store_task(task_id: str, data: dict[str, Any], owner_id: str) -> None:
    """Persist task data in Redis with TTL and owner tag."""
    try:
        r = await _get_redis()
        payload = {**data, "_owner_id": owner_id}
        import json
        await r.setex(
            f"task:{task_id}",
            settings.task_ttl_seconds,
            json.dumps(payload),
        )
    except Exception as exc:
        log.error("redis_store_task_failed", task_id=task_id, error=str(exc))
        raise HTTPException(status_code=503, detail="Task store temporarily unavailable")


async def _load_task(task_id: str) -> dict[str, Any] | None:
    """Load task data from Redis; returns None if not found."""
    try:
        r = await _get_redis()
        import json
        data = await r.get(f"task:{task_id}")
    except Exception as exc:
        log.error("redis_load_task_failed", task_id=task_id, error=str(exc))
        raise HTTPException(status_code=503, detail="Task store temporarily unavailable")
    if data is None:
        return None
    return json.loads(data)


async def _update_task(task_id: str, updates: dict[str, Any]) -> None:
    """Merge updates into an existing task record and reset its TTL."""
    existing = await _load_task(task_id)
    if existing is None:
        log.warning("redis_update_task_not_found", task_id=task_id)
        return
    merged = {**existing, **updates}
    try:
        r = await _get_redis()
        import json
        await r.setex(
            f"task:{task_id}",
            settings.task_ttl_seconds,
            json.dumps(merged),
        )
    except Exception as exc:
        log.error("redis_update_task_failed", task_id=task_id, error=str(exc))
        raise HTTPException(status_code=503, detail="Task store temporarily unavailable")


# ── Runtime kill-switch (FR-4.3) ──────────────────────────────────────────────
# The settings flag (settings.agent_kill_switch_engaged) is a DEPLOY-TIME lever — it is
# read once at startup and needs a restart to change. FR-4.3 wants a RUNTIME lever, so we
# add a per-division Redis flag (agt:killswitch:<division_id>) that any request can consult
# live. The agent is halted if EITHER is true (fail-closed): the settings flag stays an
# always-on override, and the Redis flag can be flipped without a restart via
# POST /admin/kill-switch. A Redis error fails CLOSED (engaged) — a governance halt must
# not be silently lifted by an unavailable store.

def _killswitch_key(division_id: str) -> str:
    return f"agt:killswitch:{division_id}"


async def _runtime_kill_switch_engaged() -> bool:
    """True if the kill-switch is engaged by EITHER the deploy-time settings flag OR the
    runtime Redis flag for this division. Fail-closed on a Redis error."""
    if settings.agent_kill_switch_engaged:
        return True
    try:
        r = await _get_redis()
        val = await r.get(_killswitch_key(settings.division_id))
    except Exception as exc:
        # Fail closed: if we cannot confirm the runtime flag is OFF, treat the path as halted.
        log.error("kill_switch_check_failed_failing_closed", error=str(exc))
        return True
    return str(val) == "1"


async def _set_runtime_kill_switch(engaged: bool) -> None:
    """Engage/disengage the runtime kill-switch for this division (Redis flag).

    Engaging is durable (no TTL) so a halt survives until an admin explicitly lifts it.
    Disengaging deletes the key (the settings override, if set, still halts the path)."""
    r = await _get_redis()
    key = _killswitch_key(settings.division_id)
    if engaged:
        await r.set(key, "1")
    else:
        await r.delete(key)


# ── Rate limiting (Finding #7) ────────────────────────────────────────────────

# In-process fallback counters, used ONLY when Redis is unreachable so the limiter DEGRADES
# (per-replica enforcement) rather than disappearing. {(prefix:subject, window): count}.
_local_rl_counts: dict[tuple[str, int], int] = {}


async def _check_rate_limit(subject: str, *, limit: int | None = None,
                            prefix: str = "ratelimit") -> None:
    """Fixed-window per-subject rate limit. Backed by Redis (INCR + EXPIRE) so it is shared
    across replicas. On a Redis error it DEGRADES to an in-process per-replica counter instead
    of failing OPEN — a saturated/attacked Redis can no longer disable the only cost/DoS gate.

    ``limit`` overrides the per-user default (used for the more generous per-peer federation
    limit); ``prefix`` namespaces the window key (so user and peer budgets don't collide).
    """
    cap = settings.rate_limit_per_minute if limit is None else limit
    window = int(time.time()) // 60
    try:
        r = await _get_redis()
        key = f"{prefix}:{subject}:{window}"
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, 120)
    except Exception as exc:
        # Degrade, don't disappear: enforce on this replica with an in-process window counter.
        log.warning("rate_limit_redis_degraded_to_local", subject=subject, error=str(exc))
        if len(_local_rl_counts) > 10_000:           # cheap bound: drop all stale windows
            _local_rl_counts.clear()
        lkey = (f"{prefix}:{subject}", window)
        count = _local_rl_counts.get(lkey, 0) + 1
        _local_rl_counts[lkey] = count
    if count > cap:
        log.warning("rate_limit_exceeded", subject=subject, count=count, limit=cap,
                    agt_audit=True)  # M8: abuse signal
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please slow down.")


# ── HMAC helpers ──────────────────────────────────────────────────────────────

def _sign_approval(request_id: str, decision: str, exp: int) -> str:
    """Generate an HMAC-SHA256 hex digest for an approval deep-link.

    Finding #2: the expiry timestamp is part of the signed message so a leaked
    deep-link cannot be replayed indefinitely after it expires.
    """
    key = settings.approval_hmac_secret.encode()
    msg = f"{request_id}:{decision}:{exp}".encode()
    return hmac_lib.new(key, msg, hashlib.sha256).hexdigest()


def _verify_approval_token(request_id: str, decision: str, exp: int, token: str) -> bool:
    """Timing-safe HMAC verification for approval deep-links."""
    expected = _sign_approval(request_id, decision, exp)
    return hmac_lib.compare_digest(expected, token)


# ── AgentCard JSON ─────────────────────────────────────────────────────────────

def _build_agent_card(agent_did: str) -> dict[str, Any]:
    return {
        "name": settings.agent_name,
        "description": (
            "AGT-governed federated RAG agent — hybrid vector + graph retrieval "
            "with OpenFGA per-chunk authorization, Temporal approval workflows, "
            "and AgentMesh DID-based zero-trust inter-agent identity."
        ),
        "url": str(settings.agent_url),
        "did": agent_did,
        "capabilities": {
            "streaming": True,
            "pushNotifications": True,
            "stateTransitionHistory": True,
        },
        "skills": [
            {
                "id": "rag-query",
                "name": "RAG Query",
                "description": (
                    "Answer questions using the knowledge base with AGT-governed "
                    "access control and optional cross-cluster federation."
                ),
            }
        ],
    }


# ── Auth dependency ───────────────────────────────────────────────────────────

async def _get_bearer_token(authorization: str | None) -> tuple[str, dict[str, Any]]:
    """Parse Authorization header, validate JWT, return (raw_token, claims)."""
    # A wholly-absent Authorization header must fail closed with 401 (not 422).
    # The param is Optional at the route layer so FastAPI doesn't 422 before this
    # handler runs; the None-guard must precede .partition() (which AttributeErrors
    # on None). RFC 6750: a 401 challenge carries WWW-Authenticate: Bearer.
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = await validate_token(token)
    except JWTError:
        # M8: failed authentication is a security event — chain it (intrusion trail).
        log.warning("token_validation_failed", agt_audit=True)
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except AuthServiceUnavailable as exc:
        log.error("auth_service_unavailable", error=str(exc))
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    except Exception as exc:
        log.error("token_validation_unexpected_error", error=str(exc))
        raise HTTPException(status_code=503, detail="Authentication service unavailable")

    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Token missing required 'sub' claim")

    # FR-2.2: a division admin's disable takes effect on the NEXT request, not at token
    # expiry — JWTs are validated locally, so Keycloak's session revocation alone would leave
    # an already-issued access token usable until it lapses.
    refusal = await _account_refusal(str(sub), claims.get("iat"))
    if refusal == "disabled":
        log.warning("disabled_account_refused", subject=str(sub), agt_audit=True)
        raise HTTPException(status_code=401, detail="Account disabled",
                            headers={"WWW-Authenticate": "Bearer"})
    if refusal == "stale_token":
        # Re-enabled account: a token minted BEFORE the re-enable (possibly the very token
        # whose theft caused the disable) must not come back to life.
        log.warning("pre_reenable_token_refused", subject=str(sub), agt_audit=True)
        raise HTTPException(status_code=401, detail="Token predates account re-enable",
                            headers={"WWW-Authenticate": "Bearer"})

    return token, claims


# ── Disabled-account denylist (FR-2.2 disable cascade) ─────────────────────────
# Keyed by the Keycloak user id (== the token `sub`) and namespaced by division. No TTL:
# the entry outlives every token the user could still hold. Checked on every authenticated
# request; a Redis error FAILS CLOSED (503), like the kill-switch — a store we cannot read
# must not silently re-admit a disabled account.

def _disabled_key(sub: str) -> str:
    return f"agt:disabled:{settings.division_id}:{sub}"


def _not_before_key(sub: str) -> str:
    # Set on re-enable: tokens with iat < this epoch second are refused. No TTL (it must
    # outlive every token minted before the re-enable).
    return f"agt:token-nbf:{settings.division_id}:{sub}"


async def _account_refusal(sub: str, iat: Any) -> str | None:
    """None if the token's subject may proceed; else "disabled" or "stale_token".

    One Redis round trip. Fails CLOSED (503) on a store error. A re-enabled account's
    token is accepted only if its ``iat`` is at/after the re-enable time; a token with no
    usable ``iat`` is refused for such an account (cannot prove it is fresh).
    """
    try:
        r = await _get_redis()
        disabled, nbf = await r.mget(_disabled_key(sub), _not_before_key(sub))
    except Exception as exc:
        log.error("disabled_check_failed_failing_closed", error=str(exc))
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    if disabled:
        return "disabled"
    if nbf:
        try:
            if float(iat) < float(nbf):
                return "stale_token"
        except (TypeError, ValueError):
            return "stale_token"
    return None


async def _account_disabled(sub: str) -> bool:
    return await _account_refusal(sub, None) == "disabled"


async def _mark_account_disabled(sub: str) -> None:
    r = await _get_redis()
    await r.set(_disabled_key(sub), str(int(time.time())))


async def _clear_account_disabled(sub: str) -> None:
    """Lift the denylist AND invalidate every token minted before now (not-before marker),
    so a pre-disable token — possibly the stolen one that prompted the disable — stays dead."""
    r = await _get_redis()
    await r.set(_not_before_key(sub), str(int(time.time())))
    await r.delete(_disabled_key(sub))


# ── Division-admin gate (FR-2.2 role: division admin) ──────────────────────────

# The realm-role convention used across this product (see onboarding + tests/test_identity):
# users carry "member", "data-owner", "division-admin". Admin-only endpoints require the
# "division-admin" role. We read it from BOTH the configured groups/roles claim (via the
# existing extract_groups helper) AND the standard Keycloak realm_access.roles, so the gate
# works whether the IdP maps roles through a groups protocol-mapper or the default realm_access
# block — without adding a config field.
_ADMIN_ROLE = "division-admin"


def _is_division_admin(claims: dict[str, Any]) -> bool:
    """True iff the verified claims carry the division-admin role.

    Reuses extract_groups (the configured groups/roles claim, already used by the data
    path) and additionally inspects Keycloak's realm_access.roles. Fail-closed: any shape
    that doesn't clearly assert the role returns False.
    """
    if _ADMIN_ROLE in set(extract_groups(claims)):
        return True
    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        roles = realm_access.get("roles")
        if isinstance(roles, (list, tuple)) and _ADMIN_ROLE in roles:
            return True
    return False


async def _require_admin(authorization: str | None) -> tuple[str, dict[str, Any]]:
    """Validate the bearer token AND require the division-admin role.

    Returns (caller_principal, claims). 401 on missing/invalid token or an
    unbuildable principal; 403 (audited) when the caller is not a division admin.
    """
    _, claims = await _get_bearer_token(authorization)
    try:
        caller = principal(claims)
    except ValueError as exc:
        log.warning("admin_principal_unbuildable", error=str(exc))
        raise HTTPException(
            status_code=401,
            detail="Token lacks a verified email required for authorization",
        )
    if not _is_division_admin(claims):
        log.warning("admin_endpoint_forbidden_not_admin", caller=caller, agt_audit=True)
        raise HTTPException(status_code=403, detail="Division-admin role required")
    return caller, claims


# ── Application lifespan ──────────────────────────────────────────────────────

@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    # M8: hook the tamper-evident audit chain into structlog (captures agt_audit events)
    import audit_log
    audit_log.configure_audit_logging(settings.division_id, "agent", settings.audit_log_dir)

    # Surface the documented deployment residuals at runtime so operators see them on every
    # boot (THREAT_MODEL: these are known limits, not regressions — make them visible).
    #
    # 1) Audit anchoring: an empty AUDIT_ANCHOR_URL leaves the chain anchored only to a LOCAL
    #    sibling file. The chain is a keyless SHA256, so a host-compromise attacker who can
    #    rewrite BOTH the chain and the local anchor in lock-step gets verified:true. A remote
    #    append-only collector is the only sink such an attacker cannot reach.
    import os
    if not os.environ.get("AUDIT_ANCHOR_URL", "").strip():
        log.warning(
            "audit_anchor_local_only",
            detail="AUDIT_ANCHOR_URL is unset — audit chain is anchored to a LOCAL file only; "
            "tamper-evidence is not tamper-PROOF against a host/filesystem compromise. Set "
            "AUDIT_ANCHOR_URL to a remote append-only collector for off-host anchoring.",
            agt_audit=True,
        )
    # 2) mTLS without a CRL: require_mtls enforces a client cert (CERT_REQUIRED) but with no
    #    TLS_CRL_FILE there is NO revocation gate — a revoked-yet-CA-signed cert is accepted.
    if settings.require_mtls:
        try:
            from transport.mtls import crl_path_for
            crl = crl_path_for(settings)
        except Exception:
            crl = ""
        if not crl:
            log.warning(
                "mtls_without_crl",
                detail="require_mtls is set but no CRL is configured (TLS_CRL_FILE empty) — "
                "client certs are required but NOT checked for revocation; a revoked CA-signed "
                "cert would be accepted. Configure TLS_CRL_FILE (and ssl_crl at the nginx edge) "
                "to enforce NFR-3 revocation.",
                agt_audit=True,
            )
    # 3) OCSP posture (transport/ocsp.py). Off by default. soft = fail-OPEN on a responder
    #    outage (an attacker who can block the responder defeats it — the classic soft-fail
    #    caveat); a mode set without require_mtls is inert (no inbound peer cert to check).
    try:
        from transport.ocsp import ocsp_mode_for
        ocsp_mode = ocsp_mode_for(settings)
    except ValueError as exc:
        ocsp_mode = "invalid"
        log.warning("ocsp_mode_invalid", detail=str(exc), agt_audit=True)
    if ocsp_mode != "off" and not settings.require_mtls:
        log.warning(
            "ocsp_without_mtls",
            detail=f"TLS_OCSP_MODE={ocsp_mode} but require_mtls is false — there is no inbound "
            "client cert to check, so OCSP is NOT enforced on this agent.",
            agt_audit=True,
        )
    elif ocsp_mode == "soft":
        log.warning(
            "ocsp_soft_fail",
            detail="TLS_OCSP_MODE=soft — a REVOKED answer is refused, but an unreachable/invalid "
            "responder or an UNKNOWN status is ALLOWED (logged). Use TLS_OCSP_MODE=hard to fail "
            "closed once the responder is HA.",
            agt_audit=True,
        )

    # Initialise AgentMesh identity — resolves or creates the DID
    await agent_identity.get_mesh()
    did = await agent_identity.get_did()
    log.info("agentmesh_identity_ready", did=did)

    # ── Cross-agent tool delegation: governed registration at boot ────────────
    # Now that the mesh identity exists, make THIS division usable as a tool PROVIDER:
    #   1. register its ENABLED local tool servers (per AGT_LOCAL_TOOLS) into the governed
    #      MCP executor, so /solve and /a2a/tool can run them through every gate from the
    #      first request — not lazily on first call;
    #   2. if a discovery broker is configured (DISCOVERY_URL), advertise our capabilities so a
    #      peer can DISCOVER us even though a pure provider never itself asks for a tool.
    # Each step is best-effort: a failure is logged and never blocks startup (a provider that
    # can't reach the broker still serves locally + via configured peer_tool_map routing).
    from mesh.discovery import advertised_capabilities
    try:
        from tools.local_tools import ensure_local_servers_registered
        ensure_local_servers_registered()
        log.info("local_tool_servers_registered", capabilities=advertised_capabilities())
    except Exception as exc:  # noqa: BLE001 — tool registration must never block startup
        log.warning("local_tool_registration_failed", error=str(exc))

    discovery_url = os.environ.get("DISCOVERY_URL", "").strip()
    if discovery_url:
        try:
            from discovery.client import register_self
            caps = advertised_capabilities()
            await register_self(discovery_url, caps)
            log.info("discovery_self_registered_startup", url=discovery_url, capabilities=caps)
        except Exception as exc:  # noqa: BLE001 — broker registration must never block startup
            log.warning("discovery_self_registration_failed_startup",
                        url=discovery_url, error=str(exc))

    # Connect to Temporal
    tc = await TemporalClient.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
    )
    app.state.temporal_client = tc
    log.info("temporal_client_connected", address=settings.temporal_address)

    yield

    # Graceful shutdown — close Redis connection pool
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None
        log.info("redis_connection_closed")

    log.info("shutting_down")


# ── FastAPI application ────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.agent_name,
    version="1.0.0",
    docs_url=None,   # disabled in production
    redoc_url=None,
    lifespan=_lifespan,
)

# AGT SRE middleware — request-level SLO tracking via agent_sre.
# Added before body-size and correlation-ID middlewares so it wraps the full
# request lifecycle including downstream middleware latency.
if settings.sre_enabled:
    app.add_middleware(
        SREMiddleware,
        slo_latency_p99_ms=settings.sre_slo_latency_p99_ms,
    )

# BFF session router + middleware (production browser auth — no token in the browser).
# The middleware resolves a valid session cookie into an Authorization header (and enforces
# CSRF), so the JWT-validating endpoints below work unchanged for cookie-authenticated SPAs.
from api import bff  # noqa: E402
app.include_router(bff.router)
app.add_middleware(bff.BFFSessionMiddleware)

# Correlation ID middleware — inject X-Request-ID into every request/response.
# Added before body-size so every response (including 413) carries the header.
app.add_middleware(_CorrelationIdMiddleware)

# Body-size middleware — pure ASGI; never buffers SSE response payloads.
app.add_middleware(_LimitBodySizeMiddleware, max_bytes=settings.max_request_body_bytes)

# CORS — outermost layer so preflight OPTIONS is handled before body-size checks.
# allow_origins is read from settings.cors_origins (default: localhost dev server).
# Override via CORS_ORIGINS env var — comma-separated list of allowed origins:
#   CORS_ORIGINS=https://rag.example.com,https://admin.example.com
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,                    # BFF session cookie + CSRF header
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-ID", "X-CSRF-Token"],
)


# ── GET /health ───────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, str]:
    """Kubernetes liveness and readiness probe.

    Returns the cluster ID and this agent's AgentMesh DID so operators can
    verify the identity without a separate /identity call.
    """
    try:
        did = await agent_identity.get_did()
    except Exception:
        did = "unavailable"
    return {
        "status": "ok",
        "cluster": settings.cluster_id,
        "agent_did": did,
    }


@app.get("/metrics")
async def metrics(authorization: str | None = Header(default=None)) -> Response:
    """Prometheus scrape endpoint (Phase-1 item 13). Dependency-free text format; counters
    are the governance audit events (auth decisions/denials, approvals, rotations, peer
    rejections, audit-write errors).

    Recon hardening: the counters reveal auth-failure / denial rates, so when METRICS_TOKEN
    is configured this endpoint requires `Authorization: Bearer <token>` (timing-safe) and
    401s otherwise. Empty METRICS_TOKEN = open (dev default); production sets it and the
    scraper sends the header (or it's reached only via an internal network)."""
    if settings.metrics_token:
        expected = f"Bearer {settings.metrics_token}"
        if not authorization or not hmac_lib.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="metrics: unauthorized")
    import audit_log
    return Response(content=audit_log.render_prometheus(), media_type="text/plain; version=0.0.4")


# ── GET /.well-known/agent-card.json ─────────────────────────────────────────

@app.get("/.well-known/agent-card.json")
async def agent_card() -> JSONResponse:
    """A2A-compatible AgentCard — includes the agent's DID for peer discovery."""
    did = await agent_identity.get_did()
    card = _build_agent_card(did)
    return JSONResponse(content=card)


# ── GET /identity ─────────────────────────────────────────────────────────────

@app.get("/identity")
async def identity() -> dict[str, Any]:
    """Return this agent's AgentMesh DID and public-key JWK.

    Peer operators retrieve both values at setup time and set them as
    PEER_AGENT_DID and PEER_AGENT_PUBLIC_JWK in their deployment configuration,
    so the peer can verify the Ed25519 signature on this agent's callbacks
    (verify_signed_message). Only the PUBLIC key is exposed here.
    """
    did = await agent_identity.get_did()
    public_jwk = await agent_identity.get_public_jwk()
    return {"did": did, "cluster": settings.cluster_id, "public_key_jwk": public_jwk}


# ── POST /query ───────────────────────────────────────────────────────────────

@app.post("/query", response_class=EventSourceResponse)
async def query(
    request: Request,
    authorization: str | None = Header(default=None),
) -> EventSourceResponse:
    """Main query endpoint — streams results as Server-Sent Events.

    Auth:   User JWT validated via auth.token_validator.validate_token.
    Flow:   Delegates to agent.graph.run_query(), which applies AGT governance.
    Output: SSE stream with "result" events and a final "done" event.

    Rate limit: queries exceeding max_query_length are rejected with 400.

    Kill-switch: when the operator has set AGENT_KILL_SWITCH_ENGAGED=true this
    endpoint refuses with HTTP 503 (Service Unavailable = administrative disable)
    BEFORE the SSE stream opens or any auth/retrieval/LLM work runs. 503 (not 403)
    is the correct signal for a load balancer / health monitor: the query path is
    administratively down, not a per-request authz denial. The internal
    govern_action gate in run_query still denies independently (defense in depth /
    AgentMesh audit), but catching the flag here gives callers a clean unsigned
    HTTP status instead of a 200 SSE stream that immediately errors.
    """
    # Kill-switch: refuse the whole query path before doing any work. /health
    # stays 200 (the process is up); only this query surface is disabled.
    # FR-4.3: consults the RUNTIME flag (Redis) in addition to the deploy-time settings
    # flag, so an operator can halt this path via POST /admin/kill-switch with no restart.
    if await _runtime_kill_switch_engaged():
        log.warning("kill_switch_refused_query", agt_audit=True)
        raise HTTPException(
            status_code=503,
            detail="Agent administratively disabled (kill-switch engaged)",
        )

    # Validate JWT and extract user identity
    try:
        token, claims = await _get_bearer_token(authorization)
    except HTTPException:
        raise
    except PermissionError as exc:
        log.warning("agt_policy_denial_query", error=str(exc))
        raise HTTPException(status_code=403, detail="Request denied by governance policy")

    # Authorization principal = verified (issuer, email), NOT the bare sub. This is
    # the same namespaced identity used for cross-division calls (see /a2a/query), so
    # a local user and "the same user arriving from a peer division" are DISTINCT
    # principals unless explicitly granted — least-privilege federated trust.
    try:
        user_id = principal(claims)
    except ValueError as exc:
        log.warning("query_principal_unbuildable", error=str(exc))
        raise HTTPException(
            status_code=401,
            detail="Token lacks a verified email required for authorization",
        )
    task_id = str(uuid.uuid4())
    context_id = str(uuid.uuid4())

    # Finding #7: per-subject rate limit before expensive retrieval + LLM work.
    await _check_rate_limit(user_id)

    # Parse and validate request body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")

    raw_query = body.get("query", "")
    if not isinstance(raw_query, str) or not raw_query.strip():
        raise HTTPException(status_code=400, detail="'query' field must be a non-empty string")
    if len(raw_query) > settings.max_query_length:
        raise HTTPException(
            status_code=400,
            detail=f"Query exceeds maximum length of {settings.max_query_length} characters",
        )

    # Persist initial task record. `query` is truncated for display/logs; `query_full`
    # (bounded by max_query_length) is kept so GET /tasks/{id}/result can RE-RUN the
    # exact query to re-check authorization once a data owner has approved.
    await _store_task(
        task_id,
        {"status": "submitted", "query": raw_query[:200], "query_full": raw_query},
        owner_id=user_id,
    )

    # Forward only the user's VALIDATED identity claims (not the raw bearer token) so
    # a delegated peer call carries a non-replayable, DID-signed assertion. run_query
    # stashes these in a ContextVar — never in state or logs.
    fwd_claims = minimal_assertion_claims(claims)
    # Phase-1 group grants: the user's IdP groups (from the verified token) become live
    # contextual group#member tuples in the per-chunk OpenFGA check, so a document granted
    # to one of their groups is allowed without a per-user tuple.
    user_groups = extract_groups(claims)

    async def event_stream() -> AsyncIterator[dict[str, str]]:
        yield {"event": "status", "data": '{"status": "working"}'}

        run_task: asyncio.Task[dict[str, Any]] = asyncio.create_task(
            agent_graph.run_query(
                query=raw_query,
                user_id=user_id,
                user_claims=fwd_claims,
                task_id=task_id,
                context_id=context_id,
                user_groups=user_groups,
            )
        )

        try:
            result = await run_task
        except asyncio.CancelledError:
            if not run_task.done():
                run_task.cancel()
            log.info("query_cancelled_by_client", task_id=task_id)
            await _update_task(task_id, {"status": "cancelled"})
            return
        except PermissionError as exc:
            log.warning("agt_policy_denial_stream", task_id=task_id, error=str(exc))
            await _update_task(task_id, {"status": "denied"})
            yield {
                "event": "error",
                "data": '{"error": "Request denied by governance policy"}',
            }
            return
        except Exception as exc:
            log.error("query_run_failed", task_id=task_id, error=str(exc))
            await _update_task(task_id, {"status": "failed"})
            yield {"event": "error", "data": '{"error": "Internal server error"}'}
            return

        import json as _json
        await _update_task(task_id, {"status": result.get("status_message", "completed")})

        # FR-6.1: the instant a request PARKS on approval it becomes an offline-deliverable
        # outcome. Write a DURABLE, account-bound "pending" record now (keyed by the
        # requester's namespaced principal) so it is waiting on next login regardless of
        # whether this browser tab stays open — independent of any client poll loop. The
        # record carries the full question so GET /inbox can REGENERATE the answer through
        # the governed pipeline at delivery (FR-6.2); its live status (pending → completed /
        # declined) is recomputed there. Cross-division parks (peer-originated) are delivered
        # to the requester's HOME store by that division's callback, not here. Best-effort:
        # a store hiccup must not break the live SSE response (the user is still online here).
        result_flow = (result.get("flow") or "").lower()
        # Callback-binding (FR-6.6, callback-injection guard): when a request PARKS as a
        # FEDERATED/REMOTE task (delegated to a peer for the owner's decision), record the
        # delegate peer's DID + a federated flag ON THE TASK RECORD. POST /tasks/{id}/callback
        # then accepts an outcome write ONLY from that delegate DID for a federated task —
        # so a trusted-but-unrelated peer can neither overwrite a victim's pending outcome
        # (DoS-on-delivery) nor inject an outcome onto a purely-local task. A "remote" flow is
        # the only one whose outcome legitimately arrives via a peer callback.
        if "remote" in result_flow:
            try:
                await _update_task(
                    task_id,
                    {"_federated": True, "_delegate_did": settings.peer_agent_did or ""},
                )
            except Exception as exc:
                log.warning("query_federation_mark_failed", task_id=task_id, error=str(exc))
        if "needs_approval" in result_flow:
            try:
                import outcome_store
                await outcome_store.put(
                    principal_id=user_id,
                    task_id=task_id,
                    question=raw_query,
                    status="pending",
                )
                await outcome_store.bump_badge(user_id)
            except Exception as exc:
                log.warning("query_outcome_seed_failed", task_id=task_id, error=str(exc))

        yield {
            "event": "result",
            "data": _json.dumps({
                "task_id": result.get("task_id", task_id),
                "answer": result.get("answer", ""),
                "status_message": result.get("status_message", ""),
                "flow": result.get("flow", ""),
                "approval_request_id": result.get("approval_request_id"),
                "peer_task_id": result.get("peer_task_id"),
            }),
        }
        yield {"event": "done", "data": "{}"}

    return EventSourceResponse(event_stream())


# ── POST /solve ───────────────────────────────────────────────────────────────

@app.post("/solve")
async def solve(
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Governed cross-agent TOOL endpoint — the user trigger for solve_with_tools.

    GOVERNED FLOW: this is the front door to the governed tool path. A request names a TOOL
    capability (directly, or as free text we route). We solve it LOCALLY through our governed
    MCP executor when THIS division serves the capability; otherwise we DISCOVER a trusted peer
    that does (broker, or the configured peer_tool_map) and DELEGATE the call over the
    DID-signed /a2a/tool channel — the peer runs ITS governed tool and returns a signed result.
    The user's identity travels onward only as a recipient-bound, time-limited ASSERTION minted
    from the validated JWT claims (set_user_claims below), NEVER a raw bearer token on the wire.

    Auth — mirrors POST /query EXACTLY:
      * kill-switch engaged → 503 (administrative disable, before any work);
      * JWT validated via _get_bearer_token; principal(claims) → user_id (401 if unbuildable);
      * per-subject rate limit (_check_rate_limit) before any tool/LLM work.

    Request body (either form):
      * DIRECT:  {"capability": "tool.pii", "arguments": {"text": "..."}}
      * ROUTED:  {"problem": "screen this text for PII: ..."}   (routed via _route_capability)

    Response (JSON, the solve_with_tools result):
      {"status": "completed"|"failed"|"no_capability",
       "source": "local"|"peer"|"none",
       "capability": "tool.pii",            # the resolved capability (absent if unroutable)
       "result": {...},                      # present when status == "completed"
       "reason": "...",                      # present on failure / degradation
       "peer_did": "did:mesh:..."}           # present when delegated to a peer
    """
    # Kill-switch: refuse the governed-tool path before any work (same posture as /query).
    if await _runtime_kill_switch_engaged():
        log.warning("kill_switch_refused_solve", agt_audit=True)
        raise HTTPException(
            status_code=503,
            detail="Agent administratively disabled (kill-switch engaged)",
        )

    # Validate JWT and extract user identity (identical to /query).
    try:
        _token, claims = await _get_bearer_token(authorization)
    except HTTPException:
        raise
    except PermissionError as exc:
        log.warning("agt_policy_denial_solve", error=str(exc))
        raise HTTPException(status_code=403, detail="Request denied by governance policy")

    try:
        user_id = principal(claims)
    except ValueError as exc:
        log.warning("solve_principal_unbuildable", error=str(exc))
        raise HTTPException(
            status_code=401,
            detail="Token lacks a verified email required for authorization",
        )

    # Per-subject rate limit before the (potentially delegated) tool work.
    await _check_rate_limit(user_id)

    # Parse + validate the request body.
    import json
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    capability = body.get("capability")
    arguments = body.get("arguments")
    problem = body.get("problem")

    if capability is not None:
        # DIRECT form: an explicit capability + arguments object.
        if not isinstance(capability, str) or not capability.strip():
            raise HTTPException(status_code=400, detail="'capability' must be a non-empty string")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise HTTPException(status_code=400, detail="'arguments' must be a JSON object")
        # Reject non-finite numbers (inf/nan can't be re-serialized in the signed peer payload).
        if _has_non_finite_number(arguments):
            raise HTTPException(status_code=422, detail="'arguments' contain a non-finite number")
        if len(json.dumps(arguments).encode("utf-8")) > _MAX_TOOL_ARGS_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"'arguments' exceed the maximum size of {_MAX_TOOL_ARGS_BYTES} bytes",
            )
    else:
        # ROUTED form: free-text problem the deterministic router maps to a capability.
        if not isinstance(problem, str) or not problem.strip():
            raise HTTPException(
                status_code=400,
                detail="Provide either 'capability' (+ 'arguments') or a non-empty 'problem'",
            )
        if len(problem) > settings.max_query_length:
            raise HTTPException(
                status_code=400,
                detail=f"'problem' exceeds the maximum length of {settings.max_query_length} characters",
            )

    # Set the per-request user CLAIMS ContextVar so a DELEGATED tool call mints its
    # recipient-bound assertion from the VALIDATED claims (not a raw token), exactly like the
    # /query path. minimal_assertion_claims strips the claims to the non-replayable subset.
    agent_nodes.set_user_claims(minimal_assertion_claims(claims))

    log.info("solve_request", user_id=user_id,
             capability=capability or "(routed)", agt_audit=True)

    result = await agent_nodes.solve_with_tools(
        problem,
        user_id=user_id,
        capability=capability,
        arguments=arguments,
    )
    return JSONResponse(result)


# ── GET /tasks/{task_id}/result ───────────────────────────────────────────────

@app.get("/tasks/{task_id}/result")
async def task_result(
    task_id: str,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Requester-side approval-outcome poll (the UI polls this after a query parks
    on `input-required`).

    Re-checks the CALLER's CURRENT authorization for the task's original query by
    re-running the governed pipeline in check_only mode — which RE-CHECKS live OpenFGA
    state but does NOT start a new approval workflow (see start_approval). Returns:
        {"status": "pending"}                    — still awaiting the owner's decision
        {"status": "completed", "answer": "..."} — approved → answer released
        {"status": "denied", "message": "..."}   — denied / timed out / no access

    Security:
      * the bearer token is validated and the namespaced principal MUST own the task
        (no IDOR — a user cannot poll another user's task);
      * the answer is released ONLY after a fresh OpenFGA re-authorization, so a
        revoked/expired grant stops delivering immediately (no stale replay);
      * read-only — it never mutates authorization state, and the check_only flag is
        threaded to the peer so a cross-division poll never re-notifies the data owner.
    """
    token, claims = await _get_bearer_token(authorization)
    try:
        user_id = principal(claims)
    except ValueError as exc:
        log.warning("task_result_principal_unbuildable", error=str(exc))
        raise HTTPException(
            status_code=401,
            detail="Token lacks a verified email required for authorization",
        )

    # Rate-limit: each poll re-runs the governed pipeline (OpenFGA + a possible cross-division
    # peer call + LLM), and the UI polls every ~4s — so an unthrottled caller is a real cost/DoS
    # vector. Legitimate polling stays well under the per-minute limit.
    await _check_rate_limit(user_id)

    rec = await _load_task(task_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Task not found")
    # IDOR guard: only the task's owner (namespaced principal) may poll it.
    if rec.get("_owner_id") != user_id:
        log.warning("task_result_ownership_denied", task_id=task_id, agt_audit=True)
        raise HTTPException(status_code=403, detail="Not the owner of this task")

    query_text = rec.get("query_full") or rec.get("query") or ""
    if not query_text:
        return JSONResponse({"status": "pending"})

    # Re-run the governed pipeline check-only: re-authorize against live OpenFGA, never
    # spawn a new approval. Claims come from THIS caller's token (a cross-division
    # re-check forwards them to the peer, exactly like /query).
    fwd_claims = minimal_assertion_claims(claims)
    try:
        result = await agent_graph.run_query(
            query=query_text,
            user_id=user_id,
            user_claims=fwd_claims,
            task_id=task_id,
            context_id="",
            check_only=True,
            user_groups=extract_groups(claims),
        )
    except PermissionError as exc:
        log.warning("task_result_governance_denied", task_id=task_id, error=str(exc))
        return JSONResponse({"status": "denied", "message": "Request denied by governance policy"})
    except Exception as exc:
        log.error("task_result_run_failed", task_id=task_id, error=str(exc))
        raise HTTPException(status_code=503, detail="Could not check task result")

    flow = (result.get("flow") or "").lower()
    answer = result.get("answer") or ""
    if "needs_approval" in flow:
        return JSONResponse({"status": "pending"})
    if ("allowed" in flow or "approved" in flow) and answer:
        await _update_task(task_id, {"status": "completed"})
        log.info("task_result_delivered", task_id=task_id, agt_audit=True)
        return JSONResponse({"status": "completed", "answer": answer})
    # LOCAL_DENIED / REMOTE_DENIED / no access — owner declined, timed out, or the
    # grant was never made (deny/timeout revoke the pending tuple). No data leak.
    return JSONResponse({
        "status": "denied",
        "message": "Your request was declined or you no longer have access.",
    })


# ── Regenerate-at-delivery helper (shared by /tasks/{id}/result and /inbox) ────

async def _regenerate_outcome(
    user_id: str,
    question: str,
    claims: dict[str, Any],
    task_id: str,
    declined_message: str = "Your request was declined or you no longer have access.",
) -> dict[str, Any]:
    """Re-run the governed pipeline (check_only) for ``user_id``'s ``question`` and map the
    result to a delivery outcome. This is the FR-6.2 fail-closed re-check: the answer is
    (re)generated server-side under the CALLER's CURRENT authorization at delivery time, so a
    revoked/expired grant between decision and login cannot leak stale data.

    Returns one of:
        {"status": "pending"}
        {"status": "completed", "answer": "..."}
        {"status": "denied", "message": "..."}
    """
    if not question:
        # No question to re-run (e.g. a denial record carrying only a message). Treat as a
        # terminal declined outcome rather than fabricating access.
        return {"status": "denied", "message": declined_message}
    fwd_claims = minimal_assertion_claims(claims)
    try:
        result = await agent_graph.run_query(
            query=question,
            user_id=user_id,
            user_claims=fwd_claims,
            task_id=task_id,
            context_id="",
            check_only=True,
            user_groups=extract_groups(claims),
        )
    except PermissionError:
        return {"status": "denied", "message": "Request denied by governance policy"}
    flow = (result.get("flow") or "").lower()
    answer = result.get("answer") or ""
    if "needs_approval" in flow:
        return {"status": "pending"}
    if ("allowed" in flow or "approved" in flow) and answer:
        return {"status": "completed", "answer": answer}
    return {"status": "denied", "message": declined_message}


# ── GET /inbox ────────────────────────────────────────────────────────────────

@app.get("/inbox")
async def inbox(
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """FR-6: the requester's durable, account-bound outcome inbox — surfaced on NEXT LOGIN.

    Returns every waiting outcome for the AUTHENTICATED caller (keyed by their namespaced
    principal — IDOR-safe, a user only ever sees their OWN inbox), retrieved from the durable
    store with NO short TTL and NO dependence on a client poll loop (FR-6.1/6.4). Each item is
    presented against its original question.

    REGENERATE-AT-DELIVERY (FR-6.2): for every record carrying a question we RE-RUN the full
    governed pipeline in check_only mode at this moment, so the delivered status reflects
    CURRENT authorization — an approval whose grant was since revoked/expired delivers
    "declined", not a stale answer; a still-open request stays "pending"; a granted one
    regenerates the actual answer. A denial record (FR-6.3) returns its declined message.

    Also returns the in-app badge count (FR-6.5). Read-only — never mutates authz state.
    """
    _, claims = await _get_bearer_token(authorization)
    try:
        user_id = principal(claims)
    except ValueError as exc:
        log.warning("inbox_principal_unbuildable", error=str(exc))
        raise HTTPException(
            status_code=401,
            detail="Token lacks a verified email required for authorization",
        )
    await _check_rate_limit(user_id)        # each item re-runs the pipeline — bound it

    import outcome_store
    records = await outcome_store.list_outcomes(user_id)

    items: list[dict[str, Any]] = []
    for rec in records:
        task_id = rec.get("task_id", "")
        question = rec.get("question", "")
        stored_status = rec.get("status", "pending")
        item: dict[str, Any] = {
            "task_id": task_id,
            "question": question,
            "decided_at": rec.get("decided_at"),
            "acknowledged": rec.get("acknowledged", False),
        }
        if stored_status == "denied" and not question:
            # Terminal declined record with no question to re-run — deliver as recorded.
            item["status"] = "denied"
            item["message"] = rec.get("answer_or_message") \
                or "Your request was declined or you no longer have access."
        else:
            # Regenerate live status under the caller's CURRENT authorization (FR-6.2).
            try:
                outcome = await _regenerate_outcome(user_id, question, claims, task_id)
            except Exception as exc:
                log.error("inbox_regenerate_failed", task_id=task_id, error=str(exc))
                # Fail closed: do not deliver an answer we could not re-authorize.
                outcome = {"status": "pending"}
            item.update(outcome)
        items.append(item)

    badge = await outcome_store.read_badge(user_id)
    log.info("inbox_listed", count=len(items), badge=badge, agt_audit=True)
    return JSONResponse(content={"items": items, "badge": badge}, status_code=200)


# ── POST /inbox/{task_id}/ack ─────────────────────────────────────────────────

@app.post("/inbox/{task_id}/ack")
async def inbox_acknowledge(
    task_id: str,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Acknowledge (clear) one inbox outcome so it leaves the default next-login view.

    Authenticated; the namespaced principal is the inbox key, so a caller can only ack
    their OWN outcomes (IDOR-safe). Idempotent — acking an absent/already-acked item is a
    no-op 'acknowledged: false/true' result, never an error. Decrements the in-app badge.
    """
    _validate_safe_id(task_id, "task_id")
    _, claims = await _get_bearer_token(authorization)
    try:
        user_id = principal(claims)
    except ValueError as exc:
        log.warning("inbox_ack_principal_unbuildable", error=str(exc))
        raise HTTPException(
            status_code=401,
            detail="Token lacks a verified email required for authorization",
        )
    import outcome_store
    acked = await outcome_store.acknowledge(user_id, task_id)
    return JSONResponse(content={"acknowledged": acked}, status_code=200)


# ── POST /a2a/query ───────────────────────────────────────────────────────────

@app.post("/a2a/query")
async def a2a_query(request: Request) -> JSONResponse:
    """Cross-cluster peer query endpoint — DID-authenticated, not user-JWT.

    This is the receiving side of the AgentMesh federation transport. The peer
    cluster's mesh.peer_client.call_peer_agent() POSTs a DID-signed query here.

    Auth (peer-to-peer): there is NO user bearer token on this path. The request
    is authenticated by the Ed25519 signature in the ``_agentmesh`` envelope,
    verified by verify_signed_message() against the peer's PUBLIC key from
    trusted config (settings.peer_agent_public_jwk) — never from the body. The
    verified signer must equal the configured PEER_AGENT_DID. A request whose
    signature does not verify is rejected with 401.

    Delegated authorization: the ``user_id`` is read from the *signed* payload
    (so it cannot be forged) and the SAME governed pipeline as /query runs with
    that user_id. OpenFGA therefore re-decides the delegated user's access to
    THIS cluster's data — the peer does not bypass authorization, it only
    vouches for the user's identity. The raw user JWT is never forwarded.

    Response: a DID-SIGNED JSON object (sign_outbound_message) so the caller can
    verify it came from this cluster's private key. Shape:
        {status, answer, task_id, approval_request_id, _agentmesh}
    where status ∈ {"completed", "input_required", "failed"}.
    """
    # Kill-switch (FR-4.3): halt the WHOLE division's governed path, not just the user
    # /query surface — refuse inbound cross-division requests before any work. Consults
    # the RUNTIME flag (Redis) plus the deploy-time settings flag, so an operator halt via
    # POST /admin/kill-switch takes effect here with no restart. Fail-closed (503).
    if await _runtime_kill_switch_engaged():
        log.warning("kill_switch_refused_a2a_query", agt_audit=True)
        raise HTTPException(
            status_code=503,
            detail="Agent administratively disabled (kill-switch engaged)",
        )

    # Parse body, then reject any non-finite JSON number anywhere in the document
    # (Infinity/-Infinity/NaN and any literal like 1e400 that json.loads coerces to inf).
    # Starlette's request.json() uses json.loads with DEFAULT settings, which accept those
    # non-standard tokens; an inf/nan `exp` would then defeat the assertion expiry guard
    # (never-expiring assertion). Post-validating the parsed structure closes that at the
    # edge so the malformed value never enters the system (defence-in-depth alongside the
    # finite check in validate_cross_division_assertion).
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")
    if _has_non_finite_number(payload):
        log.warning("a2a_query_non_finite_number", agt_audit=True)
        raise HTTPException(status_code=422, detail="Request body contains a non-finite number")

    # ── DID authentication: verify the Ed25519 signature on the payload ──────
    sig_verified, signer_did = await agent_identity.verify_signed_message(payload)
    if not sig_verified or not signer_did:
        log.warning("a2a_query_signature_invalid", agt_audit=True)   # M8: forged/unsigned peer msg
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing AgentMesh message signature",
        )

    # Per-PEER rate limit on this federation endpoint: bound a compromised-but-trusted peer
    # from driving unbounded retrieval/LLM cost through /a2a/query. Keyed on the verified
    # signer DID (a per-user limit is evadable — a peer can rotate user_ids).
    await _check_rate_limit(signer_did, limit=settings.peer_rate_limit_per_minute,
                            prefix="peerlimit")

    # Registry trust-score gate on the verified signer (defence in depth).
    verified, trust_score = await agent_identity.verify_peer_identity(signer_did)
    if not verified or trust_score < settings.agent_trust_threshold:
        log.warning(
            "a2a_query_peer_identity_rejected",
            signer_did=signer_did,
            trust_score=trust_score,
            agt_audit=True,                                          # M8: rejected peer identity
        )
        raise HTTPException(status_code=403, detail="Peer identity verification failed")

    # M3 multi-peer: the signer is already proven to be a TRUSTED peer (its DID is a key
    # in settings.peer_trust — verify_signed_message rejected otherwise). Resolve THIS
    # signer's bound issuer from the map for the per-DID assertion binding below.
    peer_issuer = settings.peer_trust.get(signer_did, {}).get("issuer", "")

    # ── Extract the delegated query from the SIGNED payload ──────────────────
    raw_query = payload.get("query", "")
    if not isinstance(raw_query, str) or not raw_query.strip():
        raise HTTPException(status_code=400, detail="'query' field must be a non-empty string")
    if len(raw_query) > settings.max_query_length:
        raise HTTPException(
            status_code=400,
            detail=f"Query exceeds maximum length of {settings.max_query_length} characters",
        )

    # M2/Wave-3 (FR-3.6), security-hardened: derive the AUTHORITATIVE user identity from the
    # RECIPIENT-BOUND, time-limited user-assertion CLAIMS in the (already signature-verified,
    # replay-protected) envelope — NOT a forwarded raw bearer token (which a compromised peer
    # could replay against the user's HOME APIs). validate_cross_division_assertion enforces,
    # all fail-closed:
    #   • aud == THIS division's own DID (recipient binding) — so an assertion minted for
    #     another division cannot be forwarded here (cross-recipient replay guard);
    #   • exp not passed (short-lived) — bounded acceptance even inside the envelope window;
    #   • iss bound to THIS specific signing peer (peer_issuer, from the per-DID trust map) —
    #     so a compromised-but-trusted peer cannot assert ANOTHER division's user even with N
    #     peers; it fails closed if peer_issuer is empty (a half-populated map entry never
    #     widens acceptance).
    # The identity WITHIN the signer's namespace is vouched by the DID-authenticated home
    # agent (see assertion_principal's trust-model note), not re-verified against home Keycloak.
    assertion = payload.get("user_assertion")
    if not isinstance(assertion, dict):
        raise HTTPException(
            status_code=401,
            detail="Missing cross-division user assertion — identity required",
        )
    self_did = await agent_identity.get_did()   # the audience the assertion must be bound to
    try:
        user_id = validate_cross_division_assertion(
            assertion,
            expected_issuer=peer_issuer,
            expected_audience=self_did,
        )
    except Exception as exc:
        log.warning("a2a_query_assertion_invalid", error=str(exc), agt_audit=True)  # M8
        raise HTTPException(status_code=401, detail="Invalid cross-division user assertion")

    context_id = str(payload.get("context_id", "")) or str(uuid.uuid4())
    # Approval-poll re-auth (signed in the envelope): re-check this delegated user's
    # access against live OpenFGA WITHOUT restarting our approval workflow.
    check_only = bool(payload.get("check_only", False))
    task_id = str(uuid.uuid4())
    # M0 tenancy: the originating division (from the SIGNED envelope) is recorded
    # so cross-division requests are attributable in this division's audit.
    source_division = str(payload.get("source_division", "")) or "unknown"

    log.info(
        "a2a_query_received",
        signer_did=signer_did,
        trust_score=trust_score,
        user_id=user_id,
        source_division=source_division,
        division_id=settings.division_id,
    )

    # M4 (FR-6): cross-division callback target. The caller sends callback_url = its OWN
    # agent's /tasks/<id>/callback. SSRF guard: accept it ONLY if it targets the SIGNING
    # peer's known agent_url (from the trust map) and has the expected /tasks/<id>/callback
    # shape — never an attacker-chosen host. If approval is needed, the workflow calls back
    # this target ("approved, re-send"); the user then re-runs the governed pipeline (D-6).
    orig_agent_url = orig_task_id = None
    raw_cb = str(payload.get("callback_url", "")).strip()
    if raw_cb:
        peer_url = str(settings.peer_trust.get(signer_did, {}).get("agent_url", "")).rstrip("/")
        if peer_url and raw_cb.startswith(peer_url + "/tasks/") and raw_cb.endswith("/callback"):
            orig_agent_url = peer_url
            orig_task_id = raw_cb[len(peer_url) + len("/tasks/"):-len("/callback")]
        else:
            log.warning("a2a_callback_url_untrusted", signer_did=signer_did, agt_audit=True)

    # ── Run the SAME governed pipeline as /query ─────────────────────────────
    # The peer's DID-signed claims established user_id; OpenFGA on THIS division
    # re-authorizes that principal. No onward forwarding here (single-hop), so no
    # user_claims are injected.
    try:
        result = await agent_graph.run_query(
            query=raw_query,
            user_id=user_id,
            user_claims=None,     # single-hop: nothing to forward onward
            allow_remote=False,   # M3 loop guard: a peer-originated query must not re-delegate
            task_id=task_id,
            context_id=context_id,
            originating_agent_url=orig_agent_url,   # M4: SSRF-validated callback target
            originating_task_id=orig_task_id,
            check_only=check_only,  # approval-poll: re-check without restarting our workflow
        )
    except PermissionError as exc:
        log.warning("a2a_query_governance_denied", task_id=task_id, error=str(exc))
        result = {
            "answer": "",
            "status_message": "denied",
            "approval_request_id": None,
            "task_id": task_id,
        }
    except Exception as exc:
        log.error("a2a_query_run_failed", task_id=task_id, error=str(exc))
        result = {
            "answer": "",
            "status_message": "failed",
            "approval_request_id": None,
            "task_id": task_id,
        }

    # ── Map the pipeline outcome to a peer-protocol status ───────────────────
    # approval_request_id is checked FIRST: format_response overwrites a None
    # answer with the status_message, so the pending-approval case (flow B/D on
    # this cluster) returns a non-empty answer — keying on answer-presence would
    # misclassify it as completed.
    approval_request_id = result.get("approval_request_id")
    status_message = result.get("status_message", "")
    answer = result.get("answer") or ""
    flow = result.get("flow", "")
    # "NEEDS_APPROVAL in flow" covers the check_only re-poll: start_approval returns
    # approval_request_id=None (no new workflow) but the flow is still *_NEEDS_APPROVAL,
    # so the request is genuinely pending — not a failure.
    if approval_request_id or "needs_approval" in flow.lower():
        peer_status = "input_required"
    elif status_message == "completed" and answer:
        peer_status = "completed"
    else:
        peer_status = "failed"

    response_payload: dict[str, Any] = {
        "status": peer_status,
        "answer": answer if peer_status == "completed" else None,
        "task_id": result.get("task_id", task_id),
        "approval_request_id": approval_request_id,
    }

    # Sign the response so the caller can verify it came from this cluster.
    signed_response = await agent_identity.sign_outbound_message(response_payload)
    log.info("a2a_query_responding", task_id=task_id, status=peer_status)
    return JSONResponse(content=signed_response)


# ── POST /a2a/tool ─────────────────────────────────────────────────────────────

# Bound the delegated tool ARGUMENTS so an oversized payload can't be smuggled across
# the channel (DoS / pathological-parse guard). The canonical JSON of the arguments must
# fit this many bytes; the local tools themselves (calc/units) also bound their own inputs.
_MAX_TOOL_ARGS_BYTES = 8192


@app.post("/a2a/tool")
async def a2a_tool(request: Request) -> JSONResponse:
    """Cross-agent GOVERNED TOOL DELEGATION endpoint — DID-authenticated, not user-JWT.

    This is the receiving side of the /a2a/tool channel. A peer that lacks a TOOL
    capability discovers an agent that advertises it and POSTs a DID-signed delegation
    here (mesh.peer_client.call_peer_tool). We run OUR OWN governed tool — authorizing
    the DELEGATED USER for the capability so the peer does NOT bypass authz — and return
    a DID-SIGNED result. The envelope is IDENTICAL to /a2a/query (so the two channels can
    never diverge); only the body differs (a tool capability + arguments, not a query).

    Security envelope, in order (each step mirrors the same step in a2a_query):
      1. kill-switch (FR-4.3) → 503;
      2. parse JSON; reject non-finite numbers → 422;
      3. verify the Ed25519 signature (-> signer DID); fail closed → 401;
      4. registry trust-score gate on the verified signer → 403;
      5. resolve the signer's bound issuer from the per-DID trust map;
      6. extract + type/size-validate the tool request (capability OR server+tool, +args);
      7. derive the user from the RECIPIENT-BOUND signed assertion (aud == self DID) → 401;
      8. authorize the DELEGATED user for mcp.call (default-deny) THEN run our governed tool;
      9. audit every received/authorized/executed/denied case (agt_audit=True);
     10. build {status, result, tool, capability, task_id, _agentmesh} and SIGN it.

    A tool-level failure (unconfigured capability, bad arguments, policy denial) returns a
    SIGNED ``status="failed"`` result — never a 500 leak — so the caller always gets a
    verifiable answer it can act on.
    """
    # ── Step 1: kill-switch — halt the whole division before any work (503) ──
    if await _runtime_kill_switch_engaged():
        log.warning("kill_switch_refused_a2a_tool", agt_audit=True)
        raise HTTPException(
            status_code=503,
            detail="Agent administratively disabled (kill-switch engaged)",
        )

    # ── Step 2: parse + reject non-finite numbers (never-expiring-assertion guard) ──
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")
    if _has_non_finite_number(payload):
        log.warning("a2a_tool_non_finite_number", agt_audit=True)
        raise HTTPException(status_code=422, detail="Request body contains a non-finite number")

    # ── Step 3: DID authentication — verify the Ed25519 signature on the payload ──
    sig_verified, signer_did = await agent_identity.verify_signed_message(payload)
    if not sig_verified or not signer_did:
        log.warning("a2a_tool_signature_invalid", agt_audit=True)   # M8: forged/unsigned peer msg
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing AgentMesh message signature",
        )

    # ── Step 3b: per-PEER rate limit — bound a compromised-but-trusted peer from driving
    # unbounded governed-tool/LLM cost through /a2a/tool. Keyed on the verified signer DID.
    await _check_rate_limit(signer_did, limit=settings.peer_rate_limit_per_minute,
                            prefix="peerlimit")

    # ── Step 4: registry trust-score gate on the verified signer (defence in depth) ──
    verified, trust_score = await agent_identity.verify_peer_identity(signer_did)
    if not verified or trust_score < settings.agent_trust_threshold:
        log.warning(
            "a2a_tool_peer_identity_rejected",
            signer_did=signer_did,
            trust_score=trust_score,
            agt_audit=True,                                          # M8: rejected peer identity
        )
        raise HTTPException(status_code=403, detail="Peer identity verification failed")

    # ── Step 5: resolve the signer's bound issuer for the per-DID assertion binding ──
    peer_issuer = settings.peer_trust.get(signer_did, {}).get("issuer", "")

    # ── Step 6: extract + validate the delegated TOOL request from the SIGNED payload ──
    # The caller names a CAPABILITY (e.g. "tool.pii") — resolved to OUR local server here,
    # never the peer's server name — OR an explicit server+tool pair. Arguments must be a
    # dict and bounded in size (DoS guard). All type/size failures are 400 (malformed request).
    from tools.local_tools import (
        capability_for as _capability_for,
        server_for_capability as _server_for_capability,
    )
    capability = payload.get("capability")
    server = payload.get("server")
    tool = payload.get("tool")
    arguments = payload.get("arguments", {})
    if not isinstance(arguments, dict):
        raise HTTPException(status_code=400, detail="'arguments' must be a JSON object")
    import json
    try:
        args_size = len(json.dumps(arguments))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="'arguments' must be JSON-serialisable")
    if args_size > _MAX_TOOL_ARGS_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"'arguments' exceed the maximum size of {_MAX_TOOL_ARGS_BYTES} bytes",
        )
    if capability is not None:
        if not isinstance(capability, str) or not capability.strip():
            raise HTTPException(status_code=400, detail="'capability' must be a non-empty string")
        resolved_server = _server_for_capability(capability)
        if resolved_server is None:
            # Unconfigured capability → SIGNED "failed", not a 500/raw error (per the contract).
            log.warning("a2a_tool_unconfigured_capability", signer_did=signer_did,
                        capability=capability, agt_audit=True)
            return await _signed_tool_failure(
                capability=capability, tool=None,
                reason=f"capability '{capability}' is not served by this agent",
            )
        server = resolved_server
        # The local registry maps a server to exactly one tool of the same domain; pick it.
        tool = tool if isinstance(tool, str) and tool.strip() else _default_tool_for(server)
    else:
        # Explicit server+tool (no capability hint). Both must be non-empty strings.
        if not (isinstance(server, str) and server.strip()
                and isinstance(tool, str) and tool.strip()):
            raise HTTPException(
                status_code=400,
                detail="provide a 'capability' OR an explicit 'server'+'tool'",
            )
        capability = _capability_for(server)   # may be None for a non-local server (audited)

    # ── Step 7: derive the user from the RECIPIENT-BOUND signed assertion (401 on failure) ──
    # The user_id comes ONLY from the signed, recipient-bound assertion (aud == self DID),
    # NEVER an unsigned body field or a raw token — same guarantee as a2a_query.
    assertion = payload.get("user_assertion")
    if not isinstance(assertion, dict):
        raise HTTPException(
            status_code=401,
            detail="Missing cross-division user assertion — identity required",
        )
    self_did = await agent_identity.get_did()   # the audience the assertion must be bound to
    try:
        user_id = validate_cross_division_assertion(
            assertion,
            expected_issuer=peer_issuer,
            expected_audience=self_did,
        )
    except Exception as exc:
        log.warning("a2a_tool_assertion_invalid", error=str(exc), agt_audit=True)  # M8
        raise HTTPException(status_code=401, detail="Invalid cross-division user assertion")

    task_id = str(uuid.uuid4())
    source_division = str(payload.get("source_division", "")) or "unknown"

    log.info(
        "a2a_tool_received",
        signer_did=signer_did,
        trust_score=trust_score,
        user_id=user_id,
        capability=capability,
        server=server,
        tool=tool,
        source_division=source_division,
        division_id=settings.division_id,
    )

    # ── Step 8: GOVERNED EXECUTION — authorize the DELEGATED user, THEN run our tool ──
    # Default-deny policy gate (the SAME engine call_mcp_tool uses), extended with the
    # delegated user_id + source_division so the decision is policy-decidable + audited —
    # the peer cannot bypass OUR authorization by reaching in over /a2a/tool.
    try:
        await agent_nodes._enforce(
            "mcp.call",
            {
                "server": server,
                "tool": tool,
                "user_id": user_id,
                "source_division": source_division,
                "capability": capability,
            },
        )
    except PermissionError as exc:
        log.warning("a2a_tool_policy_denied", signer_did=signer_did, user_id=user_id,
                    capability=capability, server=server, tool=tool, error=str(exc),
                    agt_audit=True)
        return await _signed_tool_failure(
            capability=capability, tool=tool, task_id=task_id,
            reason="policy denied the delegated tool call",
        )

    # Run OUR governed local tool (which itself re-runs the executor's three gates).
    from tools.local_tools import run_local_tool
    try:
        result = await run_local_tool(server, tool, arguments)
    except Exception as exc:  # noqa: BLE001 — a tool error must NOT leak as a 500
        log.warning("a2a_tool_execution_failed", signer_did=signer_did, user_id=user_id,
                    capability=capability, server=server, tool=tool,
                    error_type=type(exc).__name__, error=str(exc), agt_audit=True)
        return await _signed_tool_failure(
            capability=capability, tool=tool, task_id=task_id,
            reason="tool execution failed",
        )

    # ── Step 10: VALIDATE the result, then build + SIGN it ───────────────────
    # F2 (defence-in-depth): the inbound _has_non_finite_number guard only checks the REQUEST
    # body — a governed tool can still COMPUTE a value JSONResponse can't serialize (inf/nan
    # under allow_nan=False, or an int past CPython's str-digit limit). That ValueError would
    # fire inside render() AFTER this handler returns, defeating the try/except around execution
    # and surfacing as an uncaught 500 instead of the contract's signed status="failed". So we
    # reject an unserializable result HERE and route it through the same signed-failure path.
    if not _result_is_json_safe(result):
        log.warning("a2a_tool_result_unserializable", signer_did=signer_did, user_id=user_id,
                    capability=capability, server=server, tool=tool, agt_audit=True)
        return await _signed_tool_failure(
            capability=capability, tool=tool, task_id=task_id,
            reason="tool produced an unserializable result",
        )

    log.info(
        "a2a_tool_executed",
        signer_did=signer_did,
        user_id=user_id,
        capability=capability,
        server=server,
        tool=tool,
        source_division=source_division,
        agt_audit=True,
    )

    response_obj: dict[str, Any] = {
        "status": "completed",
        "result": result,
        "tool": tool,
        "capability": capability,
        "task_id": task_id,
        "source_division": settings.division_id,
    }
    # Belt-and-suspenders: even with the validation above, ANY error while signing or
    # constructing the response must degrade to a signed failure, never a 500. We pre-render
    # the JSON here (the SAME json.dumps settings JSONResponse uses) so a serialization error
    # is caught in THIS try/except rather than later inside Starlette's render().
    try:
        signed = await agent_identity.sign_outbound_message(response_obj)
        import json
        body = json.dumps(signed, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except Exception as exc:  # noqa: BLE001 — a sign/serialize error must NOT leak as a 500
        log.warning("a2a_tool_response_build_failed", signer_did=signer_did, user_id=user_id,
                    capability=capability, tool=tool, error_type=type(exc).__name__,
                    agt_audit=True)
        return await _signed_tool_failure(
            capability=capability, tool=tool, task_id=task_id,
            reason="failed to build the signed tool result",
        )
    log.info("a2a_tool_responding", task_id=task_id, status="completed")
    return Response(content=body, media_type="application/json")


def _default_tool_for(server: str) -> str:
    """The default tool name a local capability-server exposes (its first registered tool).

    A capability maps to exactly one local server, and each local server exposes one tool of
    the same domain; this returns that tool when the caller named only the capability. Falls
    back to the server name's suffix so an unconfigured server still yields a stable string
    (run_local_tool then fails it CLOSED through the governed executor)."""
    from tools.local_tools import local_server_configs
    for cfg in local_server_configs():
        if cfg.get("name") == server:
            tools = cfg.get("tools") or []
            if tools:
                return str(tools[0])
    return server.rsplit("-", 1)[-1]


async def _signed_tool_failure(
    *,
    capability: str | None,
    tool: str | None,
    reason: str,
    task_id: str | None = None,
) -> JSONResponse:
    """Build + DID-SIGN a ``status="failed"`` /a2a/tool result (never a 500 leak).

    Every delegated-tool failure (unconfigured capability, policy denial, tool error) is
    returned to the caller as a SIGNED result it can verify — the reason is a generic,
    non-leaky string (no stack traces / internal identifiers reach the peer)."""
    response_obj: dict[str, Any] = {
        "status": "failed",
        "result": None,
        "tool": tool,
        "capability": capability,
        "task_id": task_id or str(uuid.uuid4()),
        "reason": reason,
        "source_division": settings.division_id,
    }
    signed = await agent_identity.sign_outbound_message(response_obj)
    return JSONResponse(content=signed)


# ── POST /tasks/{task_id}/callback ────────────────────────────────────────────

@app.post("/tasks/{task_id}/callback")
async def task_callback(
    task_id: str,
    request: Request,
) -> JSONResponse:
    """Peer agent callback — receives status updates from the federated peer.

    Authentication (Finding #1): the inbound message must carry an `_agentmesh`
    signature block whose signature verifies *against the payload* via
    verify_signed_message().  A DID is public (served by /identity), so a DID
    lookup alone is not authentication — the cryptographic signature check is
    what proves the message came from the peer's private key.

    After signature verification: the registry trust score must clear the
    threshold, the verified signer must equal the configured PEER_AGENT_DID,
    and the AGT policy engine must allow `peer.receive_callback` (Finding #5).
    """
    _validate_safe_id(task_id, "task_id")

    # Parse body
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")

    # ── Finding #1: cryptographically verify the AgentMesh signature ─────────
    # The previous implementation trusted `_agentmesh.sender_did` straight from
    # the request body and only looked it up in the registry — an authentication
    # bypass, since any unauthenticated caller who knows the (public) peer DID
    # could forge a callback.  verify_signed_message() verifies the signature in
    # the `_agentmesh` block against the payload and fails closed otherwise.
    sig_verified, signed_sender_did = await agent_identity.verify_signed_message(payload)
    if not sig_verified or not signed_sender_did:
        log.warning("callback_signature_invalid", task_id=task_id, agt_audit=True)  # M8
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing AgentMesh message signature",
        )

    # The DID asserted in the block must match the cryptographically-verified
    # signer; a mismatch means the body was altered after signing.
    claimed_did = ""
    if isinstance(payload.get("_agentmesh"), dict):
        claimed_did = payload["_agentmesh"].get("sender_did", "")
    if claimed_did and claimed_did != signed_sender_did:
        log.warning(
            "callback_did_mismatch",
            task_id=task_id,
            claimed_did=claimed_did,
            signed_did=signed_sender_did,
            agt_audit=True,                                          # M8: tampered callback body
        )
        raise HTTPException(status_code=403, detail="Sender DID does not match message signature")
    sender_did = signed_sender_did

    # Registry trust-score gate (defence in depth, on the verified signer)
    verified, trust_score = await agent_identity.verify_peer_identity(sender_did)
    if not verified or trust_score < settings.agent_trust_threshold:
        log.warning(
            "callback_peer_identity_rejected",
            task_id=task_id,
            sender_did=sender_did,
            trust_score=trust_score,
            agt_audit=True,                                          # M8: rejected callback peer
        )
        raise HTTPException(status_code=403, detail="Peer identity verification failed")

    # M3 multi-peer: the signer is already proven TRUSTED (its DID is in settings.peer_trust
    # — verify_signed_message rejected otherwise), so no separate single-peer DID check.

    # ── Finding #5: enforce the AGT policy engine on the inbound callback ────
    # peer.receive_callback was previously enforced only inside the LangGraph
    # node, never on this HTTP entry point. A PermissionError is mapped to
    # HTTP 403 by permission_error_handler. The verification values below are
    # the REAL results of the checks performed above in this same function
    # (signature verified, registry trust score, configured-peer match) — not
    # hardcoded optimistic constants (cf. Finding #4).
    await agent_nodes._enforce(
        "peer.receive_callback",
        {
            "task_id": task_id,
            "sender_did": sender_did,
            "peer_did_verified": True,        # signature + registry verified above
            "transport_encrypted": True,      # callbacks traverse the mesh / Istio mTLS
            "peer_trust_score": trust_score,  # real registry trust score
            "peer_execution_ring": "TRUSTED",
            "peer_circuit_state": "CLOSED",   # no outbound circuit breaker on inbound
        },
    )

    # Extract and validate status update
    status = payload.get("status", {})
    state = status.get("state", "")
    message = str(status.get("message", ""))[:500]  # cap free-text

    if not state:
        raise HTTPException(status_code=422, detail="Callback payload missing 'status.state'")

    # ── Task↔delegate binding (callback-injection guard) ─────────────────────
    # The signature gate above proves the caller is SOME trusted peer — it does NOT prove
    # the caller is the peer THIS task was delegated to, nor that the task was federated at
    # all. Without a binding, any one trusted peer could drive an outcome onto any task_id
    # it can guess: overwrite a victim's legitimately-parked 'pending' with a terminal denial
    # (DoS-on-delivery) or inject an outcome onto a purely-local task (inbox/badge spam). We
    # bind here, fail-closed: accept the callback ONLY when the task was recorded federated
    # AND the signing peer's DID equals the delegate DID recorded at park time (see /query
    # event_stream). Read the record once and reuse it for delivery below.
    rec = await _load_task(task_id)
    is_federated = bool(rec.get("_federated")) if rec is not None else False
    delegate_did = (rec.get("_delegate_did", "") if rec is not None else "")
    if not is_federated or not delegate_did or sender_did != delegate_did:
        log.warning(
            "callback_task_delegate_unbound",
            task_id=task_id,
            sender_did=sender_did,
            delegate_did=delegate_did,
            federated=is_federated,
            agt_audit=True,                                          # M8: callback-injection attempt
        )
        raise HTTPException(
            status_code=403,
            detail="Callback peer is not the delegate this task was federated to",
        )

    # Update task in Redis (only after the binding holds)
    await _update_task(task_id, {"peer_status": state, "peer_message": message})

    # ── FR-6.6: deliver the cross-division outcome to the REQUESTER's account ─────
    # This callback arrives in the REQUESTER's HOME division (this is alice's division;
    # the owner who decided lives in the peer division that signed this message). The
    # original /query task here recorded the requester's namespaced principal (_owner_id)
    # and the full question (query_full), so we write a DURABLE, account-bound outcome to
    # THIS division's store — exactly as a same-division park does — so it is waiting on
    # alice's next login regardless of any open tab (no shared client state, no short TTL).
    #
    # FAIL-CLOSED / no stale data: on an APPROVED callback we record a "pending" outcome
    # carrying the question, NOT the answer — GET /inbox re-runs the governed pipeline
    # (which re-delegates to the peer with a fresh authorization re-check) at delivery
    # (FR-6.2). A denial/timeout records the declined message (FR-6.3). The peer's
    # decision is the SIGNATURE-VERIFIED, trust-gated message handled above; this reuses
    # that path and adds no new trust.
    if rec is not None:
        requester = rec.get("_owner_id", "")
        question = rec.get("query_full") or rec.get("query") or ""
        decision = str(payload.get("decision", "")).lower()
        if requester:
            try:
                import outcome_store
                # Idempotency (replay guard): a replayed/retried signed callback must not
                # resurrect an already-delivered outcome (outcome_store.put resets
                # acknowledged=False and re-bumps the badge). Skip the write entirely if a
                # terminal ('completed'/'denied') OR an acknowledged record already exists
                # for this task — the first delivery is authoritative.
                existing = await outcome_store.get(requester, task_id)
                if existing is not None and (
                    existing.get("status") in ("completed", "denied")
                    or existing.get("acknowledged") is True
                ):
                    log.info(
                        "callback_outcome_idempotent_skip",
                        task_id=task_id,
                        existing_status=existing.get("status"),
                        agt_audit=True,
                    )
                else:
                    # Deliver only when BOTH signals agree the request was approved AND the
                    # peer task completed; a 'denied' decision (even with state=='completed')
                    # or an unfinished state records a denial — the more permissive signal
                    # must NOT win (denial-confusion guard).
                    if decision == "approved" and state == "completed":
                        await outcome_store.put(
                            principal_id=requester,
                            task_id=task_id,
                            question=question,
                            status="pending",   # regenerated at /inbox under a fresh authz re-check
                        )
                    else:
                        await outcome_store.put(
                            principal_id=requester,
                            task_id=task_id,
                            question=question,
                            status="denied",
                            answer_or_message=message
                            or "Your cross-division request was declined.",
                        )
                    await outcome_store.bump_badge(requester)
            except Exception as exc:
                # The peer callback itself succeeds (202) even if the local store write
                # fails — the peer must not retry a delivered decision; we log loudly so
                # the missed durable write is visible.
                log.error("callback_outcome_store_failed", task_id=task_id, error=str(exc),
                          agt_audit=True)

    log.info(
        "peer_callback_received",
        task_id=task_id,
        sender_did=sender_did,
        state=state,
        trust_score=trust_score,
    )
    return JSONResponse(content={"ok": True}, status_code=202)


# ── GET /approve/{request_id} ─────────────────────────────────────────────────

@app.get("/approve/{request_id}")
async def handle_approval(
    request_id: str,
    decision: str = Query(..., pattern="^(approve|deny)$"),
    exp: int = Query(..., description="Unix expiry timestamp — link rejected after this time"),
    token: str = Query(..., description="HMAC-SHA256 of '{request_id}:{decision}:{exp}'"),
    reason: str = Query("", description="Optional free-text reason"),
    request: Request = None,  # type: ignore[assignment]
) -> JSONResponse:
    """Approval deep-link — HMAC-protected; signals the Temporal approval workflow.

    Security:
      - HMAC token is verified with hmac.compare_digest (timing-safe).
      - request_id must be alphanumeric + hyphens only.
      - Response never echoes request_id or decision (LOW-3).
      - Temporal errors are logged internally and not surfaced to the caller.
    """
    _validate_safe_id(request_id, "request_id")

    # Finding #2: reject expired links before any work. The expiry is part of
    # the HMAC-signed message, so a caller cannot extend it by editing the query.
    if exp < int(time.time()):
        log.warning("approval_link_expired", request_id=request_id, agt_audit=True)  # M8
        raise HTTPException(status_code=401, detail="Approval link has expired")
    if not _verify_approval_token(request_id, decision, exp, token):
        # M8: an invalid HMAC on an approval link is a forgery attempt — high-signal audit.
        log.warning("approval_hmac_invalid", agt_audit=True)
        raise HTTPException(status_code=401, detail="Invalid or expired approval token")

    temporal_client: TemporalClient = request.app.state.temporal_client
    workflow_id = f"approval-{request_id}"
    handle = temporal_client.get_workflow_handle(workflow_id)

    try:
        await handle.signal(
            "approval_decision",
            ApprovalDecisionSignal(
                decision="approved" if decision == "approve" else "denied",
                reason=reason[:500],   # cap free-text (M3-3)
                # Finding #8: record the decision channel so the workflow audit
                # log is not blank. Full human attribution requires an
                # authenticated approval UI (see SECURITY_REVIEW.md).
                approver_id="approval-deeplink",
            ),
        )
    except Exception as exc:
        log.error("temporal_signal_failed", workflow_id=workflow_id, error=str(exc))
        raise HTTPException(
            status_code=500,
            detail="Failed to record decision. Please try again.",
        )

    # LOW-3: generic acknowledgement — do not echo request_id or decision
    return JSONResponse(content={"message": "Decision recorded. Thank you."})


# ── GET /approvals/pending ────────────────────────────────────────────────────

@app.get("/approvals/pending")
async def list_pending_approvals(
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Authenticated approver inbox — the pending access requests THIS caller
    (as data owner) is entitled to decide.

    The requester never learns the ``request_id`` (L-6); only the owner can enumerate the
    requests routed to them. Backed by the Redis approval index keyed on the caller's
    NAMESPACED principal (email|issuer-ns) — a fast, consistent point read. (The previous
    implementation scanned Temporal `list_workflows`, which on the bundled start-dev server
    is eventually-consistent + O(open requests) — it lagged/stalled the inbox; the index
    removes that dependency. Temporal remains the source of truth for the decision itself.)

    Returns ``{"pending": [{"request_id", "requester_id", "query"}]}``.
    """
    _, claims = await _get_bearer_token(authorization)
    try:
        caller = principal(claims)
    except ValueError as exc:
        log.warning("approvals_pending_principal_unbuildable", error=str(exc))
        raise HTTPException(
            status_code=401,
            detail="Token lacks a verified email required for authorization",
        )
    await _check_rate_limit(caller)        # bound inbox enumeration
    import approval_index
    items = await approval_index.list_for(caller)
    pending = [{"request_id": it.get("request_id", ""),
                "requester_id": it.get("requester_id", ""),
                "query": it.get("query", "")} for it in items]
    return JSONResponse(content={"pending": pending}, status_code=200)


# ── POST /approvals/{request_id}/decision ─────────────────────────────────────

@app.post("/approvals/{request_id}/decision")
async def authenticated_approval(
    request_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Authenticated approval decision — the product/UI path, alongside the HMAC
    deep-link (`/approve`).

    Why a second path: the deep-link is a bearer credential (anyone holding the
    signed URL can decide) and records the approver as the constant
    ``"approval-deeplink"`` — no human attribution. Here the caller's JWT is the
    credential, so the decision carries REAL attribution and the backend verifies
    the caller is the data owner before signalling Temporal.

    - Bearer JWT required (``_get_bearer_token`` → 401 on missing/invalid).
    - 403 unless the caller's ``sub`` == the request's designated approver (owner).
    - 404 if no open approval workflow; 409 if already decided.
    Body: ``{"decision": "approve"|"deny", "reason": "<optional>"}``.
    """
    # request_id is a server-generated uuid4; constrain it so it cannot be used
    # to inject into the Temporal workflow-id namespace.
    _validate_safe_id(request_id, "request_id")

    _, claims = await _get_bearer_token(authorization)
    # Compare the NAMESPACED principal (email|issuer-ns) — the form the owner is stored
    # as and the workflow records as approver_id — NOT the raw Keycloak `sub` (a UUID
    # that never matches, which would 403 the legitimate owner).
    try:
        approver_principal = principal(claims)
    except ValueError as exc:
        log.warning("authenticated_approval_principal_unbuildable", error=str(exc))
        raise HTTPException(
            status_code=401,
            detail="Token lacks a verified email required for authorization",
        )
    await _check_rate_limit(approver_principal)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")
    decision = body.get("decision")
    if decision not in ("approve", "deny"):
        raise HTTPException(status_code=400, detail="'decision' must be 'approve' or 'deny'")
    reason = str(body.get("reason", ""))[:500]

    temporal_client: TemporalClient = request.app.state.temporal_client
    handle = temporal_client.get_workflow_handle(f"approval-{request_id}")

    # Owner-verification: query the workflow for its designated approver. A
    # closed/absent workflow → 404; the caller must be that approver → else 403.
    try:
        info = await handle.query("get_info")
    except Exception as e:
        # Workflow gone (completed/terminated) but the inbox index still lists it — self-heal
        # by dropping the stale entry so the inbox converges instead of showing dead requests.
        log.warning("authenticated_approval_query_failed", error=str(e))
        import approval_index
        await approval_index.remove(approver_principal, request_id)
        raise HTTPException(status_code=404, detail="No open approval request found")
    if info.get("decided"):
        raise HTTPException(status_code=409, detail="This request has already been decided")
    if approver_principal != info.get("approver_id"):
        # M8: a non-owner attempting to decide an approval is an authorization-bypass attempt.
        log.warning("authenticated_approval_forbidden_not_owner", agt_audit=True)
        raise HTTPException(status_code=403, detail="Only the data owner may decide this request")

    try:
        await handle.signal(
            "approval_decision",
            ApprovalDecisionSignal(
                decision="approved" if decision == "approve" else "denied",
                reason=reason,
                approver_id=approver_principal,  # real attribution (vs the HMAC link's constant)
            ),
        )
    except Exception as e:
        # S-6: log full details internally, return a generic message to the caller.
        log.error("authenticated_approval_signal_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to record decision. Please try again.")

    # Drop it from the approver's inbox index now that it's decided.
    import approval_index
    await approval_index.remove(approver_principal, request_id)

    log.info("authenticated_approval_recorded", decision=decision, agt_audit=True)
    return JSONResponse(content={"status": "recorded"}, status_code=200)


# ── POST /access/revoke ───────────────────────────────────────────────────────

async def _chunks_for_doc(title: str) -> list[str]:
    """Resolve a document title to its chunk_ids in THIS division's Qdrant."""
    import httpx
    url = f"{str(settings.qdrant_url).rstrip('/')}/collections/{settings.qdrant_collection}/points/scroll"
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(url, json={"limit": 512, "with_payload": True, "with_vector": False})
        r.raise_for_status()
        out: list[str] = []
        for pt in r.json().get("result", {}).get("points", []):
            pl = pt.get("payload", {})
            t = pl.get("title") or (pl.get("metadata") or {}).get("title", "")
            cid = pl.get("chunk_id", "")
            if t == title and cid:
                out.append(cid)
        return out


@app.post("/access/revoke")
async def revoke_access(
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """M5 / FR-7.2: a data OWNER revokes a user's access to one of their documents.

    Removes the VIEWER grant and re-sets PENDING_APPROVAL, so the user has no standing
    access and a re-ask re-enters the approval flow — no stale reuse (D-6). The caller's
    JWT is the credential; the backend verifies the caller is the document's owner
    (OpenFGA `owner` relation) before revoking. Audited (agt_audit).

    Body: ``{"user_email": "...", "doc": "<title>", "home_division": "<id>"?}``.
    ``home_division`` (optional) namespaces the target principal to a peer division's
    issuer; default is this division (a local user).
    """
    _, claims = await _get_bearer_token(authorization)
    caller = principal(claims)
    await _check_rate_limit(caller)        # bound owner-mutation calls

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")
    target_email = str(body.get("user_email", "")).strip().lower()
    doc = str(body.get("doc", "")).strip()
    home_division = str(body.get("home_division", "")).strip()
    if not (target_email and doc):
        raise HTTPException(status_code=400, detail="'user_email' and 'doc' are required")

    # Target principal — namespaced by the target's HOME issuer (this division by
    # default; the configured peer's issuer for a federated cross-division user).
    if home_division and home_division != settings.division_id:
        home_iss = settings.peer_agent_issuer
        if not home_iss:
            raise HTTPException(status_code=400,
                                detail="cross-division revoke requires a federated peer issuer")
    else:
        home_iss = str(settings.oidc_issuer)
    target = f"{target_email}|{issuer_namespace(home_iss)}"

    chunk_ids = await _chunks_for_doc(doc)
    if not chunk_ids:
        raise HTTPException(status_code=404, detail=f"document '{doc}' not found in this division")

    auth = await agent_nodes._get_openfga()
    # IDOR guard: the caller must own EVERY chunk before we mutate ANY of them. Checking
    # only chunk[0] would let a cross-owner title collision revoke chunks the caller does
    # not own; verifying all-first also avoids a partial mutation on rejection.
    for cid in chunk_ids:
        if await auth.get_chunk_owner(cid) != caller:
            log.warning("access_revoke_forbidden_not_owner", doc=doc, chunk_id=cid, agt_audit=True)
            raise HTTPException(status_code=403,
                                detail="Only the data owner may revoke access to this document")

    for cid in chunk_ids:
        await auth.revoke_viewer(target, cid)
        await auth.set_pending_approval(target, cid)   # re-ask re-enters approval (D-6)
    log.info("access_revoked", target=target, doc=doc, chunks=len(chunk_ids),
             by=caller, agt_audit=True)
    return JSONResponse(content={"status": "revoked", "doc": doc, "chunks": len(chunk_ids)},
                        status_code=200)


# ── GET /audit ────────────────────────────────────────────────────────────────

@app.get("/audit")
async def get_audit(
    authorization: str | None = Header(default=None),
    event: str | None = Query(default=None, description="Optional exact event-name filter"),
    limit: int = Query(default=500, ge=1, le=10000,
                       description="Most-recent N entries to return (chain still fully verified)"),
) -> JSONResponse:
    """FR-8.1 / NFR-9: admin-queryable export of THIS division's tamper-evident audit trail.

    Read-only. Surfaces the per-division hash-chained log (previously CLI-only via
    scripts/verify_audit.py) as an admin API, with a chain-verification status so the
    export itself carries tamper-evidence.

    Authn/authz: a valid user JWT (validate_token) AND the division-admin role — the same
    token-validation dependency the data path uses, gated by _require_admin. Non-admin → 403.

    Division-scoped (NFR-2): only ``settings.division_id``'s own chains are read, so an admin
    can never export another division's trail. Optional ?event= filter and ?limit= slice
    (the slice is the most-recent N; verification always covers the full chain).
    """
    caller, _ = await _require_admin(authorization)
    await _check_rate_limit(caller)

    import audit_log
    try:
        result = audit_log.read_division_chain(
            settings.division_id,
            base_dir=settings.audit_log_dir,
            event=event,
            limit=limit,
        )
    except Exception as exc:
        log.error("audit_export_failed", error=str(exc))
        raise HTTPException(status_code=503, detail="Could not read audit trail")

    log.info("audit_exported", division=settings.division_id, count=result.get("count"),
             verified=result.get("verified"), agt_audit=True)
    return JSONResponse(content=result, status_code=200)


# ── Artifact storage (durable evidence packs / exports) ───────────────────────
# These wire the artifact store (artifact_store.py) into a real GOVERNED flow: an admin exports
# this division's tamper-evident audit trail as a durable, retrievable compliance evidence pack.
# Admin-only and division-scoped (the store namespaces keys by division_id), so an admin can
# neither read another division's artifacts nor export another division's trail.

@app.post("/admin/audit/export-pack")
async def export_audit_pack(
    authorization: str | None = Header(default=None),
    event: str | None = Query(default=None, description="Optional exact event-name filter"),
    limit: int = Query(default=10000, ge=1, le=100000),
) -> JSONResponse:
    """Export THIS division's audit trail to durable artifact storage as an evidence pack and
    return its ArtifactRef (the pack carries the chain-verification status, so it's tamper-
    evident on its own). Admin-only, division-scoped. Answers SC-11 ("who accessed X, who
    approved it") as a shareable, durable artifact."""
    caller, _ = await _require_admin(authorization)
    await _check_rate_limit(caller)
    import json as _json

    import artifact_store
    import audit_log
    try:
        chain = audit_log.read_division_chain(
            settings.division_id, base_dir=settings.audit_log_dir, event=event, limit=limit)
    except Exception as exc:
        log.error("audit_export_failed", error=str(exc))
        raise HTTPException(status_code=503, detail="Could not read audit trail")
    pack = {
        "division": settings.division_id,
        "exported_by": caller,
        "exported_at": int(time.time()),
        "verified": chain.get("verified"),
        "count": chain.get("count"),
        "audit": chain,
    }
    data = _json.dumps(pack, indent=2, default=str).encode("utf-8")
    name = f"evidence-packs/audit-{int(time.time())}.json"
    ref = await artifact_store.put_artifact(
        name, data, content_type="application/json",
        metadata={"kind": "audit-evidence-pack", "exported_by": caller})
    log.info("audit_pack_exported", key=ref.key, count=chain.get("count"), agt_audit=True)
    return JSONResponse(content={"artifact": artifact_store.ref_to_dict(ref)}, status_code=201)


@app.get("/admin/artifacts")
async def list_artifacts_endpoint(
    authorization: str | None = Header(default=None),
    prefix: str = Query(default=""),
) -> JSONResponse:
    """List THIS division's stored artifacts (names, division-scoped). Admin-only."""
    await _require_admin(authorization)
    import artifact_store
    names = await artifact_store.list_artifacts(prefix)
    return JSONResponse(content={"division": settings.division_id, "artifacts": names},
                        status_code=200)


@app.get("/admin/artifacts/{name:path}")
async def get_artifact_endpoint(
    name: str,
    authorization: str | None = Header(default=None),
) -> Response:
    """Retrieve a stored artifact by name (division-scoped). Admin-only."""
    await _require_admin(authorization)
    import artifact_store
    try:
        data = await artifact_store.get_artifact(name)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid artifact name")
    except Exception:
        raise HTTPException(status_code=404, detail="artifact not found")
    return Response(content=data, media_type="application/octet-stream")


# ── POST /admin/kill-switch ───────────────────────────────────────────────────

@app.post("/admin/kill-switch")
async def admin_kill_switch(
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """FR-4.3: engage/disengage the RUNTIME kill-switch for this division — no restart.

    Sets/clears the per-division Redis flag (agt:killswitch:<division_id>) that /query
    consults live. The deploy-time settings flag remains an always-on override: when it is
    set, the path stays halted regardless of what this endpoint does (and the response
    reports that effective state).

    Authn/authz: valid JWT AND the division-admin role (_require_admin). Non-admin → 403.
    Body: ``{"engaged": true|false}``. Audited.
    """
    caller, _ = await _require_admin(authorization)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")
    engaged = body.get("engaged")
    if not isinstance(engaged, bool):
        raise HTTPException(status_code=400, detail="'engaged' must be a boolean")

    try:
        await _set_runtime_kill_switch(engaged)
    except Exception as exc:
        log.error("kill_switch_set_failed", error=str(exc))
        raise HTTPException(status_code=503, detail="Could not update kill-switch")

    # Effective state = runtime flag OR the deploy-time settings override.
    effective = engaged or settings.agent_kill_switch_engaged
    log.warning("kill_switch_set", engaged=engaged, by=caller,
                division_id=settings.division_id, agt_audit=True)
    return JSONResponse(
        content={
            "division_id": settings.division_id,
            "runtime_engaged": engaged,
            "settings_override": settings.agent_kill_switch_engaged,
            "effective_engaged": effective,
        },
        status_code=200,
    )


# ── Division-admin user lifecycle (FR-2.2) ────────────────────────────────────
# POST /admin/users, PUT /admin/users/{username}/roles, POST /admin/users/{username}/disable,
# POST /admin/users/{username}/enable.
#
# Scope = THIS division only, by construction (NFR-2): the caller must present a token
# validated against THIS division's issuer + audience + JWKS (_require_admin) — a foreign
# division's token never gets past validate_token — and every Keycloak call targets the realm
# derived from THIS division's own OIDC config, authenticated as THIS division's agent service
# account (realm-management manage/view/query-users in its own realm only). There is no
# division parameter to tamper with. OpenFGA writes land in this division's own store.
#
# Role model: a division realm role R (member | data-owner | division-admin) in Keycloak is
# mirrored 1:1 as the OpenFGA tuple `user:<principal> member group:role-R`, written/removed
# in the same call, so the token's role and the ReBAC graph agree.

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@\-]{0,127}$")


def _kc_http_client() -> Any:
    """HTTP client for the Keycloak admin API (patched to an httpx.MockTransport in tests)."""
    import httpx
    return httpx.AsyncClient(timeout=15)


@asynccontextmanager
async def _kc_admin() -> AsyncIterator[tuple[Any, str, str, dict[str, str]]]:
    """Yield (client, keycloak_base, realm, admin_headers) for THIS division's realm.

    The realm is derived from the JWKS URI (reachable from the agent even where the
    browser-facing issuer host is not, e.g. k8s). Auth: client-credentials as the agent's
    own service account — the same agent_client_id/secret the division already holds."""
    from auth import keycloak_admin as ka
    kc, realm = ka.split_realm_url(str(settings.oidc_jwks_uri))
    async with _kc_http_client() as c:
        h = await ka.service_account_headers(c, kc, realm, settings.agent_client_id,
                                             settings.agent_client_secret)
        yield c, kc, realm, h


def _user_principal(username: str, email: str) -> str:
    """The OpenFGA principal a token for this user will resolve to (== principal(claims)):
    `<subject>|<issuer-ns>` with this division's issuer."""
    claim = settings.principal_claim
    if claim == "email":
        subject = email
    elif claim == "preferred_username":
        subject = username
    else:
        raise HTTPException(status_code=501,
                            detail=f"user lifecycle API does not support PRINCIPAL_CLAIM={claim}")
    if not subject:
        raise HTTPException(status_code=409, detail="user has no subject claim value")
    return f"{subject.strip().lower()}|{issuer_namespace(str(settings.oidc_issuer))}"


def _validate_username(username: str) -> str:
    if not _USERNAME_RE.match(username or ""):
        raise HTTPException(status_code=400, detail="Invalid username")
    return username


def _validate_roles(raw: Any) -> list[str]:
    from auth.keycloak_admin import DIVISION_ROLES
    if not isinstance(raw, list) or not all(isinstance(r, str) for r in raw):
        raise HTTPException(status_code=400, detail="'roles' must be a list of strings")
    bad = sorted(set(raw) - set(DIVISION_ROLES))
    if bad:
        raise HTTPException(status_code=400,
                            detail=f"unknown role(s) {bad}; allowed: {list(DIVISION_ROLES)}")
    return sorted(set(raw))


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="Request body must be a JSON object")
    return body


def _idp_unavailable(op: str, exc: Exception) -> HTTPException:
    # Never echo IdP response bodies (may carry internal detail) — log the class + status.
    log.error("admin_idp_call_failed", action=op, error=type(exc).__name__,
              detail=str(exc)[:200])
    return HTTPException(status_code=503, detail="Identity provider admin API unavailable")


@app.post("/admin/users")
async def admin_provision_user(
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """FR-2.2: provision a user in THIS division (Keycloak user + realm roles + OpenFGA
    role mirror). Admin-only. Audited.

    Body: ``{"username", "email", "roles": [..] (default ["member"]), "first_name"?,
    "last_name"?, "password"?, "temporary"? (default true)}``. Without ``password`` the user
    must set one via Keycloak's UPDATE_PASSWORD action. 409 if the username exists."""
    caller, _ = await _require_admin(authorization)
    await _check_rate_limit(caller)
    body = await _json_body(request)
    username = _validate_username(str(body.get("username", "")).strip())
    email = str(body.get("email", "")).strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+$", email):
        raise HTTPException(status_code=400, detail="Invalid email")
    roles = _validate_roles(body.get("roles", ["member"]))
    password = body.get("password")
    if password is not None and (not isinstance(password, str) or len(password) < 8):
        raise HTTPException(status_code=400, detail="'password' must be a string of >= 8 chars")
    temporary = body.get("temporary", True)
    if not isinstance(temporary, bool):
        raise HTTPException(status_code=400, detail="'temporary' must be a boolean")
    target = _user_principal(username, email)

    from auth import keycloak_admin as ka
    try:
        async with _kc_admin() as (c, kc, realm, h):
            created = await ka.create_user(
                c, kc, realm, h, username=username, email=email,
                first_name=str(body.get("first_name", ""))[:100],
                last_name=str(body.get("last_name", ""))[:100],
                password=password, temporary=temporary)
            if not created:
                raise HTTPException(status_code=409, detail="User already exists")
            u = await ka.find_user(c, kc, realm, h, username)
            if not u:
                raise ka.KeycloakAdminError("find_user_after_create", 404)
            await ka.add_realm_roles(c, kc, realm, h, u["id"], roles)
    except HTTPException:
        raise
    except Exception as exc:
        raise _idp_unavailable("provision", exc)

    try:
        fga = await agent_nodes._get_openfga()
        for role in roles:
            await fga.add_role_membership(target, role)
    except Exception as exc:
        log.error("admin_user_provision_incomplete", user_id=target, subject=caller,
                  action="provision", roles=roles, error=type(exc).__name__, agt_audit=True)
        raise HTTPException(status_code=503,
                            detail="User created in the IdP but the role mirror failed; "
                                   "retry PUT /admin/users/{username}/roles")

    log.info("admin_user_provisioned", user_id=target, subject=caller, action="provision",
             roles=roles, division_id=settings.division_id, agt_audit=True)
    return JSONResponse(status_code=201, content={
        "division_id": settings.division_id, "username": username, "principal": target,
        "keycloak_id": u["id"], "roles": roles, "enabled": True})


@app.put("/admin/users/{username}/roles")
async def admin_set_user_roles(
    username: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """FR-2.2: set a user's division roles to EXACTLY ``{"roles": [...]}`` (subset of
    member | data-owner | division-admin; other realm roles are untouched). Keycloak role
    mappings and the OpenFGA role mirror are converged in the same call. Admin-only, audited.
    409 for a disabled user, or an admin removing their OWN division-admin role (lockout)."""
    caller, _ = await _require_admin(authorization)
    await _check_rate_limit(caller)
    _validate_username(username)
    body = await _json_body(request)
    want = _validate_roles(body.get("roles"))

    from auth import keycloak_admin as ka
    try:
        async with _kc_admin() as (c, kc, realm, h):
            u = await ka.find_user(c, kc, realm, h, username)
            if not u:
                raise HTTPException(status_code=404, detail="User not found in this division")
            if not u.get("enabled", True):
                raise HTTPException(status_code=409, detail="User is disabled")
            target = _user_principal(username, str(u.get("email", "")))
            if target == caller and "division-admin" not in want:
                raise HTTPException(status_code=409,
                                    detail="An admin cannot remove their own division-admin role")
            current = set(await ka.get_realm_roles(c, kc, realm, h, u["id"])) & set(ka.DIVISION_ROLES)
            added = await ka.add_realm_roles(c, kc, realm, h, u["id"], sorted(set(want) - current))
            removed = await ka.remove_realm_roles(c, kc, realm, h, u["id"], sorted(current - set(want)))
    except HTTPException:
        raise
    except Exception as exc:
        raise _idp_unavailable("set_roles", exc)

    try:
        fga = await agent_nodes._get_openfga()
        # Converge the mirror to `want` (re-asserting is idempotent; heals any prior drift).
        for role in want:
            await fga.add_role_membership(target, role)
        for role in sorted(set(ka.DIVISION_ROLES) - set(want)):
            await fga.remove_role_membership(target, role)
    except Exception as exc:
        log.error("admin_user_roles_incomplete", user_id=target, subject=caller,
                  action="set_roles", roles=want, error=type(exc).__name__, agt_audit=True)
        raise HTTPException(status_code=503,
                            detail="IdP roles updated but the role mirror failed; retry")

    log.info("admin_user_roles_set", user_id=target, subject=caller, action="set_roles",
             roles=want, cascade={"added": added, "removed": removed},
             division_id=settings.division_id, agt_audit=True)
    return JSONResponse(status_code=200, content={
        "division_id": settings.division_id, "username": username, "principal": target,
        "roles": want, "added": added, "removed": removed})


@app.post("/admin/users/{username}/disable")
async def admin_disable_user(
    username: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """FR-2.2: disable a user in THIS division, cascading so data access stops NOW.

    Cascade (each step reported; the whole call is idempotent — re-run to finish a partial):
      1. denylist   — the agent refuses the user's still-valid access tokens on the next
                      request (401), independent of token expiry;
      2. keycloak   — user disabled + ALL sessions revoked (no new tokens, refresh dies);
      3. openfga    — viewer/editor/pending_approval chunk tuples + role-group memberships
                      deleted; ``owner`` tuples RETAINED (documents are not orphaned; the
                      count is reported so the admin can reassign ownership);
      4. approvals  — requests the user MADE are auto-DENIED in Temporal (attributed to the
                      admin) and dropped from approvers' inboxes; requests AWAITING the user
                      as approver are left pending (counted) — they fail closed at timeout
                      unless ownership is reassigned, never auto-approved;
      5. inbox      — the user's outcome inbox + badge are purged (records carry no answer
                      text; the decisions remain in the audit chain).
    200 when every step succeeded, 502 with the per-step report otherwise. Admin-only;
    audited. 409 if an admin tries to disable themselves."""
    caller, _ = await _require_admin(authorization)
    await _check_rate_limit(caller)
    _validate_username(username)

    from auth import keycloak_admin as ka
    steps: dict[str, Any] = {}
    try:
        async with _kc_admin() as (c, kc, realm, h):
            u = await ka.find_user(c, kc, realm, h, username)
            if not u:
                raise HTTPException(status_code=404, detail="User not found in this division")
            target = _user_principal(username, str(u.get("email", "")))
            if target == caller:
                raise HTTPException(status_code=409, detail="An admin cannot disable themselves")
            # 1. denylist first: the cheapest step and the one that bites immediately.
            try:
                await _mark_account_disabled(u["id"])
                steps["denylist"] = "ok"
            except Exception as exc:
                steps["denylist"] = f"failed:{type(exc).__name__}"
            # 2. Keycloak: disable + revoke sessions.
            try:
                await ka.set_enabled(c, kc, realm, h, u["id"], False)
                await ka.logout_user(c, kc, realm, h, u["id"])
                steps["keycloak"] = "ok"
            except Exception as exc:
                steps["keycloak"] = f"failed:{type(exc).__name__}"
    except HTTPException:
        raise
    except Exception as exc:
        raise _idp_unavailable("disable", exc)

    # 3. OpenFGA: neutralise access-conferring tuples.
    try:
        fga = await agent_nodes._get_openfga()
        steps["openfga"] = await fga.neutralise_user(target)
    except Exception as exc:
        steps["openfga"] = f"failed:{type(exc).__name__}"

    # 4. Pending approvals.
    import approval_index
    try:
        mine = await approval_index.by_requester(target)
        tc = getattr(request.app.state, "temporal_client", None)
        denied = 0
        for approver, rid in mine:
            if tc is not None:
                try:
                    await tc.get_workflow_handle(f"approval-{rid}").signal(
                        "approval_decision",
                        ApprovalDecisionSignal(decision="denied",
                                               reason="requester account disabled by division admin",
                                               approver_id=caller))
                    denied += 1
                except Exception as exc:   # workflow already closed → just drop the entry
                    log.warning("disable_cascade_signal_failed", request_id=rid,
                                error=type(exc).__name__)
            await approval_index.remove(approver, rid)
        steps["approvals"] = {"requested_withdrawn": len(mine), "denied_in_workflow": denied,
                              "pending_as_approver": await approval_index.count_for(target)}
    except Exception as exc:
        steps["approvals"] = f"failed:{type(exc).__name__}"

    # 5. Outcome inbox.
    import outcome_store
    try:
        steps["inbox"] = {"purged": await outcome_store.purge(target)}
    except Exception as exc:
        steps["inbox"] = f"failed:{type(exc).__name__}"

    ok = not any(isinstance(v, str) and v.startswith("failed") for v in steps.values())
    log.warning("admin_user_disabled" if ok else "admin_user_disable_incomplete",
                user_id=target, subject=caller, action="disable", cascade=steps,
                division_id=settings.division_id, agt_audit=True)
    return JSONResponse(status_code=200 if ok else 502, content={
        "division_id": settings.division_id, "username": username, "principal": target,
        "enabled": False, "complete": ok, "cascade": steps})


@app.post("/admin/users/{username}/enable")
async def admin_enable_user(
    username: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """FR-2.2: re-enable a previously disabled user in THIS division (inverse of /disable).

    Steps (each reported; idempotent — re-run to finish a partial):
      1. keycloak — user enabled (sessions were revoked by the disable; the user logs in
                    afresh). The user's CURRENT division realm roles are read back;
      2. openfga  — role-group memberships rebuilt from those Keycloak roles (Keycloak is the
                    single source of truth; division roles the user no longer holds are
                    removed). Chunk ``viewer`` / ``editor`` / ``pending_approval`` tuples the
                    disable deleted are deliberately NOT restored, and approval requests it
                    auto-denied are not revived: re-enabling restores the ROLE, not past
                    grants — any data access must be re-requested through the approval flow.
                    ``owner`` tuples were retained by the disable and are untouched;
      3. denylist — the agent stops refusing the user's tokens. Cleared LAST and only once
                    Keycloak reports the user enabled, so a failed IdP step never re-admits
                    tokens for an account the IdP still holds disabled.
    200 when every step succeeded, 502 with the per-step report otherwise. Admin-only;
    audited. 409 if an admin targets themselves (mirrors /disable's self-guard)."""
    caller, _ = await _require_admin(authorization)
    await _check_rate_limit(caller)
    _validate_username(username)

    from auth import keycloak_admin as ka
    steps: dict[str, Any] = {}
    roles: list[str] | None = None
    try:
        async with _kc_admin() as (c, kc, realm, h):
            u = await ka.find_user(c, kc, realm, h, username)
            if not u:
                raise HTTPException(status_code=404, detail="User not found in this division")
            target = _user_principal(username, str(u.get("email", "")))
            if target == caller:
                raise HTTPException(status_code=409, detail="An admin cannot enable themselves")
            was_enabled = bool(u.get("enabled", True))
            # 1. Keycloak: enable + read the authoritative division roles.
            try:
                await ka.set_enabled(c, kc, realm, h, u["id"], True)
                roles = sorted(set(await ka.get_realm_roles(c, kc, realm, h, u["id"]))
                               & set(ka.DIVISION_ROLES))
                steps["keycloak"] = "ok"
            except Exception as exc:
                steps["keycloak"] = f"failed:{type(exc).__name__}"
    except HTTPException:
        raise
    except Exception as exc:
        raise _idp_unavailable("enable", exc)

    # 2. OpenFGA: converge the role mirror to the CURRENT Keycloak roles (never past grants).
    if roles is None:
        steps["openfga"] = "skipped:keycloak_failed"
    else:
        try:
            fga = await agent_nodes._get_openfga()
            for role in roles:
                await fga.add_role_membership(target, role)
            for role in sorted(set(ka.DIVISION_ROLES) - set(roles)):
                await fga.remove_role_membership(target, role)
            steps["openfga"] = {"roles_restored": roles}
        except Exception as exc:
            steps["openfga"] = f"failed:{type(exc).__name__}"

    # 3. Denylist: re-admit tokens only once the IdP agrees the account is enabled.
    if steps["keycloak"] != "ok":
        steps["denylist"] = "skipped:keycloak_failed"
    else:
        try:
            await _clear_account_disabled(u["id"])
            steps["denylist"] = "ok"
        except Exception as exc:
            steps["denylist"] = f"failed:{type(exc).__name__}"

    ok = not any(isinstance(v, str) and v.startswith(("failed", "skipped"))
                 for v in steps.values())
    emit = log.info if ok else log.warning
    emit("admin_user_enabled" if ok else "admin_user_enable_incomplete",
         user_id=target, subject=caller, action="enable", cascade=steps, roles=roles,
         division_id=settings.division_id, agt_audit=True)
    return JSONResponse(status_code=200 if ok else 502, content={
        "division_id": settings.division_id, "username": username, "principal": target,
        "enabled": steps["keycloak"] == "ok", "was_enabled": was_enabled, "complete": ok,
        "roles": roles, "cascade": steps})


# ── Exception handlers ────────────────────────────────────────────────────────

@app.exception_handler(PermissionError)
async def permission_error_handler(request: Request, exc: PermissionError) -> JSONResponse:
    """AGT policy denial → 403."""
    log.warning("agt_policy_denial", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=403, content={"detail": "Request denied by governance policy"})


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all — never leak internal details."""
    log.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ── Entry point ───────────────────────────────────────────────────────────────

def run() -> None:
    # M7: serve mutual TLS when require_mtls is set (client cert REQUIRED). Empty dict
    # in the default localhost-demo posture (plain HTTP). Fails loud if enabled without certs.
    # When a CRL is configured the serving context enforces revocation (NFR-3): a revoked
    # client cert is rejected at the handshake (ssl_context_factory → CRL-checking context).
    from transport.mtls import crl_path_for, tls_serving_kwargs
    ssl_kwargs = tls_serving_kwargs(settings)
    if ssl_kwargs:
        from transport.ocsp import ocsp_mode_for
        crl = crl_path_for(settings)
        log.info("serving_mtls", cert=settings.tls_cert_file, client_cert="required",
                 crl_revocation="enforced" if crl else "none", crl_file=crl or None,
                 ocsp_mode=ocsp_mode_for(settings))
    uvicorn.run(
        "api.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=False,
        **ssl_kwargs,
    )


if __name__ == "__main__":
    run()
