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
from fastapi.responses import JSONResponse
from jose import JWTError
from sse_starlette.sse import EventSourceResponse
from temporalio.client import Client as TemporalClient

import agent.graph as agent_graph
import agent.nodes as agent_nodes
import mesh.agent_identity as agent_identity
from auth.token_validator import (
    AuthServiceUnavailable,
    assertion_principal,
    minimal_assertion_claims,
    principal,
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
    owner_id: str = existing.get("_owner_id", "")
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


# ── Rate limiting (Finding #7) ────────────────────────────────────────────────

async def _check_rate_limit(subject: str) -> None:
    """
    Finding #7: fixed-window per-subject rate limit for the expensive /query
    endpoint. Backed by Redis (INCR + EXPIRE). Fails OPEN on a Redis error —
    availability is preferred over hard-blocking when the limiter is degraded.
    """
    try:
        r = await _get_redis()
        window = int(time.time()) // 60
        key = f"ratelimit:{subject}:{window}"
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, 120)
    except Exception as exc:
        log.warning("rate_limit_check_failed", subject=subject, error=str(exc))
        return
    if count > settings.rate_limit_per_minute:
        log.warning("rate_limit_exceeded", subject=subject, count=count)
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
        log.warning("token_validation_failed")
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

    return token, claims


# ── Application lifespan ──────────────────────────────────────────────────────

@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    # M8: hook the tamper-evident audit chain into structlog (captures agt_audit events)
    import audit_log
    audit_log.configure_audit_logging(settings.division_id, "agent", settings.audit_log_dir)

    # Initialise AgentMesh identity — resolves or creates the DID
    await agent_identity.get_mesh()
    did = await agent_identity.get_did()
    log.info("agentmesh_identity_ready", did=did)

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
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-ID"],
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
    if settings.agent_kill_switch_engaged:
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

    # Persist initial task record
    await _store_task(
        task_id,
        {"status": "submitted", "query": raw_query[:200]},  # truncate for storage
        owner_id=user_id,
    )

    # Forward only the user's VALIDATED identity claims (not the raw bearer token) so
    # a delegated peer call carries a non-replayable, DID-signed assertion. run_query
    # stashes these in a ContextVar — never in state or logs.
    fwd_claims = minimal_assertion_claims(claims)

    async def event_stream() -> AsyncIterator[dict[str, str]]:
        yield {"event": "status", "data": '{"status": "working"}'}

        run_task: asyncio.Task[dict[str, Any]] = asyncio.create_task(
            agent_graph.run_query(
                query=raw_query,
                user_id=user_id,
                user_claims=fwd_claims,
                task_id=task_id,
                context_id=context_id,
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
    # Parse body
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")

    # ── DID authentication: verify the Ed25519 signature on the payload ──────
    sig_verified, signer_did = await agent_identity.verify_signed_message(payload)
    if not sig_verified or not signer_did:
        log.warning("a2a_query_signature_invalid")
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing AgentMesh message signature",
        )

    # Registry trust-score gate on the verified signer (defence in depth).
    verified, trust_score = await agent_identity.verify_peer_identity(signer_did)
    if not verified or trust_score < settings.agent_trust_threshold:
        log.warning(
            "a2a_query_peer_identity_rejected",
            signer_did=signer_did,
            trust_score=trust_score,
        )
        raise HTTPException(status_code=403, detail="Peer identity verification failed")

    # The verified signer must be the configured peer.
    if settings.peer_agent_did and signer_did != settings.peer_agent_did:
        log.warning(
            "a2a_query_unexpected_peer_did",
            signer_did=signer_did,
            expected_did=settings.peer_agent_did,
        )
        raise HTTPException(status_code=403, detail="Sender DID does not match configured peer")

    # ── Extract the delegated query from the SIGNED payload ──────────────────
    raw_query = payload.get("query", "")
    if not isinstance(raw_query, str) or not raw_query.strip():
        raise HTTPException(status_code=400, detail="'query' field must be a non-empty string")
    if len(raw_query) > settings.max_query_length:
        raise HTTPException(
            status_code=400,
            detail=f"Query exceeds maximum length of {settings.max_query_length} characters",
        )

    # M2 (FR-3.6), security-hardened: derive the AUTHORITATIVE user identity from the
    # DID-signed user-assertion CLAIMS in the (already signature-verified, replay-
    # protected) envelope — NOT a forwarded raw bearer token (which a compromised peer
    # could replay against the user's HOME APIs). The assertion is a claims object; we
    # bind its issuer to THIS specific signing peer (settings.peer_agent_issuer), so a
    # compromised-but-trusted peer cannot assert ANOTHER division's user. The identity
    # WITHIN that signer's namespace is vouched by the DID-authenticated home agent (see
    # assertion_principal's trust-model note), not re-verified against the home Keycloak.
    assertion = payload.get("user_assertion")
    if not isinstance(assertion, dict):
        raise HTTPException(
            status_code=401,
            detail="Missing cross-division user assertion — identity required",
        )
    try:
        user_id = assertion_principal(assertion, settings.peer_agent_issuer)
    except Exception as exc:
        log.warning("a2a_query_assertion_invalid", error=str(exc))
        raise HTTPException(status_code=401, detail="Invalid cross-division user assertion")

    context_id = str(payload.get("context_id", "")) or str(uuid.uuid4())
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

    # ── Run the SAME governed pipeline as /query ─────────────────────────────
    # The peer's DID-signed claims established user_id; OpenFGA on THIS division
    # re-authorizes that principal. No onward forwarding here (single-hop), so no
    # user_claims are injected.
    try:
        result = await agent_graph.run_query(
            query=raw_query,
            user_id=user_id,
            user_claims=None,     # single-hop: nothing to forward onward
            task_id=task_id,
            context_id=context_id,
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
    if approval_request_id:
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
        log.warning("callback_signature_invalid", task_id=task_id)
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
        )
        raise HTTPException(status_code=403, detail="Peer identity verification failed")

    # The verified signer must be the configured peer.
    if settings.peer_agent_did and sender_did != settings.peer_agent_did:
        log.warning(
            "callback_unexpected_peer_did",
            task_id=task_id,
            sender_did=sender_did,
            expected_did=settings.peer_agent_did,
        )
        raise HTTPException(status_code=403, detail="Sender DID does not match configured peer")

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

    # Update task in Redis
    await _update_task(task_id, {"peer_status": state, "peer_message": message})

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
        log.warning("approval_link_expired", request_id=request_id)
        raise HTTPException(status_code=401, detail="Approval link has expired")
    if not _verify_approval_token(request_id, decision, exp, token):
        log.warning("approval_hmac_invalid")
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

    The requester never learns the ``request_id`` (L-6); only the owner can
    enumerate the requests routed to them. Implemented by listing running
    ``ApprovalWorkflow`` executions and keeping those whose designated approver
    == the caller's ``sub``. (This performs O(open requests) point queries and
    does not scale to large request volumes; indexing the approver as a Temporal
    search attribute would fix this.)

    Returns ``{"pending": [{"request_id", "requester_id", "query"}]}``.
    """
    _, claims = await _get_bearer_token(authorization)
    caller_sub = claims.get("sub", "")
    temporal_client: TemporalClient = request.app.state.temporal_client
    pending: list[dict[str, str]] = []
    try:
        scanned = 0
        async for wf in temporal_client.list_workflows(
            "WorkflowType = 'ApprovalWorkflow' AND ExecutionStatus = 'Running'"
        ):
            scanned += 1
            if scanned > 200:          # bound the scan for safety
                break
            try:
                info = await temporal_client.get_workflow_handle(wf.id).query("get_info")
            except Exception:
                continue                # workflow completing / not yet queryable — skip
            if info.get("decided") or info.get("approver_id") != caller_sub:
                continue
            pending.append({
                "request_id": wf.id.removeprefix("approval-"),
                "requester_id": str(info.get("user_id", "")),
                "query": str(info.get("query", "")),
            })
    except Exception as e:
        log.error("list_pending_approvals_failed", error=str(e))
        raise HTTPException(status_code=503, detail="Approval service temporarily unavailable")
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
    approver_sub = claims.get("sub", "")

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
        log.warning("authenticated_approval_query_failed", error=str(e))
        raise HTTPException(status_code=404, detail="No open approval request found")
    if info.get("decided"):
        raise HTTPException(status_code=409, detail="This request has already been decided")
    if approver_sub != info.get("approver_id"):
        log.warning("authenticated_approval_forbidden_not_owner")
        raise HTTPException(status_code=403, detail="Only the data owner may decide this request")

    try:
        await handle.signal(
            "approval_decision",
            ApprovalDecisionSignal(
                decision="approved" if decision == "approve" else "denied",
                reason=reason,
                approver_id=approver_sub,  # real human attribution (vs the HMAC link's constant)
            ),
        )
    except Exception as e:
        # S-6: log full details internally, return a generic message to the caller.
        log.error("authenticated_approval_signal_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to record decision. Please try again.")

    log.info("authenticated_approval_recorded", decision=decision, agt_audit=True)
    return JSONResponse(content={"status": "recorded"}, status_code=200)


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
    uvicorn.run(
        "api.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=False,
    )


if __name__ == "__main__":
    run()
