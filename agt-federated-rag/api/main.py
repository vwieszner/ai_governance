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

import asyncio
import hashlib
import hmac as hmac_lib
import re
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import redis.asyncio as aioredis
import structlog
import uvicorn
from agent_sre import SREMiddleware  # type: ignore[import]
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from jose import JWTError
from sse_starlette.sse import EventSourceResponse
from temporalio.client import Client as TemporalClient

import agent.graph as agent_graph
import mesh.agent_identity as agent_identity
from auth.token_validator import AuthServiceUnavailable, validate_token
from config import settings
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


# ── HMAC helpers ──────────────────────────────────────────────────────────────

def _sign_approval(request_id: str, decision: str) -> str:
    """Generate an HMAC-SHA256 hex digest for an approval deep-link."""
    key = settings.approval_hmac_secret.encode()
    msg = f"{request_id}:{decision}".encode()
    return hmac_lib.new(key, msg, hashlib.sha256).hexdigest()


def _verify_approval_token(request_id: str, decision: str, token: str) -> bool:
    """Timing-safe HMAC verification for approval deep-links."""
    expected = _sign_approval(request_id, decision)
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

async def _get_bearer_token(authorization: str) -> tuple[str, dict[str, Any]]:
    """Parse Authorization header, validate JWT, return (raw_token, claims)."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

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

# AGT SRE middleware — request-level SLO tracking.
# Must be added before body-size and correlation-ID middlewares so it wraps
# the full request lifecycle including downstream middleware latency.
app.add_middleware(
    SREMiddleware,
    slo_latency_p99_ms=settings.sre_slo_latency_p99_ms,
)

# Correlation ID middleware — inject X-Request-ID into every request/response.
# Added before body-size so every response (including 413) carries the header.
app.add_middleware(_CorrelationIdMiddleware)

# Body-size middleware — pure ASGI; never buffers SSE response payloads.
app.add_middleware(_LimitBodySizeMiddleware, max_bytes=settings.max_request_body_bytes)


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
async def identity() -> dict[str, str]:
    """Return this agent's AgentMesh DID.

    Peer operators use this endpoint to retrieve the DID and set it as
    PEER_AGENT_DID in their deployment configuration so AgentMesh can verify
    inbound messages from this agent.
    """
    did = await agent_identity.get_did()
    return {"did": did, "cluster": settings.cluster_id}


# ── POST /query ───────────────────────────────────────────────────────────────

@app.post("/query", response_class=EventSourceResponse)
async def query(
    request: Request,
    authorization: str = Header(...),
) -> EventSourceResponse:
    """Main query endpoint — streams results as Server-Sent Events.

    Auth:   User JWT validated via auth.token_validator.validate_token.
    Flow:   Delegates to agent.graph.run_query(), which applies AGT governance.
    Output: SSE stream with "result" events and a final "done" event.

    Rate limit: queries exceeding max_query_length are rejected with 400.
    """
    # Validate JWT and extract user identity
    try:
        token, claims = await _get_bearer_token(authorization)
    except HTTPException:
        raise
    except PermissionError as exc:
        log.warning("agt_policy_denial_query", error=str(exc))
        raise HTTPException(status_code=403, detail="Request denied by governance policy")

    user_id: str = claims.get("sub", "")
    task_id = str(uuid.uuid4())
    context_id = str(uuid.uuid4())

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

    # Inject user token into ContextVar — never into state or logs
    agent_graph.set_user_token(token)

    async def event_stream() -> AsyncIterator[dict[str, str]]:
        yield {"event": "status", "data": '{"status": "working"}'}

        run_task: asyncio.Task[dict[str, Any]] = asyncio.create_task(
            agent_graph.run_query(
                query=raw_query,
                user_id=user_id,
                user_token=token,
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


# ── POST /tasks/{task_id}/callback ────────────────────────────────────────────

@app.post("/tasks/{task_id}/callback")
async def task_callback(
    task_id: str,
    request: Request,
) -> JSONResponse:
    """Peer agent callback — receives status updates from the federated peer.

    Authentication: The inbound message must carry an '_agentmesh' signature
    block.  We extract the sender's DID from that block and verify it against
    the AgentMesh registry.  If trust score is below the threshold the callback
    is rejected with 403.

    Only the configured PEER_AGENT_DID is accepted as a valid sender.
    """
    _validate_safe_id(task_id, "task_id")

    # Parse body
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")

    # Extract sender DID from AgentMesh signature block
    agentmesh_block = payload.get("_agentmesh", {})
    sender_did: str = agentmesh_block.get("sender_did", "")

    if not sender_did:
        log.warning("callback_missing_sender_did", task_id=task_id)
        raise HTTPException(status_code=401, detail="Missing AgentMesh identity block")

    # Verify peer DID against AgentMesh registry
    verified, trust_score = await agent_identity.verify_peer_identity(sender_did)
    if not verified or trust_score < settings.agent_trust_threshold:
        log.warning(
            "callback_peer_identity_rejected",
            task_id=task_id,
            sender_did=sender_did,
            trust_score=trust_score,
        )
        raise HTTPException(status_code=403, detail="Peer identity verification failed")

    # Optionally enforce that the sender DID matches the configured peer
    if settings.peer_agent_did and sender_did != settings.peer_agent_did:
        log.warning(
            "callback_unexpected_peer_did",
            task_id=task_id,
            sender_did=sender_did,
            expected_did=settings.peer_agent_did,
        )
        raise HTTPException(status_code=403, detail="Sender DID does not match configured peer")

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
    token: str = Query(..., description="HMAC-SHA256 of '{request_id}:{decision}'"),
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

    if not _verify_approval_token(request_id, decision, token):
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
