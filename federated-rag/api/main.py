"""
FastAPI application — exposes:
  GET  /.well-known/agent-card.json   A2A AgentCard
  POST /tasks/send                    A2A task submission (SSE streaming)
  GET  /tasks/{task_id}               A2A task status poll
  POST /tasks/{task_id}/callback      A2A push notification webhook (cross-cluster)
  GET  /approve/{request_id}          Approval UI endpoint (HMAC-signed deep-link)
  GET  /health                        Kubernetes liveness probe

Security fixes in this file:
  C-2  — /approve uses HMAC-SHA256 signed token (no unauthenticated UUID guessing)
  C-3  — Task store backed by Redis with configurable TTL
  C-4  — /callback verifies caller's JWT client_id is a known peer agent
  M-3  — Request body size enforced unconditionally (S-1 fix: pure ASGI middleware,
          not BaseHTTPMiddleware, so SSE streaming is never buffered — Q-1 fix)
  S-2  — Callback payload validated with Pydantic; bad state → 422, not 500
  S-6  — Temporal internal errors not leaked in HTTP 500 bodies
  S-7  — GET /tasks/{id} enforces owner_id so users can only read their own tasks
  S-9  — IdP unavailability returns 503, not 401
  Q-2  — X-Request-ID correlation middleware: echoes an incoming request ID or
          generates one, binds it to the structlog context, and returns it in the
          response header for end-to-end distributed tracing.
  Q-3  — Swagger/ReDoc disabled in production (set DOCS_ENABLED=true for local dev)
  Q-4  — Empty peer_agent_client_ids now rejects ALL callbacks instead of skipping check
  R-3  — Client disconnect cancels the in-flight run_query coroutine
"""
from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac as hmac_lib
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import redis.asyncio as aioredis
import structlog
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from jose import JWTError
from pydantic import ValidationError
from sse_starlette.sse import EventSourceResponse
from temporalio.client import Client as TemporalClient

from a2a.models import (
    AgentCard,
    AgentCapabilities,
    AgentSkill,
    Message,
    SendTaskRequest,
    Task,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
    TextPart,
)
from agent.graph import run_query
from auth.token_exchange import (
    AuthServiceUnavailable,
    extract_client_id,
    extract_user_id,
    validate_token,
)
from config import settings
from workflow.approval import ApprovalDecisionSignal

log = structlog.get_logger(__name__)

_DOCS_ENABLED = os.getenv("DOCS_ENABLED", "false").lower() == "true"

# ── Request correlation ID (Q-2) ──────────────────────────────────────────────
# Module-level ContextVar so the request ID is available to structlog processors
# in any coroutine that runs within the same asyncio task.
_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default=""
)


class _CorrelationIdMiddleware:
    """
    Q-2: Pure ASGI middleware that:
      1. Reads X-Request-ID from the incoming request (if present).
      2. Generates a new UUID if the header is absent.
      3. Binds the ID to the structlog context and the asyncio ContextVar.
      4. Adds X-Request-ID to every response so callers can trace end-to-end.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        request_id = (
            headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
            or str(uuid.uuid4())
        )
        _request_id_ctx.set(request_id)

        # Inject into structlog's context for this request
        structlog.contextvars.bind_contextvars(request_id=request_id)

        async def send_with_header(message: Any) -> None:
            if message["type"] == "http.response.start":
                # Append our correlation header to the response
                headers_list = list(message.get("headers", []))
                headers_list.append(
                    (b"x-request-id", request_id.encode("ascii"))
                )
                message = {**message, "headers": headers_list}
            await send(message)

        try:
            await self.app(scope, receive, send_with_header)
        finally:
            structlog.contextvars.unbind_contextvars("request_id")


# ── Pure ASGI body-size middleware (S-1 + Q-1 fix) ───────────────────────────
# BaseHTTPMiddleware buffers the full response, which destroys SSE streaming.
# This pure ASGI wrapper only intercepts the receive channel (request body),
# leaving the send channel (response) completely untouched.

class _LimitBodySizeMiddleware:
    """
    Raw ASGI middleware that enforces max request body size without buffering
    the response. Safe for SSE streaming endpoints.
    """

    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Fast-path: reject immediately on Content-Length header
        headers = dict(scope.get("headers", []))
        cl_header = headers.get(b"content-length")
        if cl_header:
            try:
                if int(cl_header) > self.max_bytes:
                    response = Response("Request body too large", status_code=413)
                    await response(scope, receive, send)
                    return
            except ValueError:
                pass  # malformed header — let the framework handle it

        # Wrap the receive channel to count bytes for chunked encoding
        total_received = 0

        async def receive_wrapper() -> Any:
            nonlocal total_received
            message = await receive()
            if message["type"] == "http.request":
                total_received += len(message.get("body", b""))
                if total_received > self.max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail="Request body too large",
                    )
            return message

        await self.app(scope, receive_wrapper, send)


# ── Redis task store (C-3) ────────────────────────────────────────────────────

_redis: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


async def _store_task(task: Task, owner_id: str | None = None) -> None:
    r = await _get_redis()
    # Embed the owner_id in the task metadata for ownership verification (S-7)
    if owner_id is not None:
        task.metadata["owner_id"] = owner_id
    await r.setex(
        f"task:{task.id}",
        settings.task_ttl_seconds,
        task.model_dump_json(by_alias=True),
    )


async def _load_task(task_id: str) -> Task | None:
    r = await _get_redis()
    data = await r.get(f"task:{task_id}")
    if data is None:
        return None
    return Task.model_validate_json(data)


async def _store_callback_url(task_id: str, url: str) -> None:
    r = await _get_redis()
    await r.setex(f"task_cb:{task_id}", settings.task_ttl_seconds, url)


# ── HMAC helpers (C-2) ────────────────────────────────────────────────────────

def _sign_approval(request_id: str, decision: str) -> str:
    key = settings.approval_hmac_secret.encode()
    msg = f"{request_id}:{decision}".encode()
    return hmac_lib.new(key, msg, hashlib.sha256).hexdigest()


def _verify_approval_token(request_id: str, decision: str, token: str) -> bool:
    expected = _sign_approval(request_id, decision)
    return hmac_lib.compare_digest(expected, token)


# ── FastAPI app with lifespan ─────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    tc = await TemporalClient.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
    )
    app.state.temporal_client = tc
    log.info("temporal_client_connected", address=settings.temporal_address)
    yield
    log.info("shutting_down")


app = FastAPI(
    title=settings.agent_name,
    version="0.1.0",
    # Q-3: docs disabled in production; set DOCS_ENABLED=true for local development
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    lifespan=lifespan,
)

# Q-2: correlation ID middleware — must be added BEFORE body-size middleware
# so every request (including 413 rejections) gets an X-Request-ID header.
app.add_middleware(_CorrelationIdMiddleware)

# S-1 + Q-1: pure ASGI body-size limit that does NOT buffer SSE responses
app.add_middleware(_LimitBodySizeMiddleware, max_bytes=settings.max_request_body_bytes)


# ── Dependency: validate bearer token ─────────────────────────────────────────

async def get_token_claims(authorization: str = Header(...)) -> dict[str, Any]:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    try:
        claims = await validate_token(token)
        return {"claims": claims, "token": token}
    except JWTError as e:
        log.warning("token_validation_failed", error=str(e))
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except AuthServiceUnavailable as e:
        # S-9: JWKS network errors → 503, not 401
        log.error("auth_service_unavailable", error=str(e))
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    except Exception as e:
        log.error("token_validation_unexpected_error", error=str(e))
        raise HTTPException(status_code=503, detail="Authentication service unavailable")


# ── AgentCard ─────────────────────────────────────────────────────────────────

@app.get("/.well-known/agent-card.json", response_model=None)
async def agent_card() -> dict[str, Any]:
    card = AgentCard(
        name=settings.agent_name,
        description=(
            "Federated RAG agent — hybrid vector + graph retrieval with "
            "OpenFGA per-chunk authorization and Temporal approval workflows."
        ),
        url=str(settings.agent_url),
        capabilities=AgentCapabilities(
            streaming=True,
            push_notifications=True,
            state_transition_history=True,
        ),
        skills=[
            AgentSkill(
                id="rag-query",
                name="RAG Query",
                description="Answer questions using the knowledge base with access control.",
            )
        ],
    )
    return card.model_dump(by_alias=True)


# ── tasks/send (SSE streaming) ────────────────────────────────────────────────

@app.post("/tasks/send")
async def send_task(
    request: Request,
    auth: dict[str, Any] = Depends(get_token_claims),
) -> EventSourceResponse:
    body = await request.json()
    req = SendTaskRequest.model_validate(body)

    task_id = req.id or str(uuid.uuid4())
    user_id = extract_user_id(auth["claims"])
    user_token = auth["token"]

    # Validate query length before processing (missing input validation fix)
    query = ""
    for part in req.message.parts:
        if isinstance(part, TextPart) or (isinstance(part, dict) and part.get("type") == "text"):
            query = part.text if hasattr(part, "text") else part.get("text", "")
            break
    if len(query) > settings.max_query_length:
        raise HTTPException(
            status_code=400,
            detail=f"Query exceeds maximum length of {settings.max_query_length} characters",
        )

    if req.push_notification and req.push_notification.url:
        await _store_callback_url(task_id, req.push_notification.url)

    # Create and persist initial task record; embed owner for S-7
    task = Task(
        id=task_id,
        contextId=req.context_id or "",
        status=TaskStatus(state=TaskState.SUBMITTED),
        history=[req.message],
    )
    await _store_task(task, owner_id=user_id)

    async def event_stream() -> AsyncIterator[dict[str, str]]:
        task.status = TaskStatus(state=TaskState.WORKING, message="Processing your query...")
        await _store_task(task, owner_id=user_id)
        yield {
            "event": "task_status_update",
            "data": task.model_dump_json(by_alias=True),
        }

        # R-3: wrap run_query in a Task so client disconnect cancels it
        run_task: asyncio.Task = asyncio.ensure_future(
            run_query(
                query=query,
                user_id=user_id,
                user_token=user_token,
                task_id=task_id,
                context_id=req.context_id or "",
            )
        )

        try:
            final_state = await run_task
        except asyncio.CancelledError:
            # Client disconnected — cancel background work and stop the stream
            if not run_task.done():
                run_task.cancel()
            log.info("task_cancelled_by_client", task_id=task_id)
            return
        except Exception as e:
            log.error("agent_run_failed", task_id=task_id, error=str(e))
            task.status = TaskStatus(state=TaskState.FAILED, message="Internal error")
            await _store_task(task, owner_id=user_id)
            yield {
                "event": "task_status_update",
                "data": task.model_dump_json(by_alias=True),
            }
            return

        status_msg = final_state.get("status_message", "")
        answer = final_state.get("answer", "")

        if final_state.get("approval_request_id") and not final_state.get("answer"):
            task.status = TaskStatus(state=TaskState.INPUT_REQUIRED, message=status_msg)
        elif final_state.get("error"):
            task.status = TaskStatus(state=TaskState.FAILED, message="Processing error")
        else:
            agent_msg = Message(
                role="agent",
                parts=[TextPart(text=answer or status_msg)],
                messageId=str(uuid.uuid4()),
                taskId=task_id,
            )
            task.history.append(agent_msg)
            task.status = TaskStatus(state=TaskState.COMPLETED, message="Done")

        await _store_task(task, owner_id=user_id)
        yield {
            "event": "task_status_update",
            "data": task.model_dump_json(by_alias=True),
        }

    return EventSourceResponse(event_stream())


# ── tasks/{task_id} GET ───────────────────────────────────────────────────────

@app.get("/tasks/{task_id}")
async def get_task(
    task_id: str,
    auth: dict[str, Any] = Depends(get_token_claims),
) -> dict[str, Any]:
    task = await _load_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # S-7: enforce task ownership — users may only read their own tasks
    caller_id = extract_user_id(auth["claims"])
    owner_id = task.metadata.get("owner_id")
    if owner_id and owner_id != caller_id:
        # Return 404 rather than 403 to avoid confirming the task exists
        raise HTTPException(status_code=404, detail="Task not found")

    return task.model_dump(by_alias=True)


# ── tasks/{task_id}/callback POST (A2A push notification) ─────────────────────

@app.post("/tasks/{task_id}/callback")
async def task_callback(
    task_id: str,
    request: Request,
    auth: dict[str, Any] = Depends(get_token_claims),
) -> dict[str, bool]:
    """
    Receives A2A push notifications from the peer agent (cross-cluster callback).

    FIX C-4: verifies the caller's JWT client_id is in peer_agent_client_ids_list.
    FIX Q-4: empty peer_agent_client_ids now rejects all callbacks (previously
             skipped the check entirely when the list was empty).
    FIX S-2: payload validated with Pydantic TaskStatusUpdateEvent before use.
    """
    # C-4 + Q-4: always enforce; empty list → deny all
    caller_client_id = extract_client_id(auth["claims"])
    allowed_peers = settings.peer_agent_client_ids_list
    if not allowed_peers or caller_client_id not in allowed_peers:
        log.warning(
            "callback_rejected",
            caller_client_id=caller_client_id,
            allowed=allowed_peers,
        )
        raise HTTPException(status_code=403, detail="Caller is not a recognised peer agent")

    task = await _load_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # S-2: validate payload structure with Pydantic; bad data → 422 not 500
    try:
        payload = await request.json()
        event = TaskStatusUpdateEvent.model_validate(payload)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid callback payload: {exc}")

    task.status = TaskStatus(
        state=event.status.state,
        message=(event.status.message or "")[:500],   # cap free-text length
    )
    owner_id = task.metadata.get("owner_id")
    await _store_task(task, owner_id=owner_id)
    log.info("task_callback_received", task_id=task_id, state=event.status.state, peer=caller_client_id)
    return {"ok": True}


# ── /approve/{request_id} (HMAC-protected approval deep-link) ─────────────────

@app.get("/approve/{request_id}")
async def handle_approval(
    request_id: str,
    decision: str = Query(..., pattern="^(approve|deny)$"),
    token: str = Query(..., description="HMAC-SHA256 signature of '{request_id}:{decision}'"),
    reason: str = Query("", description="Optional reason for the decision"),
    request: Request = None,
) -> JSONResponse:
    """
    FIX C-2: HMAC-signed deep-link — only Slack/email links generated by the
    workflow can trigger a Temporal signal.
    FIX S-6: Temporal errors are logged internally; only a generic message is
    returned to the caller to prevent information disclosure.
    """
    if not _verify_approval_token(request_id, decision, token):
        log.warning("approval_hmac_invalid", request_id=request_id, decision=decision)
        raise HTTPException(status_code=401, detail="Invalid or expired approval token")

    workflow_id = f"approval-{request_id}"
    temporal_client: TemporalClient = request.app.state.temporal_client

    handle = temporal_client.get_workflow_handle(workflow_id)
    try:
        await handle.signal(
            "approval_decision",
            ApprovalDecisionSignal(
                decision="approved" if decision == "approve" else "denied",
                reason=reason,
            ),
        )
    except Exception as e:
        # S-6: log full details internally, return generic message to caller
        log.error("temporal_signal_failed", workflow_id=workflow_id, error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to record decision. Please try again.",
        )

    return JSONResponse(
        content={"message": f"Decision '{decision}' recorded for request {request_id}"},
        status_code=200,
    )


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "cluster": settings.cluster_id}


# ── Run ───────────────────────────────────────────────────────────────────────

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
