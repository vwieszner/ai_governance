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

# Use the OS trust store for TLS verification BEFORE any SSL context is created.
# Python's bundled certifi CA bundle does not include the issuer for the NVIDIA
# (and some other) endpoints on this host, causing CERTIFICATE_VERIFY_FAILED.
# truststore delegates verification to the OS, which has the issuer. Must run
# first, before httpx/openai build their default SSL contexts.
import truststore
truststore.inject_into_ssl()

import asyncio
import contextvars
import hashlib
import hmac as hmac_lib
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import redis.asyncio as aioredis
import structlog
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
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
from agent.state import AgentState
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

# PY-8: compile once at module load, not on every request
_SAFE_ID_CHARS = re.compile(r"[^a-zA-Z0-9\-]")


class _BodyTooLargeError(Exception):
    """Internal sentinel — body limit exceeded; 413 already sent to the ASGI server."""

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
        _raw_id = headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        # M3-1: sanitize to alphanumeric + hyphens, max 64 chars, to prevent
        # header injection via CRLF sequences or oversized values.
        # PY-8: _SAFE_ID_CHARS is a module-level constant; not recompiled per request.
        if _raw_id:
            request_id = _SAFE_ID_CHARS.sub("", _raw_id)[:64] or str(uuid.uuid4())
        else:
            request_id = str(uuid.uuid4())
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
                    # GQ-3: HTTPException raised inside a raw ASGI receive() callable
                    # is NOT caught by FastAPI's exception handlers — they only wrap
                    # the endpoint coroutine, not the receive channel.  Send the 413
                    # directly over the ASGI send channel, then raise a private
                    # sentinel to abort request processing cleanly.
                    _body = b"Request body too large"
                    await send({
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [
                            (b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(_body)).encode()),
                        ],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": _body,
                        "more_body": False,
                    })
                    raise _BodyTooLargeError()
            return message

        try:
            await self.app(scope, receive_wrapper, send)
        except _BodyTooLargeError:
            pass  # 413 already sent above


# ── Redis task store (C-3) ────────────────────────────────────────────────────

_redis: aioredis.Redis | None = None
# HIGH-1: protect the singleton with a lock — same double-checked locking pattern
# used by all other singletons in this codebase.
_redis_lock: asyncio.Lock = asyncio.Lock()


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is not None:
        return _redis
    async with _redis_lock:
        if _redis is None:
            _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


async def _store_task(task: Task, owner_id: str | None = None) -> None:
    # HIGH-1: wrap Redis operations — surface connectivity failures as 503, not 500
    try:
        r = await _get_redis()
        if owner_id is not None:
            task.metadata["owner_id"] = owner_id
        await r.setex(
            f"task:{task.id}",
            settings.task_ttl_seconds,
            task.model_dump_json(by_alias=True),
        )
    except Exception as exc:
        log.error("redis_store_task_failed", task_id=task.id, error=str(exc))
        raise HTTPException(status_code=503, detail="Task store temporarily unavailable")


async def _load_task(task_id: str) -> Task | None:
    try:
        r = await _get_redis()
        data = await r.get(f"task:{task_id}")
    except Exception as exc:
        log.error("redis_load_task_failed", task_id=task_id, error=str(exc))
        raise HTTPException(status_code=503, detail="Task store temporarily unavailable")
    if data is None:
        return None
    return Task.model_validate_json(data)


async def _store_callback_url(task_id: str, url: str) -> None:
    # HIGH-2: this stores the A2A push-notification webhook URL for the *originating*
    # caller, so that if this agent later acts as the *peer* responding to a cross-
    # cluster request it knows where to push updates.  The key is read by the
    # task_callback endpoint logic if/when the peer calls back with a status update.
    # NOTE: currently _load_callback_url is not implemented — add it when implementing
    # the full push-notification fanout path.
    try:
        r = await _get_redis()
        await r.setex(f"task_cb:{task_id}", settings.task_ttl_seconds, url)
    except Exception as exc:
        # Non-fatal: push notifications are best-effort; the SSE stream is the
        # primary delivery mechanism.
        log.warning("redis_store_callback_url_failed", task_id=task_id, error=str(exc))


# ── Rate limiting (Finding #7) ────────────────────────────────────────────────

async def _check_rate_limit(subject: str) -> None:
    """
    Finding #7: fixed-window per-subject rate limit for expensive query
    endpoints. Backed by Redis (INCR + EXPIRE). Fails OPEN on a Redis error —
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


# ── HMAC helpers (C-2) ────────────────────────────────────────────────────────

def _sign_approval(request_id: str, decision: str, exp: int) -> str:
    # Finding #2: the signed message binds an expiry timestamp so an approval
    # deep-link cannot be replayed indefinitely after it leaks (mail archive,
    # Slack export, log aggregation, browser history).
    key = settings.approval_hmac_secret.encode()
    msg = f"{request_id}:{decision}:{exp}".encode()
    return hmac_lib.new(key, msg, hashlib.sha256).hexdigest()


def _verify_approval_token(request_id: str, decision: str, exp: int, token: str) -> bool:
    expected = _sign_approval(request_id, decision, exp)
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
    # FA-6: close the Redis connection pool so the OS releases sockets cleanly.
    # Without this, Kubernetes pod termination logs spurious "connection reset" errors.
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None


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


# ── Dependency: validate bearer token ─────────────────────────────────────────

async def get_token_claims(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    # SEC: a MISSING Authorization header must be 401 (RFC 7235), not FastAPI's
    # default 422 for a required header. Declaring it Optional and checking here
    # makes "missing" and "malformed" both fail closed with the same 401, and
    # lets us emit a WWW-Authenticate challenge.
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
        # LOW-5: reject tokens that lack a `sub` claim — an empty user_id would
        # propagate into OpenFGA and Redis as an empty string, matching any tuple
        # with an empty user ID and creating a phantom user in the task store.
        if not claims.get("sub"):
            raise HTTPException(status_code=401, detail="Token missing required 'sub' claim")
        return {"claims": claims, "token": token}
    except JWTError:
        # C3-3: do NOT log str(e) — python-jose includes the raw JWT value and
        # decoded claim payloads in many error messages, which would write user
        # PII and token material into structured logs / aggregators.
        log.warning("token_validation_failed")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except AuthServiceUnavailable as e:
        # S-9: JWKS network errors → 503, not 401
        log.error("auth_service_unavailable", error=str(e))
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    except Exception as e:
        log.error("token_validation_unexpected_error", error=str(e))
        raise HTTPException(status_code=503, detail="Authentication service unavailable")


# ── AgentCard ─────────────────────────────────────────────────────────────────

@app.get(
    "/.well-known/agent-card.json",
    response_model=AgentCard,
    response_model_by_alias=True,  # FA-2: emit camelCase aliases per A2A spec
)
async def agent_card() -> AgentCard:
    return AgentCard(
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


# ── tasks/send (SSE streaming) ────────────────────────────────────────────────

@app.post(
    "/tasks/send",
    response_class=EventSourceResponse,  # FA-1: declare SSE content-type in OpenAPI schema
)
async def send_task(
    request: Request,
    auth: dict[str, Any] = Depends(get_token_claims),
) -> EventSourceResponse:
    # FA-7: wrap JSON parsing so a malformed body returns 422, not 500
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")
    req = SendTaskRequest.model_validate(body)

    task_id = req.id or str(uuid.uuid4())
    user_id = extract_user_id(auth["claims"])
    user_token = auth["token"]

    # Finding #7: per-subject rate limit before doing any expensive work
    # (retrieval fan-out + LLM call). Fails open on Redis error.
    await _check_rate_limit(user_id)

    # Validate query length before processing (missing input validation fix)
    query = ""
    for part in req.message.parts:
        # GQ-1: after Pydantic validation, parts are always TextPart or DataPart objects.
        # The isinstance(part, dict) branch is unreachable and was masking type errors.
        if isinstance(part, TextPart):
            query = part.text
            break
    # L3-1: reject messages that contain no text part — an empty query passes the
    # length check but produces a useless LLM response.
    if not query:
        raise HTTPException(status_code=400, detail="Message must contain at least one text part")
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

        # Live progress channel: nodes push human-readable lines (incl. the
        # cross-cluster agent-to-agent conversation) onto this queue; we stream
        # each one out as an intermediate task_status_update so the UI Monitor
        # shows the federation happening instead of a single opaque "working".
        progress_queue: asyncio.Queue[str] = asyncio.Queue()

        async def progress_cb(line: str) -> None:
            await progress_queue.put(line)

        # R-3: wrap run_query in a Task so client disconnect cancels it
        # N3-5: asyncio.create_task() is the preferred API (ensure_future deprecated)
        # GQ-5: parameterize Task with the return type for static analysis
        run_task: asyncio.Task[AgentState] = asyncio.create_task(
            run_query(
                query=query,
                user_id=user_id,
                user_token=user_token,
                task_id=task_id,
                context_id=req.context_id or "",
                progress_cb=progress_cb,
            )
        )

        try:
            # Drain progress lines as they arrive, until the graph finishes.
            while not run_task.done() or not progress_queue.empty():
                try:
                    line = await asyncio.wait_for(progress_queue.get(), timeout=0.3)
                except asyncio.TimeoutError:
                    continue
                task.status = TaskStatus(state=TaskState.WORKING, message=line)
                yield {
                    "event": "task_status_update",
                    "data": task.model_dump_json(by_alias=True),
                }
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

        # Finding #3: mark the task as eligible for a peer callback only when
        # this agent actually delegated it to a peer cluster. task_callback
        # rejects callbacks for any task without this flag.
        if final_state.get("peer_task_id"):
            task.metadata["awaiting_peer_callback"] = True

        await _store_task(task, owner_id=user_id)
        yield {
            "event": "task_status_update",
            "data": task.model_dump_json(by_alias=True),
        }

    return EventSourceResponse(event_stream())


# ── tasks/{task_id} GET ───────────────────────────────────────────────────────

@app.get(
    "/tasks/{task_id}",
    response_model=Task,
    response_model_by_alias=True,  # FA-3: emit camelCase aliases per A2A spec
)
async def get_task(
    task_id: str,
    auth: dict[str, Any] = Depends(get_token_claims),
) -> Task:
    task = await _load_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # S-7 + H3-5: enforce task ownership — deny-by-default.
    # If owner_id is absent (e.g., a task stored without an owner) or belongs to
    # a different user, return 404 to avoid confirming the task exists.
    caller_id = extract_user_id(auth["claims"])
    owner_id = task.metadata.get("owner_id")
    if not owner_id or owner_id != caller_id:
        raise HTTPException(status_code=404, detail="Task not found")

    return task


@app.get("/tasks/{task_id}/result")
async def get_task_result(
    task_id: str,
    auth: dict[str, Any] = Depends(get_token_claims),
) -> JSONResponse:
    """Poll the outcome of a pending-approval request — the cross-machine,
    server-mediated delivery channel back to the requester.

    Security / governance:
      - Authenticated (JWT) and **owner-only**: the caller must own the task,
        else 404 (never confirms another user's task exists).
      - On 'approved' the answer is produced by **re-running the query through the
        full governance pipeline** (run_query → OpenFGA re-check). The endpoint
        does NOT trust the recorded decision to release data — it only releases
        what the user is *currently* authorized for. If access was somehow not
        actually granted, the re-run will not return restricted content.

    Returns one of:
      {"status": "pending"}                          — no decision yet
      {"status": "denied",  "message": "<reason>"}   — denied / timed out
      {"status": "completed", "answer": "<text>"}    — approved → fresh answer
    """
    task = await _load_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    caller_id = extract_user_id(auth["claims"])
    owner_id = task.metadata.get("owner_id")
    if not owner_id or owner_id != caller_id:
        raise HTTPException(status_code=404, detail="Task not found")

    import json as _json  # noqa: PLC0415
    r = await _get_redis()
    raw = await r.get(f"decision:{task_id}")
    if not raw:
        return JSONResponse(content={"status": "pending"})

    try:
        decision = _json.loads(raw)
    except Exception:
        decision = {"decision": "pending"}

    verdict = decision.get("decision", "pending")
    if verdict in ("denied", "timeout"):
        return JSONResponse(content={
            "status": "denied",
            "message": decision.get("reason") or "Your request was not approved.",
        })

    if verdict == "approved":
        # Recover the original question from the task's first user message.
        query = ""
        for msg in task.history:
            if msg.role == "user":
                for part in msg.parts:
                    if getattr(part, "text", None):
                        query = part.text
                        break
            if query:
                break
        if not query:
            return JSONResponse(content={"status": "pending"})
        # Re-run through the FULL governed pipeline as this user — access is
        # re-checked in OpenFGA, so the answer is only released if truly allowed.
        final_state = await run_query(
            query=query,
            user_id=caller_id,
            user_token=auth["token"],
            task_id=task_id,
            context_id="",
        )
        answer = final_state.get("answer") or final_state.get("status_message") or ""
        return JSONResponse(content={"status": "completed", "answer": answer})

    return JSONResponse(content={"status": "pending"})


# ── tasks/{task_id}/callback POST (A2A push notification) ─────────────────────

@app.post("/tasks/{task_id}/callback", response_model=dict[str, bool])  # FA-4
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
    Finding #3: the callback is accepted only for a task that this agent
             actually delegated to a peer (metadata flag awaiting_peer_callback).
             This stops an authorised peer from overwriting the status of
             local-only tasks it was never a participant in.
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

    # Finding #3: only tasks this agent delegated to a peer may receive a
    # callback. Return 404 (not 403) so the endpoint does not confirm the
    # existence of tasks the caller has no legitimate relationship with.
    if not task.metadata.get("awaiting_peer_callback"):
        log.warning(
            "callback_for_non_delegated_task",
            task_id=task_id,
            caller_client_id=caller_client_id,
        )
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
    # FA-5 / syntax fix: Request has no default, so it must precede the
    # Query(...)-defaulted parameters — otherwise the module fails to import
    # with "parameter without a default follows parameter with a default".
    request: Request,
    decision: str = Query(..., pattern="^(approve|deny)$"),
    exp: int = Query(..., description="Unix expiry timestamp — link rejected after this time"),
    token: str = Query(..., description="HMAC-SHA256 of '{request_id}:{decision}:{exp}'"),
    reason: str = Query("", description="Optional reason for the decision"),
) -> JSONResponse:
    """
    FIX C-2: HMAC-signed deep-link — only Slack/email links generated by the
    workflow can trigger a Temporal signal.
    FIX S-6: Temporal errors are logged internally; only a generic message is
    returned to the caller to prevent information disclosure.
    Finding #2: the link carries a signed expiry timestamp; expired links are
    rejected so a leaked URL cannot be replayed indefinitely.
    """
    # Finding #2: reject expired links before any work. The expiry is part of
    # the HMAC-signed message, so a caller cannot extend it by editing the query.
    if exp < int(time.time()):
        log.warning("approval_link_expired", request_id=request_id)
        raise HTTPException(status_code=401, detail="Approval link has expired")
    if not _verify_approval_token(request_id, decision, exp, token):
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
                # M3-3: cap reason to 500 chars — approver input is free-text and
                # could otherwise inject oversized Slack payloads or mrkdwn markup.
                reason=reason[:500],
                # Finding #8: record the decision channel so the workflow audit
                # log is not blank. Full human attribution requires an
                # authenticated approval UI (see SECURITY_REVIEW.md).
                approver_id="approval-deeplink",
            ),
        )
    except Exception as e:
        # S-6: log full details internally, return generic message to caller
        log.error("temporal_signal_failed", workflow_id=workflow_id, error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to record decision. Please try again.",
        )

    # LOW-3: return a generic acknowledgement — echoing request_id and decision
    # in the response leaks workflow identifiers to the approver's browser/log.
    return JSONResponse(
        content={"message": "Decision recorded. Thank you."},
        status_code=200,
    )


@app.get("/approvals/pending")
async def list_pending_approvals(
    request: Request,
    auth: dict[str, Any] = Depends(get_token_claims),
) -> JSONResponse:
    """Authenticated approver inbox — the pending access requests THIS caller
    (as data owner) is entitled to decide.

    The requester never learns the ``request_id`` (L-6); only the owner can
    enumerate the requests routed to them. Implemented by listing running
    ``ApprovalWorkflow`` executions and keeping those whose designated approver
    == the caller's ``sub``. (Demo-scale: O(open requests) point queries;
    production would index the approver as a Temporal search attribute.)

    Returns ``{"pending": [{"request_id", "requester_id", "query"}]}``.
    """
    caller_sub = extract_user_id(auth["claims"])
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


@app.post("/approvals/{request_id}/decision")
async def authenticated_approval(
    request_id: str,
    request: Request,
    auth: dict[str, Any] = Depends(get_token_claims),
) -> JSONResponse:
    """Authenticated approval decision — the product/UI path, alongside the HMAC
    deep-link (`/approve`).

    Why a second path: the deep-link is a bearer credential (anyone holding the
    signed URL can decide) and records the approver as the constant
    ``"approval-deeplink"`` — no human attribution. Here the caller's JWT is the
    credential, so the decision carries REAL attribution and the backend verifies
    the caller is the data owner before signalling Temporal.

    - Bearer JWT required (``get_token_claims`` → 401 on missing/invalid).
    - 403 unless the caller's ``sub`` == the request's designated approver (owner).
    - 404 if no open approval workflow; 409 if already decided.
    Body: ``{"decision": "approve"|"deny", "reason": "<optional>"}``.
    """
    # request_id is a server-generated uuid4; constrain it so it cannot be used
    # to inject into the Temporal workflow-id namespace.
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request_id):
        raise HTTPException(status_code=400, detail="Invalid request_id")

    approver_sub = extract_user_id(auth["claims"])

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
