"""
FastAPI application — exposes:
  GET  /.well-known/agent-card.json   A2A AgentCard
  POST /tasks/send                    A2A task submission (SSE streaming)
  GET  /tasks/{task_id}               A2A task status poll
  POST /tasks/{task_id}/callback      A2A push notification webhook (cross-cluster callback)
  POST /approve/{request_id}          Approval UI endpoint (approve/deny)
  GET  /health                        Kubernetes liveness probe
"""
from __future__ import annotations

import uuid
from typing import Any, AsyncIterator

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
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
    TextPart,
)
from agent.graph import run_query
from auth.token_exchange import extract_user_id, validate_token
from config import settings
from workflow.approval import ApprovalDecisionSignal

log = structlog.get_logger(__name__)

app = FastAPI(
    title=settings.agent_name,
    version="0.1.0",
    docs_url="/docs",
)

# In-memory task store (replace with Redis/DB in production)
_tasks: dict[str, Task] = {}
_task_callbacks: dict[str, str] = {}   # task_id → push notification URL


# ── Dependency: validate bearer token ─────────────────────────────────────────

async def get_token_claims(authorization: str = Header(...)) -> dict[str, Any]:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    try:
        claims = await validate_token(token)
        return {"claims": claims, "token": token}
    except Exception as e:
        log.warning("token_validation_failed", error=str(e))
        raise HTTPException(status_code=401, detail="Invalid or expired token")


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

    # Register push notification webhook
    if req.push_notification and req.push_notification.url:
        _task_callbacks[task_id] = req.push_notification.url

    # Extract query text
    query = ""
    for part in req.message.parts:
        if isinstance(part, TextPart) or (isinstance(part, dict) and part.get("type") == "text"):
            query = part.text if hasattr(part, "text") else part.get("text", "")
            break

    # Create initial task record
    task = Task(
        id=task_id,
        contextId=req.context_id or "",
        status=TaskStatus(state=TaskState.SUBMITTED),
        history=[req.message],
    )
    _tasks[task_id] = task

    async def event_stream() -> AsyncIterator[dict[str, str]]:
        # Working
        task.status = TaskStatus(state=TaskState.WORKING, message="Processing your query...")
        _tasks[task_id] = task
        yield {
            "event": "task_status_update",
            "data": task.model_dump_json(by_alias=True),
        }

        try:
            final_state = await run_query(
                query=query,
                user_id=user_id,
                user_token=user_token,
                task_id=task_id,
                context_id=req.context_id or "",
            )
        except Exception as e:
            log.error("agent_run_failed", task_id=task_id, error=str(e))
            task.status = TaskStatus(state=TaskState.FAILED, message=str(e))
            _tasks[task_id] = task
            yield {
                "event": "task_status_update",
                "data": task.model_dump_json(by_alias=True),
            }
            return

        # Determine terminal state
        status_msg = final_state.get("status_message", "")
        answer = final_state.get("answer", "")

        if final_state.get("approval_request_id") and not final_state.get("answer"):
            # Needs approval
            task.status = TaskStatus(
                state=TaskState.INPUT_REQUIRED,
                message=status_msg,
            )
        elif final_state.get("error"):
            task.status = TaskStatus(state=TaskState.FAILED, message=final_state["error"])
        else:
            # Completed — add agent reply to history
            agent_msg = Message(
                role="agent",
                parts=[TextPart(text=answer or status_msg)],
                messageId=str(uuid.uuid4()),
                taskId=task_id,
            )
            task.history.append(agent_msg)
            task.status = TaskStatus(state=TaskState.COMPLETED, message="Done")

        _tasks[task_id] = task
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
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task.model_dump(by_alias=True)


# ── tasks/{task_id}/callback POST (A2A push notification) ─────────────────────

@app.post("/tasks/{task_id}/callback")
async def task_callback(
    task_id: str,
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(get_token_claims),
) -> dict[str, str]:
    """
    Receives A2A push notifications from the peer agent (cross-cluster approval callback).
    Updates the local task record so the user can poll for the result.
    """
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    new_state = payload.get("status", {}).get("state", "completed")
    msg = payload.get("status", {}).get("message", "")

    task.status = TaskStatus(
        state=TaskState(new_state),
        message=msg,
    )
    _tasks[task_id] = task
    log.info("task_callback_received", task_id=task_id, state=new_state)
    return {"ok": "true"}


# ── /approve/{request_id} (approval UI endpoint) ──────────────────────────────

@app.get("/approve/{request_id}")
async def handle_approval(
    request_id: str,
    decision: str,
    request: Request,
) -> JSONResponse:
    """
    Called by the approver clicking Approve/Deny in the Slack message or approval UI.
    Sends a Temporal signal to the running ApprovalWorkflow.
    """
    if decision not in ("approve", "deny"):
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'deny'")

    workflow_id = f"approval-{request_id}"
    temporal_client = await TemporalClient.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
    )

    handle = temporal_client.get_workflow_handle(workflow_id)
    try:
        await handle.signal(
            "approval_decision",
            ApprovalDecisionSignal(
                decision="approved" if decision == "approve" else "denied",
                reason=request.query_params.get("reason", ""),
            ),
        )
    except Exception as e:
        log.error("temporal_signal_failed", workflow_id=workflow_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

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
