"""LangGraph StateGraph for the AGT federated RAG agent.

Wraps the compiled graph with AGT GovernanceMiddleware so every invocation
is recorded in the AGT audit log, governed by the Agent OS policy engine,
and traceable via AgentMesh telemetry.

Authorization flow routing
--------------------------
After ``check_auth`` runs, ``_route`` reads the flow field and dispatches:

    LOCAL_ALLOWED          → generate_answer
    LOCAL_NEEDS_APPROVAL   → start_approval
    LOCAL_DENIED           → format_response   (no data or peer)
    REMOTE                 → call_peer_agent
    REMOTE_APPROVED        → format_response   (set by handle_peer_result)
    REMOTE_NEEDS_APPROVAL  → format_response   (set by handle_peer_result)
    REMOTE_DENIED          → format_response   (set by handle_peer_result or error)

``call_peer_agent`` has its own conditional edge: if the node wrote an error
into state (e.g. circuit open, DID unverifiable) we short-circuit directly to
``format_response`` without passing through ``handle_peer_result``.

GovernanceMiddleware
--------------------
``agentmesh_integrations.langgraph.GovernanceMiddleware`` wraps every graph
invocation.  It:
  - Enforces the Agent OS policies before and after the graph runs.
  - Emits a structured audit event (agt_audit=True) for every invocation.
  - Integrates with AgentMesh trust scoring (anomalous behaviour decays score).
  - Exposes a kill-switch: if the agent's trust score drops below the threshold
    the middleware rejects the invocation before any node runs.

Compiled graph singleton
------------------------
``_compiled`` is built once and cached under ``_compile_lock``.  LangGraph's
``compile()`` is CPU-bound (graph validation + topological sort) but runs in
microseconds; the lock prevents duplicate compilation at cold-start when many
coroutines are racing.

run_query
---------
The public entry-point.  Injects the user token via ContextVar (never in
state), invokes the governed graph, and returns a normalised result dict.
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from agent.nodes import (
    call_peer_agent,
    check_auth,
    format_response,
    generate_answer,
    handle_peer_result,
    retrieve_local,
    set_user_token,
    start_approval,
)
from agent.state import AgentState, FlowDecision
from mesh.agent_identity import govern_action

log = structlog.get_logger(__name__)


# ── Routing functions ─────────────────────────────────────────────────────────

def _route(state: AgentState) -> str:
    """Route after check_auth based on the flow decision."""
    flow = state.get("flow")
    match flow:
        case FlowDecision.LOCAL_ALLOWED:
            return "generate_answer"
        case FlowDecision.LOCAL_NEEDS_APPROVAL:
            return "start_approval"
        case FlowDecision.LOCAL_DENIED:
            return "format_response"
        case FlowDecision.REMOTE:
            return "call_peer_agent"
        case (
            FlowDecision.REMOTE_APPROVED
            | FlowDecision.REMOTE_NEEDS_APPROVAL
            | FlowDecision.REMOTE_DENIED
        ):
            # handle_peer_result already set these — go directly to format
            return "format_response"
        case _:
            raise ValueError(
                f"_route encountered unexpected flow value: {flow!r}. "
                "check_auth must set a valid FlowDecision before this router runs."
            )


def _route_after_peer(state: AgentState) -> str:
    """Short-circuit to format_response if call_peer_agent recorded an error."""
    if state.get("error"):
        return "format_response"
    return "handle_peer_result"


# ── Graph construction ────────────────────────────────────────────────────────

def _build_graph() -> StateGraph:
    """Construct and wire the StateGraph (not yet compiled)."""
    graph: StateGraph = StateGraph(AgentState)

    # Nodes
    graph.add_node("retrieve_local", retrieve_local)
    graph.add_node("check_auth", check_auth)
    graph.add_node("generate_answer", generate_answer)
    graph.add_node("start_approval", start_approval)
    graph.add_node("call_peer_agent", call_peer_agent)
    graph.add_node("handle_peer_result", handle_peer_result)
    graph.add_node("format_response", format_response)

    # Entry
    graph.set_entry_point("retrieve_local")

    # Fixed edges
    graph.add_edge("retrieve_local", "check_auth")
    graph.add_edge("generate_answer", "format_response")
    graph.add_edge("start_approval", "format_response")
    graph.add_edge("handle_peer_result", "format_response")
    graph.add_edge("format_response", END)

    # Conditional edges
    graph.add_conditional_edges(
        "check_auth",
        _route,
        {
            "generate_answer": "generate_answer",
            "start_approval": "start_approval",
            "call_peer_agent": "call_peer_agent",
            "format_response": "format_response",
        },
    )
    graph.add_conditional_edges(
        "call_peer_agent",
        _route_after_peer,
        {
            "handle_peer_result": "handle_peer_result",
            "format_response": "format_response",
        },
    )

    return graph


# ── Compiled singleton ────────────────────────────────────────────────────────

_compiled: Any = None  # CompiledStateGraph | None
_compile_lock: asyncio.Lock = asyncio.Lock()


async def _get_compiled_graph() -> Any:
    """Return the compiled graph, building it once (double-checked locking)."""
    global _compiled
    if _compiled is not None:
        return _compiled
    async with _compile_lock:
        if _compiled is None:
            _compiled = _build_graph().compile()
            log.info("agent_graph_compiled")
    return _compiled


# ── Public entry-point ────────────────────────────────────────────────────────

async def run_query(
    query: str,
    user_id: str,
    user_token: str,
    task_id: str = "",
    context_id: str = "",
) -> dict[str, Any]:
    """Run the governed agent graph for a single query.

    The user token is injected into a ContextVar before the graph runs so it
    is never stored in AgentState, LangGraph snapshots, or telemetry traces.

    Args:
        query:       Natural-language query from the user.
        user_id:     Verified user identifier (from JWT ``sub`` claim).
        user_token:  Raw bearer token — stored ONLY in the ContextVar.
        task_id:     A2A / ANP task identifier; a UUID4 is generated if empty.
        context_id:  Conversation / session identifier.

    Returns:
        Dict with at minimum ``answer`` (str) and ``status_message`` (str).
    """
    # Inject user token into ContextVar — never into state
    set_user_token(user_token)

    initial_state: AgentState = {
        "query": query,
        "user_id": user_id,
        "task_id": task_id or str(uuid.uuid4()),
        "context_id": context_id,
        "flow": None,
        "allowed_chunk_ids": [],
        "pending_chunk_ids": [],
        "denied_chunk_ids": [],
        "fused_chunks": [],
        "qdrant_results": [],
        "graph_results": [],
        "answer": None,
        "peer_answer": None,
        "status_message": "",
        "approval_request_id": None,
        "peer_task_id": None,
        "peer_status": None,
        "error": None,
    }

    log.info("agent_graph_invoked", user_id=user_id, task_id=initial_state["task_id"])

    # AGT governance gate — every graph invocation is checked by the AgentMesh
    # governance engine (AgentMeshClient.execute_with_governance) and recorded in
    # its audit log. A denial (e.g. agent trust score below threshold — the AGT
    # kill-switch) rejects the invocation before any node runs.
    gov = await govern_action(
        "agent.graph.invoke",
        {"user_id": user_id, "task_id": initial_state["task_id"]},
    )
    if not gov.allowed:
        log.warning("agent_graph_invocation_denied", user_id=user_id, decision=gov.decision)
        raise PermissionError(f"Graph invocation denied by governance: {gov.decision}")

    graph = await _get_compiled_graph()
    final_state: AgentState = await graph.ainvoke(initial_state)

    log.info(
        "agent_graph_completed",
        user_id=user_id,
        flow=str(final_state.get("flow")),
        has_answer=bool(final_state.get("answer")),
    )

    return {
        "answer": final_state.get("answer") or "",
        "status_message": final_state.get("status_message") or "completed",
        "flow": str(final_state.get("flow")),
        "approval_request_id": final_state.get("approval_request_id"),
        "peer_task_id": final_state.get("peer_task_id"),
        "task_id": final_state["task_id"],
    }
