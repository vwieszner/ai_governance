"""LangGraph StateGraph for the AGT federated RAG agent.

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

Governance gates (what actually enforces policy)
------------------------------------------------
There are two ENFORCING layers, both fail-closed:

  1. Per-node ``_enforce(action, ctx)`` (agent.nodes) — the primary control.
     Every node calls it before doing any work; it evaluates the Agent OS
     PolicyEvaluator loaded from ``settings.policy_dir`` and RAISES
     ``PermissionError`` on a deny (default-deny: unknown action / unmatched
     context → deny). This is what blocks oversized context, untrusted
     collections, unverified/low-trust peers, etc.
  2. OpenFGA per-chunk ReBAC (check_auth) — data-level authorization.

``run_query`` additionally calls ``govern_action("agent.graph.invoke", ...)``
(AgentMesh ``AgentMeshClient.execute_with_governance``) and raises if it returns
``allowed=False``. This is DEFENCE-IN-DEPTH on top of the two data-path layers
above — an operator KILL-SWITCH, not a data-authorization control. ``get_mesh()``
now builds the client with a real agentmesh-format policy
(``_GRAPH_GOVERNANCE_POLICY``: ``default_action: allow`` + a priority-1000 deny
rule on ``kill_switch_engaged``), so the gate genuinely DENIES — verified
empirically — when ``run_query`` injects ``settings.agent_kill_switch_engaged ==
True`` into the context: the deny raises ``PermissionError`` before the graph is
even compiled (no node runs, no retrieval, no LLM). NOTE on the HTTP surface: this
``PermissionError`` is caught *inside* the request handlers — ``/query`` reports it
as an SSE ``error`` event (the stream is already HTTP 200) and ``/a2a/query``
returns a signed ``status="failed"`` (HTTP 200); it does NOT surface as a 403
unless the endpoint also checks the flag before streaming. The security-relevant
guarantee is the early denial, not the status code.

SCOPE / HONESTY (do not overclaim): this is a DEPLOY-TIME operator disable lever.
``settings`` is read once at startup, so engaging it means setting
``AGENT_KILL_SWITCH_ENGAGED=true`` and RESTARTING the agent — it is NOT an instant
runtime lever, and it is NOT the automatic trust-based self-trust trip. The mesh
client's self-trust starts at 0.5 and only ever rises, so a trust-threshold rule
could never function as a kill-switch; an automatic downward-trust-degradation
signal remains a separately-tracked design item. The named ``GovernanceMiddleware``
from earlier designs is NOT used here. The fail-closed DATA-PATH controls above
(per-node ``_enforce`` default-deny + OpenFGA per-chunk ReBAC) are unchanged and
remain the real access-control boundary regardless of this gate.

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
    set_user_claims,
    start_approval,
)
from agent.state import AgentState, FlowDecision
from config import settings
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
    user_claims: dict | None = None,
    task_id: str = "",
    context_id: str = "",
) -> dict[str, Any]:
    """Run the governed agent graph for a single query.

    The user's identity claims are injected into a ContextVar before the graph runs
    so they are never stored in AgentState, LangGraph snapshots, or telemetry traces.

    Args:
        query:       Natural-language query from the user.
        user_id:     Verified authorization principal (token_validator.principal()).
        user_claims: Minimal VALIDATED identity claims (sub/email/email_verified/iss)
                     for cross-division forwarding — NOT a bearer token. Only the
                     originating /query path supplies these; a peer-received query
                     (no onward forwarding) passes None. Stored ONLY in the ContextVar.
        task_id:     A2A / ANP task identifier; a UUID4 is generated if empty.
        context_id:  Conversation / session identifier.

    Returns:
        Dict with at minimum ``answer`` (str) and ``status_message`` (str).
    """
    # Inject the user's identity claims into the ContextVar — never into state
    set_user_claims(user_claims or {})

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

    # AGT governance gate (kill-switch) — every graph invocation is checked by the
    # AgentMesh governance engine (AgentMeshClient.execute_with_governance) and
    # recorded in its audit log. The mesh client carries a real policy
    # (_GRAPH_GOVERNANCE_POLICY) whose only deny rule fires on `kill_switch_engaged`,
    # so when an operator has set AGENT_KILL_SWITCH_ENGAGED=true this DENIES the
    # invocation before any node runs (and before the graph is compiled). This is a
    # deploy-time operator off-switch (settings is read once at startup → restart to
    # engage), NOT a data-authorization control — see the module docstring. The raised
    # PermissionError is caught inside the request handlers (SSE error event on /query;
    # signed status="failed" on /a2a/query) — the guarantee is the early denial before
    # any node/retrieval/LLM, not a particular HTTP status code.
    gov = await govern_action(
        "agent.graph.invoke",
        {
            "user_id": user_id,
            "task_id": initial_state["task_id"],
            "kill_switch_engaged": settings.agent_kill_switch_engaged,
        },
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
