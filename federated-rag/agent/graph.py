"""
LangGraph agent graph — wires together all 4 authorization flows.

Flow A — Local + authorized:
  retrieve_local → check_auth → generate_answer → format_response

Flow B — Local + needs approval:
  retrieve_local → check_auth → start_approval → format_response

Flow C — Remote + authorized:
  retrieve_local → check_auth → call_peer_agent → handle_peer_result → format_response

Flow D — Remote + needs approval (cross-cluster):
  retrieve_local → check_auth → call_peer_agent → handle_peer_result → format_response
  (peer returns input-required; we surface the pending status to the user)

Flow E — Local denied (no peer):
  retrieve_local → check_auth → format_response
"""
from __future__ import annotations

from langgraph.graph import END, StateGraph

from agent.nodes import (
    check_auth,
    call_peer_agent,
    format_response,
    generate_answer,
    handle_peer_result,
    retrieve_local,
    start_approval,
)
from agent.state import AgentState, FlowDecision


# ── Routing functions ─────────────────────────────────────────────────────────

def route_after_auth(state: AgentState) -> str:
    flow = state.get("flow")
    if flow == FlowDecision.LOCAL_ALLOWED:
        return "generate_answer"
    elif flow == FlowDecision.LOCAL_NEEDS_APPROVAL:
        return "start_approval"
    elif flow == FlowDecision.REMOTE:
        return "call_peer_agent"
    else:
        # LOCAL_DENIED with no peer configured
        return "format_response"


def route_after_peer_call(state: AgentState) -> str:
    if state.get("error"):
        return "format_response"
    return "handle_peer_result"


# ── Build the graph ───────────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    # Register nodes
    graph.add_node("retrieve_local", retrieve_local)
    graph.add_node("check_auth", check_auth)
    graph.add_node("generate_answer", generate_answer)
    graph.add_node("start_approval", start_approval)
    graph.add_node("call_peer_agent", call_peer_agent)
    graph.add_node("handle_peer_result", handle_peer_result)
    graph.add_node("format_response", format_response)

    # Entry point
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
        route_after_auth,
        {
            "generate_answer": "generate_answer",
            "start_approval": "start_approval",
            "call_peer_agent": "call_peer_agent",
            "format_response": "format_response",
        },
    )
    graph.add_conditional_edges(
        "call_peer_agent",
        route_after_peer_call,
        {
            "handle_peer_result": "handle_peer_result",
            "format_response": "format_response",
        },
    )

    return graph


# Compiled graph (singleton)
_compiled = None


def get_compiled_graph():
    global _compiled
    if _compiled is None:
        _compiled = build_graph().compile()
    return _compiled


# ── Convenience runner ────────────────────────────────────────────────────────

async def run_query(
    query: str,
    user_id: str,
    user_token: str,
    task_id: str = "",
    context_id: str = "",
) -> AgentState:
    """
    Run the agent graph for a single query.

    Returns the final AgentState with `answer` and `status_message` populated.
    """
    import uuid
    initial_state: AgentState = {
        "query": query,
        "user_id": user_id,
        "user_token": user_token,
        "task_id": task_id or str(uuid.uuid4()),
        "context_id": context_id,
        "flow": None,
        "allowed_chunk_ids": [],
        "denied_chunk_ids": [],
        "pending_chunk_ids": [],
        "qdrant_results": [],
        "graph_results": [],
        "fused_chunks": [],
        "peer_task_id": None,
        "peer_status": None,
        "peer_answer": None,
        "delegated_token": None,
        "approval_request_id": None,
        "approval_decision": None,
        "answer": None,
        "status_message": None,
        "error": None,
        "messages": [],
        "iterations": 0,
    }

    graph = get_compiled_graph()
    final_state: AgentState = await graph.ainvoke(initial_state)
    return final_state
