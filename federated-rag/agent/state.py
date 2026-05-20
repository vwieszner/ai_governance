"""LangGraph agent state definition.

FIX C-5: user_token and delegated_token removed from state — they are never
stored in the graph's serialised snapshot, Langfuse traces, or Temporal history.
Both are passed via contextvars (see agent/nodes.py).

LG-1 NOTE — no Annotated reducers on list fields:
    This graph is purely sequential; there are no parallel branches.  Adding
    operator.add reducers would change "replace" semantics to "accumulate"
    semantics for every state update, which would break nodes like check_auth
    (its allowed_chunk_ids update would append to the previous run's list rather
    than replacing it).  If parallel nodes are added in the future, add
    Annotated[list[...], operator.add] reducers only to fields that are meant
    to be accumulated across concurrent node executions.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from typing_extensions import TypedDict


class FlowDecision(str, Enum):
    LOCAL_ALLOWED = "local_allowed"
    LOCAL_NEEDS_APPROVAL = "local_needs_approval"
    LOCAL_DENIED = "local_denied"
    REMOTE = "remote"                        # data lives on peer cluster
    REMOTE_APPROVED = "remote_approved"
    REMOTE_NEEDS_APPROVAL = "remote_needs_approval"
    REMOTE_DENIED = "remote_denied"


class AgentState(TypedDict):
    # Input
    query: str
    user_id: str
    # NOTE: user_token is NOT stored here — use _user_token_ctx in nodes.py
    task_id: str                             # A2A task ID
    context_id: str

    # Auth
    flow: FlowDecision | None
    allowed_chunk_ids: list[str]
    denied_chunk_ids: list[str]
    pending_chunk_ids: list[str]

    # RAG results
    qdrant_results: list[dict[str, Any]]
    graph_results: list[dict[str, Any]]
    fused_chunks: list[dict[str, Any]]

    # Cross-cluster
    peer_task_id: str | None
    peer_status: str | None                  # A2A task state from peer
    peer_answer: str | None
    # NOTE: delegated_token is NOT stored here — use _delegated_token_ctx in nodes.py

    # Approval workflow
    approval_request_id: str | None
    approval_decision: str | None            # "approved" | "denied" | "timeout"

    # Output
    answer: str | None
    status_message: str | None               # human-readable status for the user
    error: str | None

    # Control
    messages: list[dict[str, Any]]           # LangChain message history
    iterations: int
