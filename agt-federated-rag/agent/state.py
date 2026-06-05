"""LangGraph agent state definition for the AGT federated RAG system.

Design notes:

FlowDecision enum
    The seven-state enum cleanly expresses the full decision matrix.  Using a
    str-enum means FlowDecision values serialise naturally to JSON (Langfuse
    traces, Temporal history) without a custom encoder.

AgentState TypedDict
    Security boundary: user_token is NEVER stored in state.  It lives only in
    the ``_user_token_ctx`` ContextVar in nodes.py.  This keeps raw bearer tokens
    out of LangGraph's internal snapshot, Langfuse traces, and any telemetry sink.

No Annotated reducers on list fields
    This graph is purely sequential; there are no parallel branches.  Adding
    operator.add reducers would change "replace" semantics to "accumulate"
    semantics for every update, breaking nodes like check_auth whose
    allowed_chunk_ids must be set fresh on each invocation.

Field grouping follows the data-flow pipeline:
    input → retrieval → auth → generation → peer → approval → output

Security contract
    ``user_token`` is intentionally absent from AgentState.  The raw bearer
    token is passed to ``run_query`` and stashed in ``_user_token_ctx``
    (a ``contextvars.ContextVar``) before the graph is invoked.  It is never
    serialised into this TypedDict, ensuring it cannot appear in LangGraph
    snapshots, Langfuse traces, or any structured log that ships state dicts.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from typing_extensions import TypedDict


class FlowDecision(str, Enum):
    """Complete decision space for the four-flow authorization matrix."""

    LOCAL_ALLOWED = "local_allowed"
    LOCAL_NEEDS_APPROVAL = "local_needs_approval"
    LOCAL_DENIED = "local_denied"
    REMOTE = "remote"                              # no local data → ask peer cluster
    REMOTE_APPROVED = "remote_approved"            # peer returned a completed answer
    REMOTE_NEEDS_APPROVAL = "remote_needs_approval"  # peer returned input-required
    REMOTE_DENIED = "remote_denied"                # peer rejected / circuit open / error


class AgentState(TypedDict):
    """Full mutable state threaded through every LangGraph node.

    Every field has an explicit type so that static analysis (mypy --strict)
    and LangGraph's internal schema validator can catch programming errors at
    development time rather than at runtime inside a live request.
    """

    # ── Input ─────────────────────────────────────────────────────────────────
    query: str
    user_id: str
    task_id: str          # A2A / ANP task ID (caller-supplied or uuid4-generated)
    context_id: str       # conversation context / session ID

    # ── RAG retrieval ─────────────────────────────────────────────────────────
    fused_chunks: list[dict[str, Any]]      # RRF-fused output from both retrievers
    qdrant_results: list[dict[str, Any]]    # raw hybrid Qdrant results
    graph_results: list[dict[str, Any]]     # raw Neo4j graph-seam results (currently inert → empty)

    # ── Authorization ─────────────────────────────────────────────────────────
    flow: FlowDecision | None               # set by check_auth; None before that node
    allowed_chunk_ids: list[str]
    pending_chunk_ids: list[str]
    denied_chunk_ids: list[str]

    # ── Output ────────────────────────────────────────────────────────────────
    answer: str | None
    peer_answer: str | None                 # answer received from the peer cluster
    status_message: str                     # human-readable status; always a str

    # ── Approval workflow ─────────────────────────────────────────────────────
    approval_request_id: str | None         # UUID set by start_approval node

    # ── Cross-cluster peer ────────────────────────────────────────────────────
    peer_task_id: str | None                # task ID on the remote peer cluster
    peer_status: str | None                 # AGT PeerResponse.status string

    # ── Diagnostics ───────────────────────────────────────────────────────────
    error: str | None                       # internal error — never surfaced raw to user
