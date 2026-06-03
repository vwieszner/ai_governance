"""
LangGraph node implementations for the federated RAG agent.

Fixes applied:
  C-5  — user_token / delegated_token never stored in AgentState; passed via
          contextvars so they are invisible to Langfuse, tracing, and serialisation.
  C-6  — Temporal client is a module-level singleton protected by asyncio.Lock;
          no new gRPC connection is opened per workflow start.
  H-1  — Auth routing: pending_approval is now checked before allowed, ensuring
          approval is always started for chunks that require it. Remote is tried
          whenever there are no locally allowed/pending chunks and a peer is set.
  H-2  — All async singletons protected by asyncio.Lock (double-checked locking).
  M-4  — LLM context is capped at settings.llm_context_token_budget tokens
          (estimated as characters / 4) before calling the model.
  Q-5  — original_len saved before context is truncated, so the log entry
          records the pre-truncation length (not post-truncation + footer length).
  R-2  — handle_peer_result validates that delegated token is non-empty before
          calling the peer A2A endpoint.
  R-4  — start_approval handles WorkflowAlreadyStartedError from Temporal so
          duplicate workflow starts are treated as idempotent no-ops.
  S-8  — All four synchronous singletons (_qdrant, _graph, _openfga, _llm) are
          now async and protected by asyncio.Lock with double-checked locking,
          matching the pattern already used for the Temporal client.

Nodes:
  retrieve_local      — Qdrant hybrid + Neo4j GraphRAG
  check_auth          — OpenFGA decisions for retrieved chunks
  generate_answer     — LLM answer generation from allowed chunks
  start_approval      — Temporal workflow for local approval
  call_peer_agent     — A2A call to peer cluster
  handle_peer_result  — Process peer agent response
  format_response     — Final response formatting
"""
from __future__ import annotations

import asyncio
import contextvars
import re
import uuid
from typing import Any

import structlog
from langchain_openai import ChatOpenAI
from temporalio.client import Client as TemporalClient
from temporalio.exceptions import WorkflowAlreadyStartedError

from a2a.client import A2AClient
from agent.state import AgentState, FlowDecision
from auth.openfga import AuthzDecision, OpenFGAAuth
from auth.token_exchange import exchange_token
from config import settings
from rag.fusion import rrf_fuse
from rag.neo4j_retriever import GraphRAGRetriever
from rag.qdrant_retriever import HybridQdrantRetriever
from workflow.approval import ApprovalInput, ApprovalWorkflow

log = structlog.get_logger(__name__)

# ── Context vars for sensitive tokens (C-5) ───────────────────────────────────
# These are never stored in AgentState, Langfuse traces, or Temporal history.
_user_token_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "user_token", default=""
)
_delegated_token_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "delegated_token", default=""
)


def set_user_token(token: str) -> None:
    """Called once per request (in run_query) before the graph is invoked."""
    _user_token_ctx.set(token)


# ── Output DLP: credential-leak HARD-DENY (task #10, OWASP ASI-05) ────────────
#
# Post-LLM output safety control. Scans the final answer for credential/secret
# material; on a hit the ENTIRE answer is withheld (replaced with a generic safe
# message) before it leaves the agent — never returned partially redacted. This
# is the fail-closed posture chosen for task #10: a partial redaction could leave
# a regex-evaded fragment of the secret in the returned text; withholding cannot.
# Applied at format_response — the single universal output choke point that every
# terminal route (local answer AND cross-cluster peer answer) passes through.
#
# This solution intentionally has NO dependency on the AGT governance toolkit
# (agent_os / agentmesh), so the detection is a small self-contained scanner. The
# pattern set is kept BYTE-IDENTICAL to the AGT solution's
# `block-credential-leak-in-output` policy regex (agt-federated-rag/agent/policies/
# data-access-policy.yaml) so both solutions block exactly the same secret formats.
# Keep the two in sync if either changes.
#
# TIGHT patterns (fail-safe is non-negotiable — must NOT block a legitimate
# answer): each branch is a specific, structured secret format. The
# api_key/secret/password branch requires an explicit `= value` / `: value`
# assignment, so a legitimate answer that merely discusses infra/auth topology, a
# retention policy, or financials — even one that uses the words "secret"/"token"
# in prose — is NOT blocked. PII (emails / IPs / SSNs) is deliberately not matched.
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")),
    (
        "key_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|secret|password)\b\s*[:=]\s*\S{6,}"
        ),
    ),
]

# Generic message returned in place of any answer that trips a credential pattern.
_CREDENTIAL_BLOCK_MESSAGE = (
    "The response was withheld because it appeared to contain sensitive credential "
    "material. Please contact an administrator if you believe this is an error."
)


def detect_credentials(answer: str | None) -> list[str]:
    """Return the names of any credential patterns found in the answer (else [])."""
    if not answer:
        return []
    return [name for name, pattern in _CREDENTIAL_PATTERNS if pattern.search(answer)]


# ── Async-safe singletons (H-2 + S-8) ────────────────────────────────────────
#
# All singletons use double-checked locking with asyncio.Lock so that
# concurrent coroutines starting at the same time (e.g., two requests at
# cold-start) do not race and create duplicate heavyweight objects.

_qdrant: HybridQdrantRetriever | None = None
_graph: GraphRAGRetriever | None = None
_openfga: OpenFGAAuth | None = None
_llm: ChatOpenAI | None = None
_temporal_client: TemporalClient | None = None

_qdrant_lock: asyncio.Lock = asyncio.Lock()
_graph_lock: asyncio.Lock = asyncio.Lock()
_openfga_lock: asyncio.Lock = asyncio.Lock()
_llm_lock: asyncio.Lock = asyncio.Lock()
_temporal_lock: asyncio.Lock = asyncio.Lock()


async def _get_qdrant() -> HybridQdrantRetriever:
    """S-8: async singleton with double-checked locking."""
    global _qdrant
    if _qdrant is not None:
        return _qdrant
    async with _qdrant_lock:
        if _qdrant is None:
            _qdrant = HybridQdrantRetriever()
    return _qdrant


async def _get_graph() -> GraphRAGRetriever:
    """S-8: async singleton with double-checked locking."""
    global _graph
    if _graph is not None:
        return _graph
    async with _graph_lock:
        if _graph is None:
            _graph = GraphRAGRetriever()
    return _graph


async def _get_openfga() -> OpenFGAAuth:
    """S-8: async singleton with double-checked locking."""
    global _openfga
    if _openfga is not None:
        return _openfga
    async with _openfga_lock:
        if _openfga is None:
            _openfga = OpenFGAAuth()
    return _openfga


async def _get_llm() -> ChatOpenAI:
    """S-8: async singleton with double-checked locking."""
    global _llm
    if _llm is not None:
        return _llm
    async with _llm_lock:
        if _llm is None:
            _llm = ChatOpenAI(
                model=settings.llm_model,
                openai_api_base=settings.openai_api_base,
                openai_api_key=settings.openai_api_key,
                temperature=settings.llm_temperature,
                max_tokens=settings.llm_max_tokens,
                timeout=settings.llm_timeout_seconds,
                max_retries=settings.llm_max_retries,
            )
    return _llm


async def _get_temporal() -> TemporalClient:
    """
    Singleton Temporal client — acquired once and reused (C-6 / H-2 fix).
    Uses double-checked locking so concurrent coroutines don't race.
    """
    global _temporal_client
    if _temporal_client is not None:
        return _temporal_client
    async with _temporal_lock:
        if _temporal_client is None:
            _temporal_client = await TemporalClient.connect(
                settings.temporal_address,
                namespace=settings.temporal_namespace,
            )
    return _temporal_client


# ── Node: retrieve_local ──────────────────────────────────────────────────────

async def retrieve_local(state: AgentState) -> dict[str, Any]:
    """Run hybrid Qdrant + GraphRAG retrieval (no ACL filter yet)."""
    # L3-2: log query_len only at DEBUG — the query itself may contain PII and
    # would otherwise appear in OTEL/Langfuse telemetry at INFO level.
    log.debug("node_retrieve_local", query_len=len(state["query"]))
    query = state["query"]

    qdrant_results = await (await _get_qdrant()).retrieve(query)
    graph_results = await (await _get_graph()).retrieve_context(query)

    # Fuse with RRF
    fused = rrf_fuse(qdrant_results, graph_results, final_limit=settings.qdrant_final_k)

    return {
        "qdrant_results": qdrant_results,
        "graph_results": graph_results,
        "fused_chunks": fused,
    }


# ── Node: check_auth ──────────────────────────────────────────────────────────

async def check_auth(state: AgentState) -> dict[str, Any]:
    """
    Check OpenFGA authorization for each fused chunk.
    Classifies chunks into: allowed / pending_approval / denied.
    Determines the flow decision.

    FIX H-1: pending is now evaluated before allowed, ensuring that approval
    is always started when any chunk requires it.  Remote is tried whenever
    there are no locally serveable chunks and a peer cluster is configured.
    """
    # NIT-1: user_id is an OIDC sub (may look like an email) — log at DEBUG not INFO
    log.debug("node_check_auth", user_id=state["user_id"])
    auth = await _get_openfga()
    user_id = state["user_id"]
    fused = state["fused_chunks"]

    chunk_ids = [c["chunk_id"] for c in fused if c.get("chunk_id")]
    # L-5: guard against empty chunk_ids — batch_decide with an empty list is a
    # no-op but makes the logic below cleaner, and avoids a spurious OpenFGA call.
    if not chunk_ids:
        return {
            "flow": FlowDecision.REMOTE if (not fused and settings.peer_agent_url) else FlowDecision.LOCAL_DENIED,
            "allowed_chunk_ids": [],
            "pending_chunk_ids": [],
            "denied_chunk_ids": [],
        }
    decisions = await auth.batch_decide(user_id, chunk_ids)

    allowed = [cid for cid, d in decisions.items() if d == AuthzDecision.ALLOWED]
    pending = [cid for cid, d in decisions.items() if d == AuthzDecision.NEEDS_APPROVAL]
    denied  = [cid for cid, d in decisions.items() if d == AuthzDecision.DENIED]

    # FIX H-1: prioritise pending over allowed, and always try peer when no
    # locally-allowed data exists (empty results also route to REMOTE).
    #
    # MED-4: REMOTE is correct only when the local retriever found NO results
    # at all (fused is empty).  When we did find local chunks but they are ALL
    # denied, the data is local — routing to the peer leaks what the user is
    # querying and wastes a cross-cluster round-trip the peer will also deny.
    local_results_exist = bool(fused)
    if pending:
        # Some chunks require human approval — start workflow, don't serve anything yet
        flow = FlowDecision.LOCAL_NEEDS_APPROVAL
    elif allowed:
        flow = FlowDecision.LOCAL_ALLOWED
    elif not local_results_exist and settings.peer_agent_url:
        # No local data at all — ask the peer cluster
        flow = FlowDecision.REMOTE
    else:
        # Local data exists but user is denied for all of it
        flow = FlowDecision.LOCAL_DENIED

    log.info(
        "auth_decision",
        flow=flow,
        allowed=len(allowed),
        pending=len(pending),
        denied=len(denied),
    )

    # Finding #6: drop the *text* of denied chunks from state so unauthorised
    # content is not carried in the AgentState snapshot / Langfuse traces / OTEL
    # spans. generate_answer needs allowed-chunk text and start_approval needs
    # pending-chunk IDs — nothing downstream needs denied-chunk content, and the
    # raw qdrant/graph result lists are no longer used after fusion.
    serveable_ids = set(allowed) | set(pending)
    pruned_chunks = [c for c in fused if c.get("chunk_id") in serveable_ids]

    return {
        "flow": flow,
        "fused_chunks": pruned_chunks,
        "qdrant_results": [],
        "graph_results": [],
        "allowed_chunk_ids": allowed,
        "pending_chunk_ids": pending,
        "denied_chunk_ids": denied,
    }


# ── Node: generate_answer ─────────────────────────────────────────────────────

async def generate_answer(state: AgentState) -> dict[str, Any]:
    """
    Generate an answer from the allowed chunks using the LLM.

    FIX M-4: context is truncated to llm_context_token_budget characters
    (estimated as budget_tokens × 4) before calling the model.
    """
    log.info("node_generate_answer", user_id=state["user_id"])
    allowed_ids = set(state["allowed_chunk_ids"])
    context_chunks = [
        c for c in state["fused_chunks"] if c.get("chunk_id") in allowed_ids
    ]

    if not context_chunks:
        return {
            "answer": "I found relevant information but you do not have access to view it.",
            "status_message": "No accessible chunks.",
        }

    context = "\n\n---\n\n".join(
        f"[Source: {c.get('metadata', {}).get('source', 'unknown')}]\n{c['text']}"
        for c in context_chunks
    )

    # FIX M-4: guard against exceeding the model's context window
    # FIX Q-5: record original_len BEFORE truncation so the log shows the true
    #          pre-truncation size, not the (already-shortened) post-truncation length.
    max_chars = settings.llm_context_token_budget * 4   # ~4 chars per token
    original_len = len(context)
    if original_len > max_chars:
        context = context[:max_chars] + "\n\n[... context truncated to fit token budget ...]"
        log.warning("context_truncated", original_len=original_len, max_chars=max_chars)

    llm = await _get_llm()
    prompt = (
        f"You are a helpful assistant. Answer the user's question using ONLY the provided context.\n"
        f"If the context does not contain enough information, say so.\n\n"
        f"Context:\n{context}\n\n"
        f"Question: {state['query']}\n\n"
        f"Answer:"
    )

    response = await llm.ainvoke(prompt)
    answer = response.content if hasattr(response, "content") else str(response)

    return {"answer": answer, "status_message": "completed"}


# ── Node: start_approval ──────────────────────────────────────────────────────

async def start_approval(state: AgentState) -> dict[str, Any]:
    """
    Start a Temporal approval workflow for chunks that need approval.
    Writes pending_approval tuples to OpenFGA first.
    Returns immediately with a 'pending approval' status message.

    FIX C-6: reuses the module-level Temporal singleton via _get_temporal().
    """
    log.info("node_start_approval", user_id=state["user_id"])
    auth = await _get_openfga()
    user_id = state["user_id"]

    # H3-6: only start approval for PENDING chunks, never DENIED ones.
    # The DENIED state means the user has no relation on those chunks at all —
    # approving them via this workflow would create phantom access.
    # L-7: cap the chunk list size to prevent oversized Temporal workflow history
    # events.  Temporal serialises all activity inputs into its event log; a very
    # large chunk_ids list can push a single event over the 4 MB gRPC limit.
    _MAX_APPROVAL_CHUNKS = 50
    raw_chunk_ids = state["pending_chunk_ids"]
    chunk_ids = raw_chunk_ids[:_MAX_APPROVAL_CHUNKS]
    if len(raw_chunk_ids) > _MAX_APPROVAL_CHUNKS:
        log.warning(
            "approval_chunk_ids_capped",
            original=len(raw_chunk_ids),
            capped=_MAX_APPROVAL_CHUNKS,
        )
    if not chunk_ids:
        log.error("start_approval_no_pending_chunks", user_id=user_id)
        return {
            "approval_request_id": None,
            "status_message": "Internal error: no chunks require approval.",
            "answer": None,
            "error": "no_pending_chunks",
        }

    approval_request_id = str(uuid.uuid4())

    # Write pending_approval tuples to OpenFGA
    for chunk_id in chunk_ids:
        await auth.set_pending_approval(user_id, chunk_id)

    # Resolve approver from the first chunk's owner
    approver_id: str = "admin"
    for chunk_id in chunk_ids:
        owner = await auth.get_chunk_owner(chunk_id)
        if owner:
            approver_id = owner
            break

    # Start Temporal workflow (C-6: reuse singleton)
    temporal_client = await _get_temporal()
    try:
        await temporal_client.start_workflow(
            ApprovalWorkflow.run,
            ApprovalInput(
                approval_request_id=approval_request_id,
                user_id=user_id,
                chunk_ids=chunk_ids,
                query=state["query"],
                approver_id=approver_id,
                approver_slack_id=None,
                approver_email=None,
                # Q-7: snapshot timeout at start so replay is deterministic
                timeout_seconds=settings.approval_timeout_seconds,
            ),
            id=f"approval-{approval_request_id}",
            task_queue=settings.temporal_task_queue,
        )
    except WorkflowAlreadyStartedError:
        # R-4: idempotent — a duplicate start (e.g., retry) for the same
        # request ID is not an error; the existing workflow continues.
        log.warning(
            "approval_workflow_already_started",
            approval_request_id=approval_request_id,
        )

    return {
        "approval_request_id": approval_request_id,
        # L-6: do not echo the internal approval_request_id in the user-visible
        # status message.  The ID is an implementation detail; surfacing it lets
        # users probe for valid IDs and could be used to race the /approve endpoint.
        "status_message": (
            "Your request is pending approval. "
            "The approver has been notified. You will receive a notification once a "
            "decision is made."
        ),
        "answer": None,
    }


# ── Node: call_peer_agent ─────────────────────────────────────────────────────

async def call_peer_agent(state: AgentState) -> dict[str, Any]:
    """
    Perform RFC 8693 token exchange and send the query to the peer agent via A2A.

    FIX C-5: the raw user JWT is read from the context var (not from state) and
    the delegated token is stored in a context var — never in AgentState.
    """
    log.info("node_call_peer_agent", user_id=state["user_id"])
    if not settings.peer_agent_url:
        return {
            "error": "No peer agent configured.",
            "flow": FlowDecision.REMOTE_DENIED,
        }

    # C-5: read user token from context var, not from state
    user_token = _user_token_ctx.get()
    if not user_token:
        return {
            "error": "No user token in context — cannot perform token exchange.",
            "flow": FlowDecision.REMOTE_DENIED,
        }

    # RFC 8693 token exchange — audience is the peer's OAuth client_id (Keycloak
    # resolves audiences by client_id, not URL), validated against the allowlist.
    delegated = await exchange_token(
        user_token=user_token,
        target_audience=settings.peer_agent_audience,
    )

    # C-5: stash delegated token in context var, NOT in state
    _delegated_token_ctx.set(delegated.access_token)

    # A2A call
    client = A2AClient(base_url=str(settings.peer_agent_url))

    push_url = f"{settings.agent_url}/tasks/{state['task_id']}/callback"

    try:
        task = await client.send_task(
            query=state["query"],
            delegated_token=delegated.access_token,
            context_id=state["context_id"],
            push_notification_url=push_url,
        )
    except Exception as e:
        log.error("peer_a2a_call_failed", error=str(e))
        return {"error": str(e), "flow": FlowDecision.REMOTE_DENIED}
    finally:
        await client.close()

    # Extract the answer from the task we ALREADY received (send_task accumulates
    # the full task including history before returning). This avoids a second
    # get_task() round-trip in handle_peer_result, which would require the
    # delegated token to survive across LangGraph nodes — ContextVars do NOT
    # propagate across node boundaries, so that second fetch was failing with
    # "missing delegated token". The answer is in scope here; pass it via state.
    peer_answer = ""
    for msg in reversed(task.history or []):
        if msg.role == "agent":
            for part in msg.parts:
                if hasattr(part, "text") and part.text:
                    peer_answer = part.text
                    break
            if peer_answer:
                break

    return {
        "peer_task_id": task.id,
        "peer_status": task.status.state.value,
        "peer_answer": peer_answer,
        # delegated_token intentionally NOT stored in state (C-5)
    }


# ── Node: handle_peer_result ──────────────────────────────────────────────────

async def handle_peer_result(state: AgentState) -> dict[str, Any]:
    """
    Process the peer agent's A2A task result.

    The answer was already captured by call_peer_agent (from the SSE task it
    received) and passed via state["peer_answer"]. We do NOT re-fetch from the
    peer here: that required the delegated token to survive across LangGraph
    nodes, but ContextVars do not propagate across node boundaries.
    """
    peer_status = state.get("peer_status", "")
    log.info("node_handle_peer_result", peer_status=peer_status)

    if peer_status == "completed":
        answer = state.get("peer_answer") or ""
        if not answer:
            log.warning("handle_peer_result_empty_answer", peer_task_id=state.get("peer_task_id"))
            return {
                "flow": FlowDecision.REMOTE_DENIED,
                "status_message": "Peer agent completed but returned no answer.",
                "answer": None,
            }
        return {
            "peer_answer": answer,
            "answer": answer,
            "flow": FlowDecision.REMOTE_APPROVED,
            "status_message": "completed",
        }

    elif peer_status == "input-required":
        return {
            "flow": FlowDecision.REMOTE_NEEDS_APPROVAL,
            "status_message": (
                "The information you requested is on the remote cluster and requires "
                "approval from the data owner there. You will be notified once a "
                "decision is made."
            ),
            "answer": None,
        }

    else:
        return {
            "flow": FlowDecision.REMOTE_DENIED,
            "status_message": f"Remote agent returned status: {peer_status}",
            "answer": None,
        }


# ── Node: format_response ─────────────────────────────────────────────────────

async def format_response(state: AgentState) -> dict[str, Any]:
    """Final formatting — ensure answer and status_message are set."""
    answer = state.get("answer") or state.get("peer_answer")
    status = state.get("status_message", "")
    error = state.get("error")

    if error:
        # LOW-1: never surface raw exception strings (hostnames, ports, stack
        # frames) to the end user — log internally and return a generic message.
        log.warning("format_response_error", raw_error=error)
        return {
            "answer": "An error occurred while processing your request. Please try again.",
            "status_message": "error",
        }
    if not answer:
        answer = status or "I could not find an answer to your query."

    # Output DLP (task #10, HARD-DENY): scan the OUTGOING answer for credential
    # material before it leaves the agent. This is the single universal output
    # choke point — every terminal route (local answer AND cross-cluster peer
    # answer) passes through here, so a peer-sourced secret is caught without
    # trusting the peer. On a hit, withhold the ENTIRE answer (fail-closed) rather
    # than return a partial redaction that might leak a regex-evaded fragment.
    detected = detect_credentials(answer)
    if detected:
        log.warning(
            "output_credential_blocked",
            credential_types=detected,   # type names only — never the secret value
            count=len(detected),
        )
        return {
            "answer": _CREDENTIAL_BLOCK_MESSAGE,
            "status_message": "blocked_credential_leak",
        }

    return {"answer": answer, "status_message": status or "completed"}
