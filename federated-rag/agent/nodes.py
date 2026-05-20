"""
LangGraph node implementations for the federated RAG agent.

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

import uuid
from typing import Any

import structlog
from langchain_openai import ChatOpenAI
from temporalio.client import Client as TemporalClient

from agent.state import AgentState, FlowDecision
from auth.openfga import AuthzDecision, OpenFGAAuth
from auth.token_exchange import exchange_token, validate_token, extract_user_id
from config import settings
from rag.fusion import rrf_fuse
from rag.neo4j_retriever import GraphRAGRetriever
from rag.qdrant_retriever import HybridQdrantRetriever

log = structlog.get_logger(__name__)

# Singletons (initialised lazily)
_qdrant: HybridQdrantRetriever | None = None
_graph: GraphRAGRetriever | None = None
_openfga: OpenFGAAuth | None = None
_llm: ChatOpenAI | None = None


def _get_qdrant() -> HybridQdrantRetriever:
    global _qdrant
    if _qdrant is None:
        _qdrant = HybridQdrantRetriever()
    return _qdrant


def _get_graph() -> GraphRAGRetriever:
    global _graph
    if _graph is None:
        _graph = GraphRAGRetriever()
    return _graph


def _get_openfga() -> OpenFGAAuth:
    global _openfga
    if _openfga is None:
        _openfga = OpenFGAAuth()
    return _openfga


def _get_llm() -> ChatOpenAI:
    global _llm
    if _llm is None:
        _llm = ChatOpenAI(
            model=settings.llm_model,
            openai_api_base=settings.openai_api_base,
            openai_api_key=settings.openai_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )
    return _llm


# ── Node: retrieve_local ──────────────────────────────────────────────────────

async def retrieve_local(state: AgentState) -> dict[str, Any]:
    """Run hybrid Qdrant + GraphRAG retrieval (no ACL filter yet)."""
    log.info("node_retrieve_local", query=state["query"][:80])
    query = state["query"]

    qdrant_results = await _get_qdrant().retrieve(query)
    graph_results = await _get_graph().retrieve_context(query)

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
    """
    log.info("node_check_auth", user_id=state["user_id"])
    auth = _get_openfga()
    user_id = state["user_id"]
    fused = state["fused_chunks"]

    chunk_ids = [c["chunk_id"] for c in fused if c.get("chunk_id")]
    decisions = await auth.batch_decide(user_id, chunk_ids)

    allowed = [cid for cid, d in decisions.items() if d == AuthzDecision.ALLOWED]
    pending = [cid for cid, d in decisions.items() if d == AuthzDecision.NEEDS_APPROVAL]
    denied  = [cid for cid, d in decisions.items() if d == AuthzDecision.DENIED]

    # Determine flow
    if allowed:
        flow = FlowDecision.LOCAL_ALLOWED
    elif pending:
        flow = FlowDecision.LOCAL_NEEDS_APPROVAL
    elif denied and settings.peer_agent_url:
        # Nothing locally — try peer cluster
        flow = FlowDecision.REMOTE
    else:
        flow = FlowDecision.LOCAL_DENIED

    log.info(
        "auth_decision",
        flow=flow,
        allowed=len(allowed),
        pending=len(pending),
        denied=len(denied),
    )

    return {
        "flow": flow,
        "allowed_chunk_ids": allowed,
        "pending_chunk_ids": pending,
        "denied_chunk_ids": denied,
    }


# ── Node: generate_answer ─────────────────────────────────────────────────────

async def generate_answer(state: AgentState) -> dict[str, Any]:
    """Generate an answer from the allowed chunks using the LLM."""
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

    llm = _get_llm()
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
    """
    log.info("node_start_approval", user_id=state["user_id"])
    auth = _get_openfga()
    user_id = state["user_id"]
    chunk_ids = state["pending_chunk_ids"] or state["denied_chunk_ids"]

    approval_request_id = str(uuid.uuid4())

    # Write pending_approval tuples to OpenFGA
    for chunk_id in chunk_ids:
        await auth.set_pending_approval(user_id, chunk_id)

    # Resolve approver from the first chunk's owner
    approver_id = None
    for chunk_id in chunk_ids:
        approver_id = await auth.get_chunk_owner(chunk_id)
        if approver_id:
            break
    approver_id = approver_id or "admin"

    # Start Temporal workflow
    from workflow.approval import ApprovalInput, ApprovalWorkflow
    temporal_client = await TemporalClient.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
    )
    await temporal_client.start_workflow(
        ApprovalWorkflow.run,
        ApprovalInput(
            approval_request_id=approval_request_id,
            user_id=user_id,
            chunk_ids=chunk_ids,
            query=state["query"],
            approver_id=approver_id,
            approver_slack_id=None,   # TODO: resolve from user directory
            approver_email=None,
        ),
        id=f"approval-{approval_request_id}",
        task_queue=settings.temporal_task_queue,
    )

    return {
        "approval_request_id": approval_request_id,
        "status_message": (
            f"Your request is pending approval (request ID: {approval_request_id}). "
            f"The approver has been notified. You will receive a notification once a decision is made."
        ),
        "answer": None,
    }


# ── Node: call_peer_agent ─────────────────────────────────────────────────────

async def call_peer_agent(state: AgentState) -> dict[str, Any]:
    """
    Perform RFC 8693 token exchange and send the query to the peer agent via A2A.
    """
    log.info("node_call_peer_agent", user_id=state["user_id"])
    if not settings.peer_agent_url:
        return {
            "error": "No peer agent configured.",
            "flow": FlowDecision.REMOTE_DENIED,
        }

    # RFC 8693 token exchange
    delegated = await exchange_token(
        user_token=state["user_token"],
        target_audience=str(settings.peer_agent_url),
    )

    # A2A call (non-streaming for simplicity; streaming variant available)
    from a2a.client import A2AClient
    client = A2AClient(base_url=str(settings.peer_agent_url))

    # Provide a push notification URL so the peer can call us back if approval is needed
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

    return {
        "peer_task_id": task.id,
        "peer_status": task.status.state.value,
        "delegated_token": delegated.access_token,
    }


# ── Node: handle_peer_result ──────────────────────────────────────────────────

async def handle_peer_result(state: AgentState) -> dict[str, Any]:
    """
    Process the peer agent's A2A task result.
    Determines whether we got an answer, need to wait for approval, or were denied.
    """
    peer_status = state.get("peer_status", "")
    log.info("node_handle_peer_result", peer_status=peer_status)

    if peer_status == "completed":
        # Peer returned an answer — extract it from the task history
        # (In a streaming scenario we'd have it already; here we poll)
        from a2a.client import A2AClient
        client = A2AClient(base_url=str(settings.peer_agent_url))
        task = await client.get_task(
            task_id=state["peer_task_id"],
            delegated_token=state["delegated_token"],
        )
        await client.close()

        # Extract text from last agent message
        answer = ""
        for msg in reversed(task.history or []):
            if msg.role == "agent":
                for part in msg.parts:
                    if hasattr(part, "text"):
                        answer = part.text
                        break
                if answer:
                    break

        return {
            "peer_answer": answer,
            "answer": answer,
            "flow": FlowDecision.REMOTE_APPROVED,
            "status_message": "completed",
        }

    elif peer_status == "input-required":
        # Peer needs approval
        return {
            "flow": FlowDecision.REMOTE_NEEDS_APPROVAL,
            "status_message": (
                "The information you requested is on the remote cluster and requires approval from "
                "the data owner there. You will be notified once a decision is made."
            ),
            "answer": None,
        }

    else:
        # failed, canceled, or unknown
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
        return {"answer": f"Error: {error}", "status_message": "error"}
    if not answer:
        answer = status or "I could not find an answer to your query."

    return {"answer": answer, "status_message": status or "completed"}
