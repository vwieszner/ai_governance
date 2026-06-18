"""LangGraph node implementations for the AGT federated RAG agent.

Every node enforces AGT policies via ``_enforce()`` before doing any work.
This is not optional — it is the primary OWASP Agentic Top-10 control layer.

Security controls applied per node:
    retrieve_local      — ``rag.retrieve``        (ASI-02, ASI-06)
    check_auth          — ``auth.check_permission``(ASI-03)
    generate_answer     — ``llm.generate``         (ASI-05)
    start_approval      — ``approval.start_workflow``(ASI-02)
    call_peer_agent     — ``peer.send_message``    (ASI-07, ASI-08)
    handle_peer_result  — ``peer.receive_callback``
    format_response     — ``agent.format_response``(ASI-05)

Design decisions:

_enforce() pattern
    Every node calls ``_enforce(action, context)`` which delegates to the AGT
    PolicyEvaluator loaded from ``settings.policy_dir``.  A ``PermissionError``
    raised inside any node causes LangGraph to surface an error state which
    ``format_response`` converts to a safe, generic user message.

Singleton double-checked locking
    _qdrant, _graph, _openfga, _llm, _temporal_client each have a matching
    asyncio.Lock.  The outer ``if singleton is not None`` check is a fast path
    for the steady state (no lock contention); the inner check inside the lock
    prevents duplicate init when multiple coroutines race at cold-start.

user_token ContextVar (security boundary)
    ``_user_token_ctx`` is a module-level ContextVar; the token is injected by
    ``run_query`` before the graph runs.  It is never stored in AgentState so it
    cannot appear in LangGraph snapshots, Langfuse traces, or Temporal history.

L-5 fix — empty chunk_ids guard in check_auth
    ``batch_decide`` is called only when ``chunk_ids`` is non-empty.  An empty
    fused list directly sets the flow to REMOTE (if a peer is configured) or
    LOCAL_DENIED, skipping the OpenFGA fan-out entirely.

L-6 fix — approval_request_id not leaked in status_message
    The user-visible status message in ``start_approval`` contains no internal
    identifiers that would let users probe the /approve endpoint.

L-7 fix — chunk_ids capped at 50 before Temporal
    Temporal serialises all activity inputs into its event history.  A very
    large chunk_ids list can push a single event over the 4 MB gRPC limit.

MED-4 fix — REMOTE only when fused is empty AND peer is configured
    When local chunks exist but the user is denied for all of them, the data is
    local — routing to the peer leaks query intent and wastes a cross-cluster
    round-trip the peer will also deny.

circuit breaker context
    ``call_peer_agent`` includes ``peer_circuit_state`` in the policy context so
    the peer-comms-policy can gate on ``CircuitState.OPEN`` before a gRPC call
    is even attempted.
"""
from __future__ import annotations

import asyncio
import contextvars
import re
import uuid
from typing import Any

import structlog
from agent_os.policies import PolicyEvaluator  # type: ignore[import]
from langchain_openai import ChatOpenAI
from temporalio.client import Client as TemporalClient
from temporalio.exceptions import WorkflowAlreadyStartedError

from agent.state import AgentState, FlowDecision
from auth.openfga import AuthzDecision, OpenFGAAuth
from config import settings
from mesh.agent_identity import verify_peer_identity
from mesh.peer_client import call_peer_agent as _mesh_call_peer, get_peer_circuit_state
from rag.fusion import rrf_fuse_many
from workflow.approval import ApprovalInput, ApprovalWorkflow

log = structlog.get_logger(__name__)

# ── User token ContextVar (security boundary) ─────────────────────────────────
# The user's VALIDATED identity claims (minimal subset — see
# token_validator.minimal_assertion_claims) for cross-division forwarding. NEVER
# stored in AgentState/logs; injected by run_query before the graph runs and read
# only by call_peer_agent when delegating to a peer. Security-hardened M2: we no
# longer hold the user's RAW bearer token here — only non-replayable identity claims,
# carried onward inside the DID-signed, replay-protected peer envelope.
_user_claims_ctx: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "user_claims", default={}
)


def set_user_claims(claims: dict) -> None:
    """Called once per request (in graph.run_query) before the graph is invoked."""
    _user_claims_ctx.set(claims or {})


# ── FR-3.4: observable inter-agent conversation marker ─────────────────────────
# The cross-division status_message is the only structured channel that reaches the
# UI (it rides the single `result` SSE event → MonitorPanel). When a query is
# DELEGATED we prepend a compact, machine-parseable marker carrying the discovered
# peer division + capability + how it was chosen, so MonitorPanel can render the
# discover → negotiate → delegate phases as first-class events instead of inferring
# them from arbitrary prose. The contained "delegated" keyword also keeps the UI's
# inferKind() classifier landing on the peer_call event kind. Format (single line):
#   [agt:delegated division=<id> cap=<cap> via=<discovered|configured-fallback> negotiated=<0|1>]
_DELEGATION_MARKER_PREFIX = "[agt:delegated"


# Marker-injection guard (A4): division/capability originate from a discovered peer's
# self-asserted control-plane fields, so a compromised-but-trusted peer can stuff marker
# control sequences into them — a ``]`` closes the marker early, a ``[`` opens a forged
# second marker, and a `` key=`` token injects fake fields (e.g. a forged
# ``negotiated=1 via=discovered`` trust signal) the UI would render. We strip the bracket
# delimiters entirely and neutralise any `` <word>=`` token by removing the ``=`` so it
# can no longer masquerade as a marker key. ``src`` and ``negotiated`` are agent-set
# (closed vocab), not peer-supplied, so they are not a vector — but sanitising the
# peer-supplied fields is the fix.
_MARKER_INJECT_RE = re.compile(r"\s+(\w+)=")


def _sanitize_marker_field(value: str) -> str:
    """Strip marker delimiters / key=value injection sequences from a peer-supplied field."""
    # Remove the bracket delimiters that frame a marker token, plus newlines/CR (the
    # marker is a single line). Then break any `` key=`` pair so it can't forge a field.
    cleaned = value.replace("[", "").replace("]", "").replace("\r", " ").replace("\n", " ")
    cleaned = _MARKER_INJECT_RE.sub(r" \1", cleaned)
    # Collapse runs of whitespace so the single-line marker stays compact + parseable.
    return re.sub(r"\s+", " ", cleaned).strip()


def _delegation_marker(summary: dict[str, Any] | None) -> str:
    """Build the structured FR-3.4 delegation marker from a discovery_summary, or ''."""
    if not summary:
        return ""
    division = _sanitize_marker_field(str(summary.get("division") or "peer")) or "peer"
    cap = _sanitize_marker_field(str(summary.get("capability") or ""))
    src = str(summary.get("source") or "")
    negotiated = "1" if summary.get("negotiated") else "0"
    return (
        f"{_DELEGATION_MARKER_PREFIX} division={division} cap={cap} "
        f"via={src} negotiated={negotiated}]"
    )


# ── AGT PolicyEvaluator singleton ─────────────────────────────────────────────

_evaluator: PolicyEvaluator | None = None
_evaluator_lock: asyncio.Lock = asyncio.Lock()


async def _get_evaluator() -> PolicyEvaluator:
    global _evaluator
    if _evaluator is not None:
        return _evaluator
    async with _evaluator_lock:
        if _evaluator is None:
            # Real agent_os API: construct, then load every *.yaml policy
            # document from the policy directory.
            ev = PolicyEvaluator()
            ev.load_policies(settings.policy_dir)
            _evaluator = ev
            log.info("agt_policy_evaluator_loaded", policy_dir=settings.policy_dir)
    return _evaluator


async def _enforce(action: str, context: dict[str, Any]) -> None:
    """Raise PermissionError if the AGT policy engine denies the action.

    This is the primary governance gate.  Every node calls this before doing
    any work.  The evaluator runs all YAML policies in settings.policy_dir in
    priority order; the highest-priority matching rule wins.
    """
    evaluator = await _get_evaluator()
    result = evaluator.evaluate({"action": action, **context})
    if not result.allowed:
        log.warning(
            "agt_policy_denied",
            action=action,
            reason=result.reason,
            agt_audit=True,
        )
        raise PermissionError(f"Policy denied action '{action}': {result.reason}")
    log.debug("agt_policy_allowed", action=action)


# ── Output DLP: credential-leak HARD-DENY (task #10, OWASP ASI-05) ────────────
#
# Post-LLM output safety control. format_response calls
# _enforce("agent.output_check", {"llm_output": answer}) on the OUTGOING answer.
# The `block-credential-leak-in-output` policy rule (data-access-policy.yaml,
# priority 950) matches a tight set of structured secret formats — AWS AKIA,
# PEM PRIVATE KEY block, OpenAI sk-…, Slack xox…, JWT eyJ…, and explicit
# api_key/secret/password = value assignments — and DENIES on a hit; a clean
# answer falls through to the priority-100 allow-output-check rule and passes.
#
# HARD-DENY (not redact): on detection the PermissionError propagates and the API
# layer returns the generic safe message — the whole answer is withheld rather
# than partially redacted. This is the fail-closed posture team-lead chose for
# task #10: a partial redaction could leave a regex-evaded fragment of the secret
# in the returned text, whereas withholding the answer cannot leak.
#
# This makes the previously-decorative rule LIVE (GOVERNANCE_AUDIT.md Item 3a):
# it never fired before because no node passed `llm_output`. The check runs at
# format_response — the single universal output choke point — so it covers BOTH
# locally-generated AND cross-cluster peer answers (generate_answer never sees
# peer answers, which arrive via handle_peer_result -> format_response).
#
# FAIL-SAFE: the patterns are deliberately tight (structured formats + explicit
# assignments) so a legitimate answer that merely discusses infra/auth topology,
# a retention policy, or financials — even one that uses the words "secret" or
# "token" in prose — is NOT blocked. See the policy file for the rule rationale.


# ── Service singletons (double-checked asyncio.Lock locking) ──────────────────

_retrievers: list[Any] | None = None    # the configured retriever fan-out (qdrant/neo4j/RaaS)
_openfga: OpenFGAAuth | None = None
_llm: ChatOpenAI | None = None
_intent_llm: ChatOpenAI | None = None
# Fast model for intent classification. llama-3.2-3b was unreliable on NVIDIA NIM's
# free tier (frequent ReadTimeouts); 3.1-8b is both faster in practice and reliable.
_INTENT_MODEL = "meta/llama-3.1-8b-instruct"
_temporal_client: TemporalClient | None = None

_retrievers_lock: asyncio.Lock = asyncio.Lock()
_openfga_lock: asyncio.Lock = asyncio.Lock()
_llm_lock: asyncio.Lock = asyncio.Lock()
_intent_llm_lock: asyncio.Lock = asyncio.Lock()
_temporal_lock: asyncio.Lock = asyncio.Lock()


async def _get_retrievers() -> list[Any]:
    """Build + cache the configured retriever fan-out (qdrant / neo4j seam / any
    RaaS). One-time ``setup()`` per retriever (collection/index/egress check).
    See rag/retriever.py for the governance contract."""
    global _retrievers
    if _retrievers is not None:
        return _retrievers
    async with _retrievers_lock:
        if _retrievers is None:
            from rag.retriever import build_retrievers

            insts = build_retrievers()
            await asyncio.gather(*[r.setup() for r in insts])
            _retrievers = insts
    return _retrievers


async def _get_openfga() -> OpenFGAAuth:
    global _openfga
    if _openfga is not None:
        return _openfga
    async with _openfga_lock:
        if _openfga is None:
            _openfga = await OpenFGAAuth.get_instance()
    return _openfga


async def _get_llm() -> ChatOpenAI:
    global _llm
    if _llm is not None:
        return _llm
    async with _llm_lock:
        if _llm is None:
            # M6/NFR-1: fail closed if local-residency would egress to an external LLM.
            from residency import assert_inference_allowed
            assert_inference_allowed(settings.openai_api_base, "LLM")
            _llm = ChatOpenAI(
                model=settings.llm_model,
                openai_api_base=settings.openai_api_base,
                openai_api_key=settings.openai_api_key,
                temperature=settings.llm_temperature,
                timeout=settings.llm_timeout_seconds,
                max_retries=settings.llm_max_retries,
            )
    return _llm


async def _get_intent_llm() -> ChatOpenAI:
    """Fast small LLM for intent classification only (YES/NO).

    Uses llama-3.2-3b — free tier on NVIDIA NIM, sub-second latency.
    """
    global _intent_llm
    if _intent_llm is not None:
        return _intent_llm
    async with _intent_llm_lock:
        if _intent_llm is None:
            # M6/NFR-1: fail closed if local-residency would egress to an external LLM.
            from residency import assert_inference_allowed
            assert_inference_allowed(settings.openai_api_base, "LLM")
            _intent_llm = ChatOpenAI(
                model=_INTENT_MODEL,
                openai_api_base=settings.openai_api_base,
                openai_api_key=settings.openai_api_key,
                temperature=0.0,
                # NOTE: this NVIDIA NIM endpoint rejects max_tokens with a 400, so omitted.
                timeout=20.0,
                max_retries=1,
            )
    return _intent_llm


async def _get_temporal() -> TemporalClient:
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
    """Run hybrid Qdrant retrieval, RRF-fused with the Neo4j graph-retrieval seam.

    The graph retriever is invoked but is INERT: AGT ingest never writes Neo4j, so
    its vector index doesn't exist and retrieve_context() returns [] — retrieval is
    Qdrant-only. (It is also plain vector lookup, not graph traversal.)

    AGT policy enforced: ``rag.retrieve``
    Context fields passed to the evaluator:
        query_length        — data-access-policy rejects queries >4096 chars
        qdrant_collection   — data-access-policy blocks untrusted collections
        user_id             — base-policy trust-score gate uses this
    """
    await _enforce(
        "rag.retrieve",
        {
            "query_length": len(state["query"]),
            "qdrant_collection": settings.qdrant_collection,
            "user_id": state["user_id"],
        },
    )

    log.debug("node_retrieve_local", query_len=len(state["query"]))
    query = state["query"]

    # Fan out across ALL configured retrievers (qdrant + neo4j seam + any RaaS).
    # Retrieve WITHOUT an ACL pre-filter (allowed_chunk_ids=None): per-chunk
    # authorization is decided next in check_auth via OpenFGA. Passing an empty
    # list here would build a MatchAny(any=[]) filter that matches zero points,
    # silently returning no results (the cause of the empty-answer bug).
    retrievers = await _get_retrievers()
    results_per_retriever = await asyncio.gather(*[r.retrieve(query) for r in retrievers])

    by_name = {r.name: res for r, res in zip(retrievers, results_per_retriever)}
    fused = rrf_fuse_many(results_per_retriever, final_limit=settings.qdrant_final_k)

    # Observability fields stay meaningful: qdrant_results = the qdrant backend's raw
    # hits; graph_results = every other retriever's hits (neo4j seam + any RaaS).
    # fused_chunks (built from ALL retrievers) is the source of truth for check_auth.
    qdrant_results = by_name.get("qdrant", [])
    graph_results = [c for name, res in by_name.items() if name != "qdrant" for c in res]

    log.info(
        "retrieve_local_done",
        retrievers=[r.name for r in retrievers],
        counts={name: len(res) for name, res in by_name.items()},
        fused_count=len(fused),
    )
    return {
        "qdrant_results": qdrant_results,
        "graph_results": graph_results,
        "fused_chunks": fused,
    }


# ── Node: check_auth ──────────────────────────────────────────────────────────

async def check_auth(state: AgentState) -> dict[str, Any]:
    """Batch-decide OpenFGA authorization for each fused chunk, set flow.

    AGT policy enforced: ``auth.check_permission``

    L-5 fix: chunk_ids guard — if fused is empty we skip batch_decide entirely.
    MED-4 fix: REMOTE is set only when local retrieval returned zero chunks AND
               a peer is configured.  A local denial (chunks exist but all denied)
               stays LOCAL_DENIED.
    """
    await _enforce(
        "auth.check_permission",
        {
            "user_id": state["user_id"],
            "chunk_count": len(state["fused_chunks"]),
        },
    )

    log.debug("node_check_auth", user_id=state["user_id"])
    auth = await _get_openfga()
    user_id = state["user_id"]
    fused = state["fused_chunks"]

    # L-5: guard empty chunk_ids before batch_decide
    chunk_ids = [c["chunk_id"] for c in fused if c.get("chunk_id")]
    if not chunk_ids:
        # No local data. Classify intent before paying for a federated round-trip:
        # company-data questions go to the peer; general chit-chat is answered here.
        flow = FlowDecision.LOCAL_DENIED
        if not fused and settings.peer_agent_url and state.get("allow_remote", True):
            flow = FlowDecision.REMOTE
            if state.get("check_only"):
                # Approval poll: this query already parked on the peer, so we KNOW it
                # routes REMOTE. Skip the intent LLM — re-checking authz must be fast
                # and free (polls fire every few seconds); no answer is generated here.
                log.debug("check_auth_check_only_skip_intent", routed="remote")
                return {"flow": flow, "allowed_chunk_ids": [], "pending_chunk_ids": [], "denied_chunk_ids": []}
            try:
                intent_llm = await _get_intent_llm()
                intent_resp = await intent_llm.ainvoke(
                    "Classify whether a question is about COMPANY DATA (policies, salaries, "
                    "compensation, HR, finances, revenue, infrastructure, Kubernetes, technical "
                    "documentation, internal systems) or is GENERAL/PERSONAL chit-chat (greetings, "
                    "how are you, opinions, jokes, world facts).\n"
                    "Reply with ONLY the single word COMPANY or GENERAL.\n\n"
                    "Question: How much do senior engineers earn?\nClassification: COMPANY\n"
                    "Question: how is your day?\nClassification: GENERAL\n"
                    "Question: what's the weather like?\nClassification: GENERAL\n"
                    "Question: What Kubernetes version do we run?\nClassification: COMPANY\n"
                    f"Question: {state['query']}\nClassification:"
                )
                raw = (intent_resp.content if hasattr(intent_resp, "content") else str(intent_resp))
                # Only the FIRST non-empty line is the classification (small model may ramble).
                first = next((ln.strip().upper() for ln in str(raw).splitlines() if ln.strip()), "")
                flow = FlowDecision.REMOTE if first.startswith("COMPANY") else FlowDecision.LOCAL_DENIED
                log.info("intent_classified", classification=first[:20], routed=flow.value)
            except Exception as exc:
                log.warning("intent_check_failed", error=str(exc))
                flow = FlowDecision.REMOTE  # fail open

        log.info("auth_decision_no_chunks", flow=flow.value)
        result_empty: dict[str, Any] = {
            "flow": flow,
            "allowed_chunk_ids": [],
            "pending_chunk_ids": [],
            "denied_chunk_ids": [],
        }
        if flow == FlowDecision.LOCAL_DENIED:
            try:
                llm = await _get_llm()
                resp = await llm.ainvoke(
                    "You are a helpful AI assistant for a company knowledge-base system. "
                    "The user asked something that isn't a company-data question, or no "
                    "relevant information exists.\n\n"
                    f"User's message: {state['query']}\n\n"
                    "Reply briefly and naturally (1-2 sentences). If it's casual chit-chat, "
                    "respond warmly but note you're specialised for company knowledge questions."
                )
                result_empty["status_message"] = resp.content if hasattr(resp, "content") else str(resp)
            except Exception as exc:
                log.warning("no_results_llm_message_failed", error=str(exc))
                result_empty["status_message"] = "I'm specialised for company knowledge questions and couldn't find anything relevant to that."
        return result_empty

    # Phase-1 group grants: thread the user's IdP groups so a chunk granted to one of
    # their groups (group#member viewer) resolves as allowed — membership is supplied to
    # OpenFGA as a live contextual tuple, never persisted.
    decisions = await auth.batch_decide(user_id, chunk_ids, groups=state.get("user_groups") or [])

    allowed = [cid for cid, d in decisions.items() if d == AuthzDecision.ALLOWED]
    pending = [cid for cid, d in decisions.items() if d == AuthzDecision.NEEDS_APPROVAL]
    denied  = [cid for cid, d in decisions.items() if d == AuthzDecision.DENIED]

    # Flow priority: pending > allowed > remote (only if local empty) > denied
    local_results_exist = bool(fused)
    if pending:
        flow = FlowDecision.LOCAL_NEEDS_APPROVAL
    elif allowed:
        flow = FlowDecision.LOCAL_ALLOWED
    elif not local_results_exist and settings.peer_agent_url and state.get("allow_remote", True):
        # MED-4: no local data at all — ask peer, but first check intent so
        # conversational queries get an instant response instead of a 16s
        # round-trip through two clusters and two LLM calls.
        try:
            llm = await _get_intent_llm()
            intent_resp = await llm.ainvoke(
                "Classify whether a question is about COMPANY DATA (policies, salaries, "
                "compensation, HR, finances, revenue, infrastructure, Kubernetes, technical "
                "documentation, internal systems) or is GENERAL/PERSONAL chit-chat (greetings, "
                "how are you, opinions, jokes, world facts).\n"
                "Reply with ONLY the single word COMPANY or GENERAL.\n\n"
                "Question: How much do senior engineers earn?\nClassification: COMPANY\n"
                "Question: how is your day?\nClassification: GENERAL\n"
                "Question: what's the weather like?\nClassification: GENERAL\n"
                "Question: What Kubernetes version do we run?\nClassification: COMPANY\n"
                f"Question: {state['query']}\nClassification:"
            )
            intent_text = (intent_resp.content if hasattr(intent_resp, "content") else str(intent_resp)).strip().upper()
            flow = FlowDecision.REMOTE if "COMPANY" in intent_text else FlowDecision.LOCAL_DENIED
            log.info("intent_classified", classification=intent_text[:20], routed=flow.value)
        except Exception as exc:
            log.warning("intent_check_failed", error=str(exc))
            flow = FlowDecision.REMOTE  # fail open
    else:
        flow = FlowDecision.LOCAL_DENIED

    log.info(
        "auth_decision",
        flow=flow.value,
        allowed=len(allowed),
        pending=len(pending),
        denied=len(denied),
        agt_audit=True,
    )

    # When no results exist (denied or no data) and there's nowhere else to go,
    # use the LLM to generate a helpful response rather than a generic empty string.
    status_message: str | None = None
    if flow == FlowDecision.LOCAL_DENIED or (not local_results_exist and not settings.peer_agent_url):
        if state.get("check_only"):
            # Approval poll: no user-facing prose needed — the caller maps the flow to a
            # terse status. Skip the LLM so a still-denied poll stays fast and free.
            status_message = "denied"
        else:
            try:
                llm = await _get_llm()
                prompt = (
                    "You are a helpful AI assistant for a company knowledge base. "
                    "A user has asked a question but no relevant information was found "
                    "in the knowledge base, or access was denied.\n\n"
                    f"User's question: {state['query']}\n\n"
                    "Write a short, helpful response (1-2 sentences) acknowledging their question "
                    "and explaining that you don't have relevant information available to answer it. "
                    "If it seems like a general/conversational question not suited for a knowledge base, "
                    "gently clarify that you're specialised for company knowledge queries."
                )
                response = await llm.ainvoke(prompt)
                status_message = response.content if hasattr(response, "content") else str(response)
            except Exception as exc:
                log.warning("no_results_llm_message_failed", error=str(exc))
                status_message = "I couldn't find relevant information in the knowledge base to answer your question."

    # Finding #6: drop the *text* of denied chunks from state so unauthorised
    # content is not carried in the AgentState snapshot / Langfuse traces / OTEL
    # spans.
    serveable_ids = set(allowed) | set(pending)
    pruned_chunks = [c for c in fused if c.get("chunk_id") in serveable_ids]

    # A2d — content-integrity: re-source the TEXT served into the LLM from this
    # division's TRUSTED store of record (Qdrant), NOT verbatim from whatever retriever
    # the fusion happened to keep first. Per-chunk authz gates WHICH ids are served; it
    # does not authenticate WHAT an external retriever claims those ids contain. A
    # compromised/malicious RaaS that returns an authorized chunk_id with attacker text
    # would otherwise have that poisoned text flow straight into generate_answer.
    # External retrievers still add value: they contribute candidate ids + ranking (the
    # fused set), but the trusted store supplies the content for every served id. A
    # serveable id the trusted store does NOT hold (e.g. one only an external RaaS
    # surfaced) has no authoritative text → it is dropped from the served context
    # (fail-closed) rather than serving unverified retriever text.
    from rag.retriever import fetch_trusted_text

    retrievers = await _get_retrievers()
    trusted_text = await fetch_trusted_text(retrievers, list(serveable_ids))
    reconciled: list[dict[str, Any]] = []
    dropped_untrusted: list[str] = []
    for c in pruned_chunks:
        cid = c.get("chunk_id")
        src = trusted_text.get(cid)
        if src is None:
            # Authorized id with no trusted content — external-only / not in store of
            # record. Exclude it: we will not serve unauthenticated retriever text.
            dropped_untrusted.append(cid)
            continue
        reconciled.append({**c, "text": src["text"], "metadata": src["metadata"]})
    if dropped_untrusted:
        log.warning(
            "served_text_untrusted_dropped",
            chunk_ids=dropped_untrusted[:50],
            count=len(dropped_untrusted),
            agt_audit=True,
        )
    pruned_chunks = reconciled

    result: dict[str, Any] = {
        "flow": flow,
        "fused_chunks": pruned_chunks,
        "qdrant_results": [],
        "graph_results": [],
        "allowed_chunk_ids": allowed,
        "pending_chunk_ids": pending,
        "denied_chunk_ids": denied,
    }
    if status_message is not None:
        result["status_message"] = status_message
    return result


# ── Node: generate_answer ─────────────────────────────────────────────────────

async def generate_answer(state: AgentState) -> dict[str, Any]:
    """Build context from allowed chunks and invoke the LLM.

    AGT policy enforced: ``llm.generate``
    Context fields:
        context_char_count — data-access-policy caps at 24 000 chars (~6 000 tokens)
        user_id            — base-policy rate-limit gate
    """
    allowed_ids = set(state["allowed_chunk_ids"])
    context_chunks = [
        c for c in state["fused_chunks"] if c.get("chunk_id") in allowed_ids
    ]

    if not context_chunks:
        return {
            "answer": (
                "I found relevant information but you do not have permission to view it."
            ),
            "status_message": "no_accessible_chunks",
        }

    context = "\n\n---\n\n".join(
        f"[Source: {c.get('metadata', {}).get('source', 'unknown')}]\n{c['text']}"
        for c in context_chunks
    )

    # Token budget: ~4 chars per token (rough estimate for policy check)
    max_chars = settings.llm_context_token_budget * 4
    original_len = len(context)

    await _enforce(
        "llm.generate",
        {
            "user_id": state["user_id"],
            "context_char_count": original_len,
        },
    )

    if original_len > max_chars:
        context = context[:max_chars] + "\n\n[... context truncated to fit token budget ...]"
        log.warning(
            "context_truncated",
            original_len=original_len,
            max_chars=max_chars,
        )

    log.info("node_generate_answer", user_id=state["user_id"], chunks=len(context_chunks))

    # LLM01 defense-in-depth: AUDIT injection patterns in the retrieved content + the query
    # (high-impact escalation is already contained — LLM has no actions, denied data is
    # pruned — so this is logged, not hard-blocked, to avoid false positives), and SPOTLIGHT
    # the untrusted context inside per-call boundary markers a hardened preamble refers to.
    from agent.injection import detect_injection, spotlight, hardened_system_preamble
    hits = detect_injection(context) + detect_injection(state["query"])
    if hits:
        log.warning("prompt_injection_suspected", patterns=sorted(set(hits)),
                    user_id=state["user_id"], agt_audit=True)
    spotlighted, boundary = spotlight(context)

    llm = await _get_llm()
    prompt = (
        f"{hardened_system_preamble(boundary)}\n\n"
        f"{spotlighted}\n\n"
        f"Question (from the user): {state['query']}\n\n"
        "Answer:"
    )

    response = await llm.ainvoke(prompt)
    answer = response.content if hasattr(response, "content") else str(response)

    return {"answer": answer, "status_message": "completed"}


# ── Node: start_approval ──────────────────────────────────────────────────────

async def start_approval(state: AgentState) -> dict[str, Any]:
    """Write OpenFGA pending tuples and start a Temporal approval workflow.

    AGT policy enforced: ``approval.start_workflow``

    L-7 fix: chunk_ids capped at 50 before being sent to Temporal to stay
             below the 4 MB gRPC event-history limit.
    L-6 fix: approval_request_id is NOT included in the user-visible
             status_message so users cannot probe the /approve endpoint.
    WorkflowAlreadyStartedError is caught and treated as idempotent (retry-safe).
    """
    # Approval-poll re-auth (GET /tasks/{id}/result, check_only=True): the request is
    # STILL pending (check_auth routed here), so report "pending" WITHOUT writing new
    # pending tuples or starting another Temporal workflow — the original request's
    # tuples + workflow are already live. Re-doing them on every 4 s poll would spam
    # the data owner with duplicate approval notifications. flow stays
    # LOCAL_NEEDS_APPROVAL (unchanged here) so the caller maps this to "pending".
    if state.get("check_only"):
        log.debug("start_approval_check_only_pending", user_id=state["user_id"])
        return {
            "approval_request_id": None,
            "status_message": "pending_approval",
            "answer": None,
        }

    await _enforce(
        "approval.start_workflow",
        {
            "user_id": state["user_id"],
            "pending_chunk_count": len(state["pending_chunk_ids"]),
        },
    )

    log.info("node_start_approval", user_id=state["user_id"])
    auth = await _get_openfga()
    user_id = state["user_id"]

    # L-7: cap chunk list to avoid oversized Temporal event-history entries
    _MAX_APPROVAL_CHUNKS = 50
    raw_chunk_ids = state["pending_chunk_ids"]
    chunk_ids = raw_chunk_ids[:_MAX_APPROVAL_CHUNKS]
    if len(raw_chunk_ids) > _MAX_APPROVAL_CHUNKS:
        log.warning(
            "approval_chunk_ids_capped",
            original=len(raw_chunk_ids),
            capped=_MAX_APPROVAL_CHUNKS,
            agt_audit=True,
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
    log.info(
        "openfga_pending_written",
        user_id=user_id,
        count=len(chunk_ids),
        agt_audit=True,
    )

    # Resolve approver from the first chunk's owner relation
    approver_id: str = "admin"
    for chunk_id in chunk_ids:
        owner = await auth.get_chunk_owner(chunk_id)
        if owner:
            approver_id = owner
            break

    # Start Temporal approval workflow (idempotent on WorkflowAlreadyStartedError)
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
                # M4 (FR-6): cross-division callback target. For a peer-originated request
                # these carry the ORIGINATING division's agent + task so the workflow
                # send_a2a_callback notifies it on the decision (D-6: "approved, re-send"
                # → the user re-runs the governed pipeline and the far side regenerates).
                # SSRF-validated in /a2a/query before reaching here; absent for local requests.
                originating_agent_url=state.get("originating_agent_url"),
                originating_task_id=state.get("originating_task_id"),
                # Snapshot timeout at start — deterministic for Temporal replay
                timeout_seconds=settings.approval_timeout_seconds,
            ),
            id=f"approval-{approval_request_id}",
            task_queue=settings.temporal_task_queue,
        )
        log.info(
            "temporal_workflow_started",
            approval_request_id=approval_request_id,
            agt_audit=True,
        )
    except WorkflowAlreadyStartedError:
        # Duplicate start (e.g., client retry) — existing workflow continues
        log.warning(
            "approval_workflow_already_started",
            approval_request_id=approval_request_id,
        )

    # Record the pending request in the Redis inbox index so the approver's
    # /approvals/pending is a fast, consistent point read (not a laggy Temporal
    # visibility scan). Best-effort: a failure here never blocks the approval.
    import approval_index
    await approval_index.record(approver_id, approval_request_id, user_id, state["query"])

    # LLM generates a contextual message. Only source names from metadata are
    # passed — never chunk text — so the security boundary is preserved.
    sources = sorted({
        c.get("metadata", {}).get("source", "")
        for c in state.get("fused_chunks", [])
        if c.get("chunk_id") in set(chunk_ids)
    } - {""})
    source_hint = f" (relevant document: {', '.join(sources)})" if sources else ""
    try:
        llm = await _get_llm()
        prompt = (
            "You are a helpful AI assistant operating within a federated data governance system. "
            "A user has asked a question that requires access to restricted data. "
            "An approval request has been submitted to the data owner on their behalf.\n\n"
            f"User's question: {state['query']}\n"
            f"Relevant data source{source_hint}\n\n"
            "Write a single short paragraph (2-3 sentences) to the user that:\n"
            "1. Acknowledges what they asked about and confirms relevant information exists\n"
            "2. Explains that access requires approval from the data owner\n"
            "3. States that a request has been submitted and they will be notified\n"
            "Do NOT reveal any of the actual data content. Be natural and helpful."
        )
        response = await llm.ainvoke(prompt)
        status_message = response.content if hasattr(response, "content") else str(response)
    except Exception as exc:
        log.warning("approval_llm_message_failed", error=str(exc))
        status_message = (
            "Your request is pending approval. "
            "The data owner has been notified and will review your request. "
            "You will be notified once a decision is made."
        )

    return {
        "approval_request_id": approval_request_id,
        "status_message": status_message,
        "answer": None,
    }


# ── Node: call_peer_agent ─────────────────────────────────────────────────────

async def call_peer_agent(state: AgentState) -> dict[str, Any]:
    """Discover a capable peer, negotiate, then delegate the query (FR-3.1/3.2).

    AGT policy enforced: ``peer.send_message``
    Context fields include peer_circuit_state so the peer-comms-policy can
    gate on CircuitState.OPEN before any gRPC call is attempted (ASI-08).

    Delegation target selection (FR-3.1/3.2): instead of blindly using the
    configured peer, query the discovery broker for a peer advertising the
    query's capability and negotiate before committing (mesh/discovery.py).
    GRACEFUL DEGRADATION: if the broker is unreachable / returns nothing / the
    discovered peer isn't a configured trust partner, fall back to the configured
    peer so existing single-peer federation never regresses. The signed transport
    (mesh/peer_client.call_peer_agent) is unchanged — it sends to the configured
    peer; we delegate through it only when the discovered target resolves to that
    peer (the demo's single trusted partner). The discovered target is recorded in
    ``discovery_summary`` for the observable inter-agent conversation (FR-3.4).

    Security: user_token is read from _user_token_ctx, never from state.
    The peer_client layer handles DID verification, trust-score gating,
    IATP encryption, and circuit-breaker management.
    """
    if not settings.peer_agent_url:
        return {
            "error": "No peer agent configured.",
            "flow": FlowDecision.REMOTE_DENIED,
            "status_message": "No remote cluster available.",
        }

    # ── FR-3.1/3.2: discover → negotiate → resolve the delegation target ──────
    # Never raises (graceful degradation to the configured peer inside the helper).
    from mesh.discovery import resolve_delegation_target
    target = await resolve_delegation_target(state["query"])

    # HONESTY GUARD: the signed transport (_mesh_call_peer) sends to the configured
    # peer. If discovery selected a peer that is NOT the configured one (possible only
    # in a future multi-peer mesh, never in the single-peer demo), we cannot route
    # there through this transport — so we report it as a configured-fallback for THIS
    # send rather than claim a hop that didn't happen. The discovered division is kept
    # in the marker for observability of WHAT WAS DISCOVERED.
    source = target.source
    if source == "discovered" and not target.is_configured_peer():
        log.warning("discovered_peer_not_configured_transport_fallback",
                    discovered_url=target.agent_url, discovered_did=target.agent_did)
        source = "configured-fallback"

    # Structured marker the UI MonitorPanel parses into discovered/negotiated/
    # delegated rows (FR-3.4) — explicit signal, not inferred from arbitrary prose.
    discovery_summary = {
        "source": source,                        # "discovered" | "configured-fallback"
        "division": target.division_id,
        "capability": target.capability or "",
        "negotiated": target.negotiated,
        "candidates": len(target.candidates),
    }
    log.info(
        "delegation_target_resolved",
        source=source,
        peer_division=target.division_id,
        capability=target.capability,
        negotiated=target.negotiated,
        candidates=len(target.candidates),
        agt_audit=True,
    )

    # Include circuit breaker state in policy context (ASI-08, peer-comms-policy)
    circuit_state = await get_peer_circuit_state(str(settings.peer_agent_url))

    # Finding #4: feed the policy engine the REAL verification results, not
    # hardcoded "all verified" constants. With the old hardcoded values the
    # peer-comms-policy DENY rules on peer_did_verified / peer_trust_score
    # could never fire — the policy layer was decorative.
    peer_did = settings.peer_agent_did or ""
    if peer_did:
        peer_verified, peer_trust = await verify_peer_identity(peer_did)
    else:
        peer_verified, peer_trust = False, 0.0

    await _enforce(
        "peer.send_message",
        {
            "user_id": state["user_id"],
            "peer_did_verified": peer_verified,   # real registry verification result
            # transport_encrypted is structurally true: peer_client builds the
            # AgentMeshClient with require_encryption=True, which raises if the
            # IATP channel cannot be encrypted.
            "transport_encrypted": True,
            "peer_trust_score": peer_trust,       # real registry trust score
            "peer_execution_ring": "TRUSTED",
            "peer_circuit_state": circuit_state.name,  # "CLOSED" | "OPEN" | "HALF_OPEN"
        },
    )

    log.info("node_call_peer_agent", user_id=state["user_id"])

    callback_url: str | None = None
    task_id = state.get("task_id")
    if task_id:
        # rstrip so a trailing slash on agent_url doesn't produce "//tasks/" (which would
        # fail the receiver's SSRF prefix check and silently drop the callback — M4).
        callback_url = f"{str(settings.agent_url).rstrip('/')}/tasks/{task_id}/callback"

    try:
        peer_response = await _mesh_call_peer(
            query=state["query"],
            user_id=state["user_id"],
            context_id=state.get("context_id", ""),
            callback_url=callback_url,
            # M2 (FR-3.6), security-hardened: forward the user's VALIDATED identity
            # CLAIMS (minimal subset, from the security ContextVar) — NOT their raw
            # bearer token. The claims travel inside the DID-signed, replay-protected
            # envelope; the peer binds the asserted issuer to our signing DID and
            # re-authorizes via its own OpenFGA. No replayable credential leaves us.
            user_assertion=_user_claims_ctx.get(),
            # Approval-poll re-auth: tell the peer to re-check WITHOUT restarting its
            # approval workflow (else each cross-division poll re-notifies the owner).
            check_only=state.get("check_only", False),
        )
    except Exception as exc:
        log.error("peer_call_failed", error=str(exc))
        return {
            "error": str(exc),
            "flow": FlowDecision.REMOTE_DENIED,
            "status_message": "Remote cluster call failed.",
            "discovery_summary": discovery_summary,
        }

    log.info(
        "peer_call_completed",
        status=peer_response.status,
        peer_did=peer_response.peer_did,
        trust_score=peer_response.trust_score,
        agt_audit=True,
    )
    return {
        "peer_task_id": peer_response.task_id,
        "peer_status": peer_response.status,
        "peer_answer": peer_response.answer,
        "discovery_summary": discovery_summary,
    }


# ── Node: handle_peer_result ──────────────────────────────────────────────────

async def handle_peer_result(state: AgentState) -> dict[str, Any]:
    """Interpret the peer agent's status and set the final flow decision.

    AGT policy enforced: ``peer.receive_callback``

    PeerResponse.status values (from mesh/peer_client.py):
        "completed"       → REMOTE_APPROVED
        "input_required"  → REMOTE_NEEDS_APPROVAL
        anything else     → REMOTE_DENIED
    """
    await _enforce(
        "peer.receive_callback",
        {
            "user_id": state["user_id"],
            "peer_status": state.get("peer_status", "unknown"),
        },
    )

    peer_status = state.get("peer_status", "")
    log.info("node_handle_peer_result", peer_status=peer_status)

    if peer_status == "completed":
        raw_answer = state.get("peer_answer") or ""
        if state.get("check_only"):
            # Approval-outcome poll: the peer already GENERATED a full answer. Deliver it
            # directly and skip the relay LLM — that second (cold-start-prone) model call
            # is what made post-approval delivery slow for the requester. The poll's job is
            # to deliver the approved answer fast, not to re-narrate it.
            return {
                "answer": raw_answer,
                "peer_answer": raw_answer,
                "flow": FlowDecision.REMOTE_APPROVED,
                "status_message": "completed",
            }
        # LLM01: the peer answer is UNTRUSTED content entering our relay LLM — audit
        # injection patterns and spotlight it inside boundary markers (same defense as
        # generate_answer) so a poisoned peer answer can't steer the relay.
        from agent.injection import detect_injection, spotlight, hardened_system_preamble
        if (peer_hits := detect_injection(raw_answer)):
            log.warning("prompt_injection_suspected_peer", patterns=sorted(set(peer_hits)),
                        user_id=state["user_id"], agt_audit=True)
        spotlighted, boundary = spotlight(raw_answer)
        try:
            llm = await _get_llm()
            prompt = (
                f"{hardened_system_preamble(boundary)}\n\n"
                "You asked a peer cluster a question on behalf of the user; its answer is the "
                "DATA between the markers. Relay it to the user clearly and concisely, and note "
                "it came from the federated peer cluster.\n\n"
                f"User's original question: {state['query']}\n\n"
                f"{spotlighted}\n\n"
                "Relayed answer:"
            )
            response = await llm.ainvoke(prompt)
            answer = response.content if hasattr(response, "content") else str(response)
        except Exception as exc:
            log.warning("peer_result_llm_synthesis_failed", error=str(exc))
            answer = raw_answer
        return {
            "answer": answer,
            "peer_answer": raw_answer,
            "flow": FlowDecision.REMOTE_APPROVED,
            "status_message": "completed",
        }

    elif peer_status == "input_required":
        if state.get("check_only"):
            # Approval poll: no prose needed — caller maps the flow to "pending".
            status_message = "pending_approval"
        else:
            try:
                llm = await _get_llm()
                prompt = (
                    "You are a helpful AI assistant in a federated multi-cluster system. "
                    "The user asked a question that requires data from a peer cluster. "
                    "That peer cluster has determined the user needs approval from its data owner "
                    "before the information can be shared.\n\n"
                    f"User's question: {state['query']}\n\n"
                    "Write a short, clear message (2-3 sentences) that:\n"
                    "1. Explains the requested information lives on a remote cluster\n"
                    "2. States that the remote data owner's approval is required\n"
                    "3. Confirms a request has been submitted and they will be notified"
                )
                response = await llm.ainvoke(prompt)
                status_message = response.content if hasattr(response, "content") else str(response)
            except Exception as exc:
                log.warning("peer_approval_llm_message_failed", error=str(exc))
                status_message = (
                    "The requested information is on the remote cluster and requires "
                    "approval from the remote data owner. You will be notified once a "
                    "decision is made."
                )
        return {
            "flow": FlowDecision.REMOTE_NEEDS_APPROVAL,
            "status_message": status_message,
            "answer": None,
        }

    elif state.get("check_only"):
        # Approval poll that resolved to denied/no-access — terse, no LLM.
        return {
            "flow": FlowDecision.REMOTE_DENIED,
            "status_message": "denied",
            "answer": None,
        }

    else:
        try:
            llm = await _get_llm()
            prompt = (
                "You are a helpful AI assistant for a company knowledge base. "
                "You searched both local and remote cluster knowledge bases but found no relevant information.\n\n"
                f"User's question: {state['query']}\n\n"
                "Write a short, helpful response (1-2 sentences). If this looks like a "
                "general/conversational question, gently explain you're specialised for "
                "company knowledge queries. If it looks like a genuine knowledge query, "
                "acknowledge you couldn't find relevant information."
            )
            response = await llm.ainvoke(prompt)
            status_message = response.content if hasattr(response, "content") else str(response)
        except Exception as exc:
            log.warning("remote_denied_llm_message_failed", error=str(exc))
            status_message = "I searched the federated knowledge base but couldn't find relevant information to answer your question."
        return {
            "flow": FlowDecision.REMOTE_DENIED,
            "status_message": status_message,
            "answer": None,
        }


# ── Node: format_response ─────────────────────────────────────────────────────

async def format_response(state: AgentState) -> dict[str, Any]:
    """Final safe formatting — never leak raw errors to the caller.

    AGT policy enforced: ``agent.format_response``

    Raw error strings (hostnames, ports, stack traces, internal IDs) are logged
    internally and replaced with a generic user-safe message.  The ``error``
    field in state is therefore safe to log at WARNING for operator visibility
    but must never appear verbatim in the returned answer.
    """
    await _enforce(
        "agent.format_response",
        {"user_id": state["user_id"]},
    )

    error = state.get("error")
    if error:
        log.warning("format_response_with_error", raw_error=error)
        return {
            "answer": "An error occurred while processing your request. Please try again.",
            "status_message": "error",
        }

    answer = state.get("answer") or state.get("peer_answer")
    status = state.get("status_message", "")

    if not answer:
        answer = status or "I could not find an answer to your query."

    # Output DLP (task #10, HARD-DENY): gate the OUTGOING answer through the policy
    # engine before it leaves the agent. This is the single universal output choke
    # point — every terminal route (local answer AND cross-cluster peer answer)
    # passes through here, so a peer-sourced secret is caught without trusting the
    # peer. The `block-credential-leak-in-output` rule DENIES on a credential
    # match; on a clean answer it passes via allow-output-check. On a hit we
    # withhold the ENTIRE answer (fail-closed) rather than return a partial
    # redaction. PermissionError is caught here so the user gets a clear safe
    # message instead of the generic governance-denial.
    try:
        await _enforce("agent.output_check", {"llm_output": answer})
    except PermissionError:
        log.warning("output_credential_blocked", agt_audit=True)  # never log the answer/secret
        return {
            "answer": (
                "The response was withheld because it appeared to contain sensitive "
                "credential material. Please contact an administrator if you believe "
                "this is an error."
            ),
            "status_message": "blocked_credential_leak",
        }

    # FR-3.4: prepend the structured delegation marker on the cross-division path so
    # the UI MonitorPanel can surface the discovered peer + negotiation + delegation
    # as explicit events. Skipped for check_only polls (they keep terse status words
    # the requester-side poll maps directly). The marker is a separate first line; the
    # human prose follows unchanged.
    final_status = status or "completed"
    summary = state.get("discovery_summary")
    if summary and not state.get("check_only"):
        marker = _delegation_marker(summary)
        if marker and not final_status.startswith(_DELEGATION_MARKER_PREFIX):
            final_status = f"{marker} {final_status}"

    return {"answer": answer, "status_message": final_status}
