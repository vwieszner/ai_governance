# Federated RAG — Scenarios

This document maps every scenario to the real framework components
that execute it. Nothing here is invented — every node, model, and protocol
reference corresponds to live code in `federated-rag/` and `agt-federated-rag/`.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  Browser  (React + Vite)                                             │
│  LoginForm → Keycloak OIDC (password-grant) → JWT                   │
│  ChatArea  → POST /tasks/send (cluster-a) or /query (cluster-b)     │
│  MonitorPanel → live SSE event stream from both clusters             │
└────────────┬───────────────────────────────┬───────────────────────-┘
             │ SSE / A2A (port 8000)         │ SSE (port 8002)
┌────────────▼────────────┐     ┌────────────▼────────────────────────┐
│  Cluster-A              │     │  Cluster-B                           │
│  federated-rag/         │     │  agt-federated-rag/                  │
│                         │     │                                      │
│  FastAPI  api/main.py   │     │  FastAPI  api/main.py                │
│  LangGraph  graph.py    │ A2A │  LangGraph + govern-action gate      │
│  Qdrant (hybrid RAG)    │────▶│  Qdrant (hybrid RAG)                 │
│  Neo4j  (seam, inert)   │     │  Neo4j  (seam, inert)                │
│  OpenFGA (ReBAC)        │     │  OpenFGA + AGT policy engine         │
│  Temporal (approvals)   │     │  Temporal (approvals)                │
│  Redis  (task store)    │     │  Redis  (task store)                 │
│  Keycloak (OIDC)        │     │  Keycloak + AgentMesh DID            │
└─────────────────────────┘     └──────────────────────────────────────┘
```

---

## Frameworks in Use

| Framework | Where | Role |
|-----------|-------|------|
| **LangGraph** `StateGraph` | `agent/graph.py` | Orchestrates the 5 authorization flows as a directed state machine |
| **A2A v1.0 protocol** | `a2a/models.py`, `a2a/client.py` | Typed inter-agent messaging (`AgentCard`, `Task`, `TaskStatusUpdateEvent`) |
| **OpenFGA** ReBAC | `auth/openfga.py` | Per-chunk access control (`viewer`, `owner`, `pending_approval` tuples) |
| **Temporal** | `workflow/approval.py` | Signal-based approval gate with configurable timeout (default 24 h) |
| **RFC 8693** token exchange | `auth/token_exchange.py` | Cluster-A delegates its JWT to Cluster-B when making A2A calls |
| **AGT graph-invocation gate** | `agt-federated-rag/agent/graph.py` (`run_query`) | A `govern_action("agent.graph.invoke")` AgentMesh call before the graph compiles — audit + an enforcing operator kill-switch (deny on `kill_switch_engaged`; deploy-time, requires restart). Not a wrapping middleware. |
| **AgentMesh DID** | `agt-federated-rag/mesh/agent_identity.py` | Ed25519-signed A2A callbacks; trust-score gating |
| **FastEmbed + Qdrant** | `rag/qdrant_retriever.py` | BGE-M3 dense + BM25 sparse hybrid retrieval with server-side RRF |
| **neo4j-graphrag** | `rag/neo4j_retriever.py` | Graph-retrieval seam — **scaffolded but currently inert** (no Neo4j ingest, no graph traversal / entity-neighbourhood expansion); retrieval is Qdrant-only |
| **RRF fusion** | `rag/fusion.py` | Reciprocal Rank Fusion merges Qdrant and Neo4j results (the Neo4j list is currently empty, so this fuses Qdrant only) |
| **Keycloak** | `auth/token_exchange.py` | OIDC issuer; JWT validated via JWKS on every request |
| **structlog** | throughout | Structured JSON logging with request-ID correlation |
| **Pydantic v2** | `a2a/models.py`, `config.py` | Runtime type validation of all API payloads |

---

## The 5 Authorization Flows (LangGraph)

Defined in `federated-rag/agent/graph.py` → `build_graph()` and
`agt-federated-rag/agent/graph.py` → `_route()`.

```
retrieve_local
    │
    ▼
check_auth  ──── FlowDecision ────▶ generate_answer ──▶ format_response
    │                                                           ▲
    ├── LOCAL_NEEDS_APPROVAL ──▶ start_approval ────────────────┤
    │                                                           │
    ├── REMOTE ──────────────▶ call_peer_agent                  │
    │                              │                            │
    │                   (error?) ──┤                            │
    │                              ▼                            │
    │                         handle_peer_result ───────────────┤
    │                                                           │
    └── LOCAL_DENIED ──────────────────────────────────────────▶┘
```

---

## Scenario 1 — Flow A: Local, Authorized (Immediate Answer)

**Who:** Alice on Cluster-A  
**Trigger:** Query matches data in local Qdrant + OpenFGA grants `viewer` access  
**Example query:** `"What is our data retention policy?"`

### Step-by-step

| Step | Framework | Code location |
|------|-----------|---------------|
| 1. Alice POSTs query | FastAPI `POST /tasks/send` | `federated-rag/api/main.py:send_task()` |
| 2. JWT validated | Keycloak JWKS | `auth/token_exchange.py:validate_token()` |
| 3. Rate limit checked | Redis fixed-window | `api/main.py:_check_rate_limit()` |
| 4. Task stored | Redis (`task:{id}` key, 24 h TTL) | `api/main.py:_store_task()` |
| 5. LangGraph invoked | `StateGraph.ainvoke()` | `agent/graph.py:run_query()` |
| 6. **retrieve_local** | Qdrant BGE-M3 + BM25 → RRF (graph retriever is called but inert, so it returns nothing) | `agent/nodes.py:retrieve_local` |
| 7. **check_auth** | OpenFGA `check(user, viewer, chunk)` per retrieved chunk | `agent/nodes.py:check_auth` → `auth/openfga.py` |
| 8. FlowDecision = `LOCAL_ALLOWED` | All chunks pass → `generate_answer` | `agent/graph.py:route_after_auth()` |
| 9. **generate_answer** | NVIDIA NIM (OpenAI-compatible) with retrieved context | `agent/nodes.py:generate_answer` |
| 10. **format_response** | Populate `AgentState.answer` | `agent/nodes.py:format_response` |
| 11. SSE event emitted | `TaskState.COMPLETED` | `api/main.py:event_stream()` |

### Expected input / output

```
Input  (POST /tasks/send body):
{
  "message": {
    "role": "user",
    "parts": [{ "type": "text", "text": "What is our data retention policy?" }]
  }
}

SSE output (2 events):
event: task_status_update
data: { "status": { "state": "working", "message": "Processing..." } }

event: task_status_update
data: {
  "status": { "state": "completed" },
  "history": [{
    "role": "agent",
    "parts": [{ "type": "text", "text": "Our data retention policy requires..." }]
  }],
  "metadata": { "flow": "local_authorized" }
}
```

---

## Scenario 2 — Flow B: Local, Needs Approval

**Who:** Alice on Cluster-A  
**Trigger:** Query matches chunks where Alice has `pending_approval` (not `viewer`) in OpenFGA  
**Example query:** `"Show me classified documents"` or `"Show me restricted financial data"`

### Step-by-step

| Step | Framework | Code location |
|------|-----------|---------------|
| 1–6 | Same as Flow A | — |
| 7. **check_auth** | OpenFGA returns `pending_approval` for some chunks | `auth/openfga.py` |
| 8. FlowDecision = `LOCAL_NEEDS_APPROVAL` → `start_approval` | | `agent/graph.py:route_after_auth()` |
| 9. **start_approval** | Temporal `ApprovalWorkflow` started; HMAC-signed Slack deep-link generated | `workflow/approval.py` |
| 10. Temporal workflow waits | `workflow.wait_for_signal("approval_decision")` with 24 h timeout | `workflow/approval.py:ApprovalWorkflow` |
| 11. SSE emits `INPUT_REQUIRED` | Task state = `input-required`; user sees waiting indicator | `api/main.py` |
| 12. Approver clicks link | `GET /approve/{request_id}?decision=approve&exp={ts}&token={hmac}` | `api/main.py:handle_approval()` |
| 13. HMAC verified | `hmac.compare_digest(expected, token)` — timing-safe | `api/main.py:_verify_approval_token()` |
| 14. Temporal signal sent | `workflow.signal("approval_decision", ApprovalDecisionSignal)` | `api/main.py` |
| 15. OpenFGA tuple written | `write(user, viewer, chunk)` — grants permanent access | `workflow/activities.py` |

### Security notes

- Approval link signed with `HMAC-SHA256(secret, "{request_id}:{decision}:{exp}")` — see `C-2` fix
- Link expiry is part of the signed message — cannot extend by editing URL — see Finding #2 fix
- Approval token is HMAC of request_id + decision + expiry; cannot be forged without the secret

### Expected output

```
SSE:
event: task_status_update
data: {
  "status": {
    "state": "input-required",
    "message": "Access to restricted data requires approval. Request sent via Slack."
  },
  "metadata": {
    "flow": "local_needs_approval",
    "approvalRequestId": "bbdd05a5-..."
  }
}
```

---

## Scenario 3 — Flow C: Remote, Authorized (A2A Federation)

**Who:** Alice on Cluster-A; data lives on Cluster-B  
**Trigger:** No matching chunks in Cluster-A; `PEER_AGENT_URL` is configured  
**Example query:** `"What is our compliance framework?"` or `"Explain our GDPR obligations"`

### Step-by-step

| Step | Framework | Code location |
|------|-----------|---------------|
| 1–7 | Same as Flow A | — |
| 7. check_auth | No local chunks found → `REMOTE` | `agent/nodes.py:check_auth` |
| 8. FlowDecision = `REMOTE` → `call_peer_agent` | | `agent/graph.py:route_after_auth()` |
| 9. **RFC 8693 token exchange** | Alice's JWT → delegated token for Cluster-B | `auth/token_exchange.py:exchange_token()` |
| 10. **call_peer_agent** | `POST {peer}/tasks/send` with A2A `SendTaskRequest` | `a2a/client.py:send_task()` |
| 11. A2A request | Bearer = delegated token; body = `SendTaskRequest` (Pydantic model) | `a2a/models.py:SendTaskRequest` |
| 12. Cluster-B validates JWT | Keycloak JWKS; checks `client_id` is in `peer_agent_client_ids` | `federated-rag/api/main.py:get_token_claims()` |
| 13. Cluster-B runs LangGraph | Full Flow A on its own data | `agent/graph.py:run_query()` |
| 14. Cluster-B SSE streams | `task_status_update` events | `api/main.py:event_stream()` |
| 15. **handle_peer_result** | Parse peer's final state; populate `peer_answer` | `agent/nodes.py:handle_peer_result` |
| 16. **format_response** | Merge peer answer into response | `agent/nodes.py:format_response` |

### A2A wire format (real Pydantic models from `a2a/models.py`)

```python
# Cluster-A → Cluster-B
SendTaskRequest(
    id="task-uuid",
    contextId="session-uuid",
    message=Message(
        role="user",
        parts=[TextPart(text="What is our compliance framework?")],
        messageId="msg-uuid",
    ),
    pushNotification=PushNotificationConfig(
        url="https://cluster-a.internal/tasks/{id}/callback"
    )
)

# Cluster-B → Cluster-A (SSE)
TaskStatusUpdateEvent(
    id="task-uuid",
    status=TaskStatus(state=TaskState.COMPLETED, message="Done"),
    final=True
)
```

### Monitor panel events

```
12:01:05  cluster-a  alice  → query submitted
12:01:06  cluster-a  agent  ⚙ No local chunks — routing to peer
12:01:06  cluster-a  agent  → RFC 8693 token exchange
12:01:07  cluster-a  agent  ⇄ A2A POST /tasks/send → cluster-b
12:01:07  cluster-b  agent  ⚙ Retrieving from compliance knowledge base
12:01:09  cluster-b  agent  ✓ completed
12:01:09  cluster-a  agent  ← peer result received
12:01:09  cluster-a  agent  ✓ answer ready
```

---

## Scenario 4 — Flow D: Remote, Needs Approval (Cross-Cluster)

**Who:** Alice on Cluster-A; data on Cluster-B requires approval  
**Trigger:** Cluster-B's check_auth returns `pending_approval` for Alice's delegated identity  
**Example query:** `"Show me classified compliance reports from cluster-b"`

This is the most complex flow — two Temporal workflows, two HMAC links, cross-cluster callbacks.

| Step | Framework |
|------|-----------|
| 1–11 | Same as Flow C |
| 12. Cluster-B check_auth → `LOCAL_NEEDS_APPROVAL` | OpenFGA `pending_approval` for delegated token |
| 13. Cluster-B starts Temporal workflow | `ApprovalWorkflow` on Cluster-B's Temporal |
| 14. Cluster-B SSE = `input-required` | A2A client on Cluster-A receives this |
| 15. Cluster-A stores peer task as `awaiting_peer_callback` | Redis metadata flag — security fix Finding #3 |
| 16. Cluster-A SSE to Alice = `input-required` | Alice sees "Approval required on peer cluster" |
| 17. Approver on Cluster-B clicks Slack link | `GET /approve/{id}` on Cluster-B |
| 18. Cluster-B Temporal signals, writes OpenFGA tuple | Same as Flow B step 14–15 |
| 19. Cluster-B pushes callback | `POST {cluster-a}/tasks/{id}/callback` with `TaskStatusUpdateEvent` |
| 20. Cluster-A validates callback | JWT `client_id` in `peer_agent_client_ids` AND `awaiting_peer_callback` flag — Finding #3 |
| 21. Cluster-A updates task | `TaskState.COMPLETED` |

---

## Scenario 5 — Flow E: Local Denied (No Peer)

**Who:** Alice on Cluster-A  
**Trigger:** OpenFGA returns denied for all chunks; no peer configured  
**Example query:** Any query where alice has no access and no cross-cluster route

```
FlowDecision = LOCAL_DENIED
→ format_response immediately
→ TaskState.FAILED, message = "Access denied"
```

---

## Microsoft Agent Governance Toolkit (AGT) — SDK Details

Cluster-B (`agt-federated-rag/`) uses the full AGT SDK stack.
These are real imports from `pyproject.toml` dependencies — not stubs.

### SDK packages and what they provide

```python
# agentmesh-platform ── DID identity, signing, trust
from agentmesh import (
    AgentIdentity,      # Ed25519 DID keypair — create(), from_jwks(), sign(), verify_signature()
    AgentMeshClient,    # Governed execution client — execute_with_governance()
    GovernanceResult,   # Result of a governed action (.allowed, .reason, .audit_id)
    TrustBridge,        # IATP peer handshake — verify_peer(did, protocol, required_trust_score)
    TrustTracker,       # Trust event sink — record_interaction(agent, peer, event, success)
)
from agentmesh.lifecycle import LifecycleManager   # Credential rotation

# agent-sre ── SLO tracking
from agent_sre.slo import SLI, SLO, SLIValue       # Error budget management

# agent-os-kernel / agent-governance-toolkit ── Policy enforcement
# consumed via the govern_action("agent.graph.invoke") gate in run_query
# (agt-federated-rag/agent/graph.py) and per-node _enforce() in agent/nodes.py
```

Source: `agt-federated-rag/mesh/agent_identity.py`, `agt-federated-rag/sre.py`

### DID identity lifecycle

```
First start:
  AgentIdentity.create(
      name="rag-agent-cluster-b",
      sponsor="admin@example.com",
      capabilities=["rag.query", "a2a.federate"],
  )
  → persisted to agent_identity_path (JWKS, private key, chmod 600)

Subsequent starts:
  AgentIdentity.from_jwks(persisted_file)
  → same DID every time — peer can trust a static PEER_AGENT_PUBLIC_JWK

GET /identity → { did, cluster, public_key_jwk }
  → operator copies public_key_jwk into Cluster-A's PEER_AGENT_PUBLIC_JWK env var
```

### Outbound signing (Cluster-B → Cluster-A callback)

```python
# mesh/agent_identity.py:sign_outbound_message()
payload = { "status": { "state": "completed" }, ... }
signed = {
    **payload,
    "_agentmesh": {
        "sender_did": "did:mesh:rag-agent-cluster-b-...",
        "signature": identity.sign(canonical_bytes(payload)),  # Ed25519
        "alg": "EdDSA",
    }
}
```

### Inbound verification (Cluster-A receives callback)

```python
# mesh/agent_identity.py:verify_signed_message()
# Key from TRUSTED CONFIG — never from message body (Finding #1)
peer_jwk = json.loads(settings.peer_agent_public_jwk)
peer_identity = AgentIdentity.from_jwk(peer_jwk)
verified = peer_identity.verify_signature(canonical_bytes(payload), signature)
# + DID mismatch check + configured peer_agent_did check
```

### Trust scoring via TrustBridge

```python
# Peer verification before accepting any A2A call
bridge = TrustBridge(agent_did=this_agent_did)
result = bridge.verify_peer(
    peer_did,
    protocol="iatp",                       # Identity Attestation Transport Protocol
    required_trust_score=600,              # 0.6 on a 0–1000 scale
)
# result.verified + result.trust_score
```

Trust events that decay the peer's score:
```python
tracker.record_interaction(agent_id, peer_did, "iatp_error", success=False)
tracker.record_interaction(agent_id, peer_did, "policy_violation", success=False)
tracker.record_interaction(agent_id, peer_did, "call_failure", success=False)
```

### Graph-invocation governance gate (inside `run_query`, not a middleware)

```python
# agt-federated-rag/agent/graph.py — run_query()
# Before the graph is even compiled, an AgentMesh govern_action gate runs. The
# mesh client carries a real policy (default-allow + a priority-1000 deny rule on
# kill_switch_engaged), so this is an enforcing OPERATOR KILL-SWITCH — defense in
# depth on top of the real data-path controls (per-node _enforce default-deny +
# OpenFGA per-chunk ReBAC), not a data-authorization control.
gov = await govern_action(
    "agent.graph.invoke",
    {"user_id": user_id, "task_id": task_id,
     "kill_switch_engaged": settings.agent_kill_switch_engaged},
)
if not gov.allowed:
    raise PermissionError(...)   # short-circuits before any node/retrieval/LLM

# Graph runs ONLY if the gate allows
graph = await _get_compiled_graph()
final_state = await graph.ainvoke(initial_state)
```

> When `AGENT_KILL_SWITCH_ENGAGED=true`, the `/query` endpoint also refuses up front
> with HTTP **503**; the internal `govern_action` deny is caught inside the request
> handlers (SSE `error` event on `/query`, signed `status="failed"` on `/a2a/query`)
> — the guarantee is the early denial, not a 403. It's a deploy-time lever (settings
> read once at startup → restart to engage), NOT a trust-based auto-trip.

### SRE middleware (agent_sre)

```python
# agt-federated-rag/sre.py
class LatencyComplianceSLI(SLI):
    def collect(self) -> SLIValue:
        # fraction of requests within latency budget (mean over 1h window)

class SREMiddleware:
    _slo = SLO(
        name="api_latency_slo",
        indicators=[LatencyComplianceSLI(target=0.99, window="1h")],
    )
    # Records good/bad event per request; logs SLO breach if latency > budget_ms
```

---

## AGT / AgentMesh additions (Cluster-B only)

Cluster-B runs `agt-federated-rag/`, which adds a Microsoft AGT / AgentMesh layer around its LangGraph agent.

| Feature | Code | What it does |
|---------|------|--------------|
| Graph-invocation gate | `agent/graph.py` (`run_query`) | `run_query` calls `govern_action("agent.graph.invoke")` before the graph compiles — emits an AgentMesh audit event and is an enforcing operator kill-switch (deny on `kill_switch_engaged`; deploy-time lever — requires restart to engage). It is a gate inside `run_query`, **not** a middleware that wraps `StateGraph.ainvoke()`. |
| AgentMesh DID | `mesh/agent_identity.py` | Cluster-B has a permanent Ed25519 identity; every callback is signed |
| Signature verification | `mesh/agent_identity.py:verify_signed_message()` | Inbound A2A callbacks rejected if signature doesn't verify against payload |
| Trust scoring | AgentMesh registry | Tracks **peer** trust (decays a peer's score on IATP/policy/call failures); gates peer actions. NOTE: self-trust only ever rises, so it does **not** drive the kill-switch — the kill-switch is the operator flag above. |
| SRE middleware | `sre.py:SREMiddleware` | Per-request SLO tracking; P99 latency budget enforced |
| `/identity` endpoint | `api/main.py:identity()` | Returns `{did, cluster, public_key_jwk}` for peer configuration |

The A2A callback from Cluster-B to Cluster-A uses:
```json
{
  "status": { "state": "completed" },
  "_agentmesh": {
    "sender_did": "did:mesh:cluster-b-...",
    "signature": "<base64-Ed25519-sig-over-payload>"
  }
}
```

---

## UI Walkthrough (step-by-step)

### Context

You are the **AI Governance platform** for a financial services firm. Two teams each have their own RAG cluster:
- **Cluster-A** (alice) = Internal AI Operations team — model deployment policies, incident procedures, bias testing requirements
- **Cluster-B** (bob) = Regulatory Compliance team — EU AI Act, GDPR, risk assessment frameworks

The clusters federate: when the AI Ops team needs a regulatory answer, Cluster-A asks Cluster-B via A2A. Neither team stores the other's data.

### Setup
1. `.\scripts\clusters.ps1 start all` — starts both clusters and the Vite UI
2. Open `http://localhost:5173`
3. Left pane: login as **alice** (seeded password from `RAG_SEED_PASSWORD`) → AI Operations (Cluster-A)
4. Right pane: login as **bob** (same seeded password) → Regulatory Compliance (Cluster-B)
5. Click **Monitor ⬆** to open the agent communications panel

### Walkthrough sequence

**Act 1 — Local answer (Flow A): AI Ops policy question**
- Alice types: `What do we need before deploying a new AI model to production?`
- Watch monitor: `retrieve_local → check_auth (LOCAL_ALLOWED) → generate_answer`
- GLM-5.1 returns the full deployment checklist (model card, bias report, CISO approval, monitoring dashboards)
- Talking point: answer came entirely from Cluster-A's internal policy knowledge base — no cross-cluster call needed

**Act 2 — Cross-cluster A2A (Flow C): Regulatory question**
- Alice types: `Does our customer credit scoring model need to comply with the EU AI Act?`
- Monitor shows: `no local match → HMAC-signed A2A request → cluster-b → compliance RAG → answer back`
- GLM-5.1 answers using Cluster-B's EU AI Act knowledge — credit scoring is Annex III high-risk
- **Talking point:** Alice's identity was cryptographically delegated to Cluster-B via RFC 8693. Cluster-B verified the HMAC signature before processing. The compliance data never left Cluster-B — only the answer crossed.

**Act 3 — Approval required (Flow B): Sensitive data access**
- Alice types: `Can you show me the training data used for the fraud detection model?`
- Task enters `⏳ Awaiting approval` — data access requires governance sign-off
- Monitor shows: Temporal approval workflow started, HMAC-signed approval link generated
- Talking point: the Slack link is signed with `HMAC-SHA256(secret, request_id + decision + expiry)` — cannot be forged, expires after 24 hours

**Act 4 — Compliance team query (Cluster-B direct)**
- Bob types: `What are our obligations when an AI system makes an automated hiring decision?`
- Answer: GDPR Article 22 + EU AI Act high-risk classification for employment AI
- Talking point: before the graph runs, `run_query` calls AGT's `govern_action("agent.graph.invoke")` gate — it emits an AgentMesh audit event and acts as an enforcing operator kill-switch; the real per-request authorization is per-node `_enforce` (default-deny) + OpenFGA per-chunk ReBAC

**Act 5 — Another A2A scenario**
- Alice types: `We had an AI model produce biased outputs in production — what do we do?`
- Cluster-A handles the incident response procedure locally (Severity 1, page AI governance lead within 15 min)
- Then Alice follows up: `Does GDPR require us to notify anyone about this AI incident?`
- This crosses to Cluster-B — notification obligations under GDPR Article 33 + EU AI Act post-market monitoring

**Act 6 — DID-signed identity (show in browser)**
- Navigate to `http://localhost:8002/identity`
- Shows Bob's cluster DID and public JWK
- Talking point: in production, every A2A message Cluster-B sends to Cluster-A is Ed25519-signed with this key. Cluster-A refuses any callback without a valid signature.

---

## Security Model Summary

| Threat | Control | Code |
|--------|---------|------|
| Forged user requests | Keycloak JWT, JWKS validation | `auth/token_exchange.py:validate_token()` |
| User reads another user's task | Redis owner_id check, 404 not 403 | `api/main.py:get_task()` — fix S-7 |
| Forged peer callbacks | JWT `client_id` allowlist + `awaiting_peer_callback` flag | `api/main.py:task_callback()` — fix C-4/Finding #3 |
| Forged AGT callbacks | Ed25519 signature over payload | `mesh/agent_identity.py:verify_signed_message()` |
| Approval link replay | HMAC-SHA256 + expiry in signed message | `api/main.py:_verify_approval_token()` — fix C-2/Finding #2 |
| Token in logs/traces | ContextVar — never in LangGraph state | `agent/graph.py` — fix C-5 |
| Excessive query size | Body-size ASGI middleware (never buffers SSE) | `api/main.py:_LimitBodySizeMiddleware` — fix S-1/Q-1 |
| Rate abuse | Redis fixed-window per user | `api/main.py:_check_rate_limit()` — Finding #7 |
| OpenFGA pending access | Temporal grants `viewer` tuple only after approval | `workflow/activities.py` — fix H-6 |
| Cross-cluster identity forgery | RFC 8693 token delegation, not raw credential sharing | `auth/token_exchange.py:exchange_token()` |
