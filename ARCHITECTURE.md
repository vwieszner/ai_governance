# Architecture — AGT Federated RAG

How the system is wired: components, the request **dataflow**, the **callgraph**, the
cross-division **federation + offline-delivery** sequence, and where each **security control**
sits on the path. Diagrams are Mermaid (render on GitHub / most Markdown viewers).

> Companion docs: `README.md` (what + setup), `PROJECT_STATUS.md` (what's built),
> `THREAT_MODEL.md` (security posture), `k8s/README.md` (Kubernetes), `docs/archive/` (history).
> This file is the **structure**; those are scope, status, and security.

---

## 1. Component / deployment view

Each **division** is a physically-isolated stack (own IdP realm, ReBAC store, vector DB,
workflow engine, secrets, and Ed25519 DID). Nothing shared crosses a division boundary (NFR-2);
cross-division traffic is **only** the DID-signed `/a2a/*` path.

```mermaid
flowchart TB
    UI["UI · React/Vite<br/>BFF cookie auth"]
    DISC["Discovery service<br/>DID-signed registry"]

    subgraph A["Division ALPHA — isolated stack"]
      direction LR
      AG["agent<br/>FastAPI :8000"]
      WK["worker<br/>Temporal"]
      SVC["backing services (this division only)<br/>Keycloak · OpenFGA+Postgres · Qdrant<br/>Redis · Temporal · DID Ed25519"]
      AG --> SVC
      WK --> SVC
    end

    subgraph B["Division BETA — same shape"]
      AGB["agent + own stores + DID"]
    end

    UI -->|"OIDC / BFF · JWT"| AG
    AG <-->|"/a2a · signed + mTLS"| AGB
    AG -.->|"discover"| DISC
    AGB -.-> DISC

    classDef div fill:#eef,stroke:#88a
    class A,B div
```

**Isolation mechanics:** on Kubernetes each division is its own Namespace with a default-deny
`NetworkPolicy` (only the agent pod, only `/a2a` on :8000, is reachable cross-namespace). On
Compose each division is its own project/network. The discovery service never holds division
data — its loss degrades discovery, never authorization.

---

## 2. Request dataflow — the governed LangGraph pipeline

Every `/query` runs the **same 7-node graph** (`agent/graph.py`). Each node calls `_enforce()`
(default-deny policy) **before** doing work. Authorization is decided per-chunk **after**
retrieval and **before** generation, so denied data never reaches the LLM.

```mermaid
flowchart TD
    START([/query SSE]) --> RL["retrieve_local<br/>_enforce rag.retrieve<br/>fan out N retrievers → RRF fuse"]
    RL --> CA["check_auth<br/>_enforce auth.check_permission<br/>OpenFGA batch_decide per chunk_id<br/>+ re-source TEXT from trusted store"]

    CA -->|"LOCAL_ALLOWED"| GA["generate_answer<br/>_enforce llm.generate<br/>spotlight + hardened prompt"]
    CA -->|"LOCAL_NEEDS_APPROVAL"| SA["start_approval<br/>_enforce approval.start_workflow<br/>→ Temporal ApprovalWorkflow"]
    CA -->|"REMOTE (no local data)"| CP["call_peer_agent<br/>_enforce peer.send_message<br/>discover → sign → /a2a/query"]
    CA -->|"LOCAL_DENIED"| FR

    CP -->|ok| HP["handle_peer_result<br/>_enforce peer.receive_callback<br/>spotlight peer answer"]
    CP -->|error / circuit open| FR
    HP --> FR

    GA --> FR["format_response<br/>_enforce agent.output_check<br/>OUTPUT DLP hard-deny"]
    SA --> FR
    FR --> END([SSE: status · result · done])

    classDef gate fill:#fee,stroke:#c66
    class RL,CA,GA,SA,CP,HP,FR gate
```

**The three-way authorization outcome** (`check_auth` → OpenFGA `batch_decide`): every retrieved
`chunk_id` resolves to **allowed** / **needs-approval** / **denied**. Flow priority:
`pending > allowed > remote(only if no local data) > denied`. A RaaS/external retriever can
contribute candidate ids + ranking, but the served **text** is re-sourced from the trusted
store of record — so an external backend can never widen access *or* poison content.

---

## 3. Callgraph — endpoint → graph → services

The HTTP surface (`api/main.py`) and which collaborators each path touches. `/query` and
`/a2a/query` share the **same** `run_query` graph; the difference is identity handling at the door.

```mermaid
flowchart LR
    subgraph API["api/main.py (FastAPI)"]
      Q["/query (SSE)"]
      A2A["/a2a/query"]
      RES["/tasks/{id}/result"]
      INB["/inbox · /inbox/{id}/ack"]
      CB["/tasks/{id}/callback"]
      APP["/approvals/pending<br/>/approvals/{id}/decision"]
      REV["/access/revoke"]
      AUD["/audit"]
      KS["/admin/kill-switch"]
    end

    TV["auth/token_validator<br/>validate_token · principal<br/>validate_cross_division_assertion"]
    RUN["agent/graph.run_query"]
    NODES["agent/nodes.*<br/>(7 nodes + _enforce)"]
    RET["rag/retriever · fusion<br/>qdrant_retriever"]
    FGA["auth/openfga<br/>batch_decide · grant · revoke"]
    MESH["mesh/peer_client · discovery<br/>agent_identity (sign/verify)"]
    OUT["outcome_store<br/>(durable per-user inbox)"]
    WF["workflow/* (Temporal)<br/>ApprovalWorkflow · activities"]
    AUDIT["audit_log<br/>(HMAC hash-chain)"]

    Q --> TV --> RUN
    A2A --> TV
    A2A -->|"validated assertion → re-authorize"| RUN
    RUN --> NODES
    NODES --> RET --> FGA
    NODES --> MESH
    NODES --> WF
    RES --> RUN
    INB --> OUT
    INB -->|"regenerate at delivery"| RUN
    CB -->|"verify signer == delegate"| OUT
    APP --> WF
    WF -->|"on decide: notify"| OUT
    WF -->|"grant viewer"| FGA
    REV --> FGA
    AUD --> AUDIT
    KS -->|"Redis flag"| Q
    KS -->|"Redis flag"| A2A
    NODES -. every node .-> AUDIT
```

---

## 4. Cross-division federation + offline delivery (sequence)

The headline path: alice@A asks for B's data she's not yet cleared for; she goes offline;
bob@B approves later; the answer reaches her account on next login — regenerated under a fresh
authorization check (no stale leak).

```mermaid
sequenceDiagram
    autonumber
    participant U as alice (Division A)
    participant A as agent A
    participant D as discovery
    participant B as agent B
    participant OB as outcome_store (A)
    participant TB as Temporal (B)
    participant BB as bob (owner, B)

    U->>A: POST /query (JWT)
    A->>A: retrieve_local + check_auth → no local data → REMOTE
    A->>D: discover capable peer (signed)
    D-->>A: peer = B (DID, endpoint)
    A->>B: POST /a2a/query — Ed25519-signed envelope<br/>+ recipient-bound user assertion (aud=B, exp, jti)
    B->>B: verify sig + replay guard · validate assertion<br/>re-authorize alice vs B's OpenFGA → NEEDS_APPROVAL
    B->>TB: start ApprovalWorkflow (durable)
    B-->>A: input-required
    A->>OB: seed durable "pending" outcome (badge++)
    A-->>U: "⏳ awaiting approval" — alice closes browser

    Note over BB,TB: later…
    BB->>B: GET /approvals/pending → approve (authenticated owner)
    TB->>B: grant viewer (TTL) + a2a callback to A
    B->>A: POST /tasks/{id}/callback (signed)
    A->>A: verify signer == recorded delegate DID
    A->>OB: mark outcome ready (badge++)

    Note over U,A: next login…
    U->>A: GET /inbox
    A->>B: regenerate at delivery (re-run governed pipeline)
    B->>B: re-authorize live (revoked/expired ⇒ "declined")
    A-->>U: the actual answer (or declined) — no stale data
```

---

## 5. Security-control dataflow (where each gate sits)

Same path, annotated with the control at each hop. Every gate **fails closed**.

```mermaid
flowchart TD
    IN([inbound request]) --> KSW{kill-switch?<br/>settings OR Redis flag}
    KSW -->|engaged| D503[503 fail-closed]
    KSW -->|ok| IDP{identity}
    IDP -->|"/query"| JWT["validate_token<br/>issuer+audience+JWKS+exp"]
    IDP -->|"/a2a/query"| SIG["Ed25519 verify + replay guard<br/>+ recipient-bound assertion (aud/exp/signer)"]
    JWT --> PR["principal = email|sha256(iss)<br/>(namespaced — no cross-issuer impersonation)"]
    SIG --> PR
    PR --> POL["per-node _enforce (default-deny policy)"]
    POL --> RBAC["OpenFGA per-chunk ReBAC<br/>allowed / needs-approval / denied (live)"]
    RBAC --> TXT["served text from TRUSTED store only<br/>(RaaS can't poison content)"]
    TXT --> LLM["LLM (no action agency;<br/>denied chunks pruned pre-LLM)"]
    LLM --> DLP["output DLP hard-deny<br/>(credential/secret scan)"]
    DLP --> OUT([release])
    POL -. denial reason .-> AUD[(HMAC hash-chained audit<br/>tamper-proof when keyed)]
    RBAC -. decision .-> AUD
    DLP -. block .-> AUD

    classDef stop fill:#fdd,stroke:#c33
    class D503 stop
```

**Transport (not shown above):** internet-facing `/a2a/*` uses mutual TLS with **CRL revocation
checked at the handshake** (OCSP responder is a deploy-time add). Browser auth uses the **BFF**
pattern — no token in the browser, only an `HttpOnly` cookie.

---

## 6. Where it lives (code map)

| Concern | Module(s) |
|---|---|
| HTTP surface, SSE, kill-switch, /audit, /inbox | `api/main.py` |
| Governed graph + routing | `agent/graph.py`, `agent/nodes.py`, `agent/policies/*.yaml` |
| Retrieval (pluggable, multi + RaaS) | `rag/retriever.py`, `rag/fusion.py`, `rag/qdrant_retriever.py` |
| Per-chunk authorization (ReBAC) | `auth/openfga.py` |
| Identity (token + cross-division assertion) | `auth/token_validator.py` |
| Federation (sign/verify, discover, delegate) | `mesh/agent_identity.py`, `mesh/peer_client.py`, `mesh/discovery.py`, `discovery/` |
| Approvals + offline delivery | `workflow/`, `outcome_store.py` |
| Transport / mTLS / CRL | `transport/mtls.py`, `scripts/issue_division_certs.py` |
| Tamper-proof audit | `audit_log.py` |
| Deployment | `infra/` (Compose IaC), `k8s/` (kustomize) |

Each box above has tests under `agt-federated-rag/tests/` (254 collected); see
`PROJECT_STATUS.md` for the requirement→test mapping.
