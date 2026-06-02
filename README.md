# Federated RAG — Secure Multi-Agent AI Governance Demo

## What this is

A production-quality, secure **federated Retrieval-Augmented Generation (RAG)** system that
demonstrates real AI governance: two independent FastAPI agents — each with its own vector
store, knowledge graph, and identity — collaborate to answer a user's question **without ever
sharing raw data**. Every chunk of knowledge is access-controlled per user (relationship-based
authorization), sensitive answers are gated behind **human approval** workflows, and when one
cluster needs the other's data the user's identity is **cryptographically delegated** across the
trust boundary (RFC 8693 token exchange) over a **DID-signed agent-to-agent** channel. A
side-by-side React UI shows both users at once with a live monitor of the agent communication.
Nothing is mocked — real Keycloak, OpenFGA, Temporal, Qdrant, Neo4j and an NVIDIA-hosted LLM
are wired in end to end.

---

## Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │  Browser UI — React + Vite  (port 5173)      │
                         │                                              │
                         │   alice  ◀── side-by-side ──▶  bob           │
                         │  (Cluster A)                 (Cluster B)      │
                         │   ChatArea          Live Monitor Panel       │
                         └───────┬──────────────────────────┬───────────┘
                                 │ JWT + SSE                 │ JWT + SSE
                                 │ (login via Keycloak OIDC) │
                ┌────────────────▼──────────┐   ┌────────────▼─────────────────┐
                │  Cluster A                 │   │  Cluster B                    │
                │  federated-rag/  :8000     │   │  agt-federated-rag/  :8002    │
                │  A2A protocol              │◀─▶│  AGT / AgentMesh DID identity │
                │  FastAPI + LangGraph       │A2A│  FastAPI + LangGraph          │
                │                            │   │  + GovernanceMiddleware       │
                │  RFC 8693 token exchange   │   │  Ed25519 DID-signed callbacks │
                └─────────────┬──────────────┘   └─────────────┬────────────────┘
                              │      both clusters share one    │
                              ▼      governed infrastructure     ▼
   ┌───────────────────────────────────────────────────────────────────────────────┐
   │  SHARED INFRASTRUCTURE (one instance each; logically partitioned per cluster)   │
   ├───────────────────────────────────────────────────────────────────────────────┤
   │  Keycloak   :8087   one realm `rag`, users alice/bob, both agent OAuth clients   │
   │  OpenFGA    :8089   one store + model; per-chunk viewer/owner/pending tuples     │
   │  Temporal   :7233   approval workflows  (queues: approval-queue-a / -b)          │
   │  Postgres           durable datastore for OpenFGA (compose volume)               │
   │  Qdrant     :16333  hybrid vectors      (collections: knowledge_base_a / _b)     │
   │  Neo4j      :17687  GraphRAG entity graph                                        │
   │  Redis      :6379   task store          (db /1 = cluster-a, db /2 = cluster-b)   │
   └───────────────────────────────────────────────────────────────────────────────┘
```

Keycloak, OpenFGA, Temporal and Postgres run from `docker-compose.yml`. Qdrant, Neo4j and Redis
are existing host containers (`claude-qdrant`, `claude-neo4j`, `storyteller-redis-1`) re-seeded by
`setup_all.py`.

---

## The governance story

This demo exists to make four governance controls concrete and observable:

- **Per-chunk authorization (ReBAC).** Access is not "who can use the app" but "who can read
  *this specific chunk*." OpenFGA holds `viewer` / `owner` / `pending_approval` relationship
  tuples keyed by the user's Keycloak `sub` UUID and the chunk ID. After hybrid retrieval, every
  candidate chunk is checked individually; only authorized chunks reach the LLM.
- **Human approval in the loop.** When a user has only `pending_approval` (not `viewer`) on the
  matched data, the agent does not answer. It starts a **Temporal** approval workflow and returns
  `input-required`. An approver opens an HMAC-signed, time-limited deep link; on approval the
  workflow writes the `viewer` tuple and the answer is released.
- **Cross-cluster delegation via RFC 8693.** When Cluster A has no local match, it does not
  forward raw credentials. It performs an **OAuth 2.0 Token Exchange** (RFC 8693) at Keycloak to
  mint a delegated token whose audience is the peer agent's client ID, then calls the peer on the
  user's behalf. The peer re-evaluates authorization for the delegated identity — data stays put,
  only the answer crosses.
- **DID-signed agent-to-agent (A2A).** Cluster B (`agt-federated-rag`) holds a permanent
  AgentMesh Ed25519 **DID identity**. Inbound peer callbacks are verified against a trusted,
  out-of-band public key; cross-cluster callbacks are also gated by an OAuth `client_id` allowlist
  and an `awaiting_peer_callback` flag so a callback can't be forged or replayed.

The orchestration is a **LangGraph** state machine
(`retrieve_local → check_auth → {generate_answer | start_approval | call_peer_agent} →
format_response`). A fifth path (local-denied) exists in code for the no-access, no-peer case.

---

## The 4 demo flows

Log in as **alice / demo** in the left (Cluster A) pane and type the query. Open the Monitor
panel to watch the agent steps live.

| Flow | Query to type (as alice) | What happens | End state |
|------|--------------------------|--------------|-----------|
| **A — Local, authorized** | `What is our data retention policy for customer records?` | Hybrid retrieval finds the chunk in Cluster A; OpenFGA grants alice `viewer`; the LLM answers directly. | `completed` |
| **B — Local, needs approval** | `What are the salary bands for senior engineers?` | The HR-compensation chunk is owned by bob; alice has only `pending_approval`. A Temporal approval workflow starts and an HMAC-signed approval link is generated. | `input-required` |
| **C — Remote, A2A federation** | `What Kubernetes version are we running and what is the cluster topology?` | No local match. Cluster A does an RFC 8693 token exchange and calls Cluster B over A2A; Cluster B authorizes the delegated alice as `viewer`, answers, and the answer flows back. | `completed` |
| **D — Cross-cluster approval** | `What was our Q4 revenue and ARR growth?` | Cluster A federates to Cluster B as in C, but the Q4-financial chunk needs approval there. Cluster B returns `input-required`; Cluster A surfaces the pending approval back to alice and waits for the signed peer callback. | `input-required` |

Source documents live in `federated-rag/tests/docs/cluster-a/` (`data_retention_policy`,
`hr_compensation_data`) and `…/cluster-b/` (`technical_architecture`, `q4_financial_results`).
The matching OpenFGA tuples are seeded by `setup_all.py` (its summary prints **6/6 PASS**).

---

## Tech stack

| Layer | Technology | Role |
|-------|-----------|------|
| Agent orchestration | **LangGraph** `StateGraph` | Directed state machine driving all flows |
| Authorization | **OpenFGA** (ReBAC) | Per-chunk `viewer` / `owner` / `pending_approval` tuples |
| Human approval | **Temporal** | Signal-based approval workflows, 24 h timeout |
| Identity / OIDC | **Keycloak** | Realm `rag`, JWT issuance, JWKS validation, RFC 8693 token exchange |
| Cross-cluster identity | **RFC 8693 Token Exchange** | Delegate the user's identity to the peer agent |
| Vector retrieval | **Qdrant + FastEmbed** | Hybrid `BAAI/bge-large-en-v1.5` dense + `Qdrant/bm25` sparse, server-side RRF |
| Graph retrieval | **Neo4j GraphRAG** | Entity-graph context (embeddings: `nvidia/nv-embedqa-e5-v5`) |
| Agent governance | **AGT / AgentMesh** (Cluster B) | DID identity, GovernanceMiddleware, trust scoring, SRE/SLO |
| Inter-agent protocol | **A2A** | Typed `AgentCard` / `Task` / status-update messaging between clusters |
| API | **FastAPI** | Both backends; SSE streaming |
| Frontend | **React + Vite** | Side-by-side dual-user UI with live agent monitor |
| LLM | **NVIDIA NIM — `z-ai/glm-5.1`** (GLM-5.1) | Answer generation (OpenAI-compatible endpoint) |

---

## Quick start

From the repo root (`D:\work\ai_governance\ai_governance\`), using the project venv:

```powershell
# 1. Start governed infrastructure (Keycloak, OpenFGA, Temporal, Postgres)
docker compose up -d
#    plus the existing host containers for vectors/graph/cache:
docker start claude-qdrant claude-neo4j storyteller-redis-1

# 2. Create OpenFGA store, Keycloak realm + users, ingest docs, seed tuples  (~30s, prints 6/6 PASS)
.venv\Scripts\python.exe setup_all.py --no-neo4j

# 3. Launch both backends + Temporal workers + UI
.\launch_all.ps1
```

Then open **http://localhost:5173** and log in: **alice / demo** (left, Cluster A) and
**bob / demo** (right, Cluster B). Stop everything with `.\launch_all.ps1 -Stop`.

> **Known issue:** `launch_all.ps1` still health-checks Cluster B on the retired port 8001 and
> aborts before starting the UI. The backends are already running by then — just start the UI
> manually. See **Troubleshooting** below.

> `--no-neo4j` runs a fast Qdrant-only ingest (GraphRAG context is empty). For full Neo4j
> GraphRAG, run `setup_all.py` **without** `--no-neo4j` (slower; one LLM call per chunk).
>
> After any Docker restart that drops Qdrant data, re-run step 2 to re-ingest and re-seed.

---

## Project layout

| Path | Contents |
|------|----------|
| `federated-rag/` | **Cluster A** backend (A2A). FastAPI `api/`, LangGraph `agent/` (graph + nodes + state), `rag/` (Qdrant hybrid + Neo4j GraphRAG + RRF fusion + ingest), `auth/` (OpenFGA checks, JWT validation, RFC 8693 exchange), `a2a/` (peer client + Pydantic models), `workflow/` (Temporal approval + activities + worker). Also `tests/docs/` source documents. |
| `agt-federated-rag/` | **Cluster B** backend (AGT / AgentMesh). Same RAG/auth/workflow structure plus `mesh/` (Ed25519 DID identity, signed peer client), `sre.py` (SLO/SLI middleware), and AGT `GovernanceMiddleware` wrapping the LangGraph in `agent/graph.py`. |
| `ui/` | React + Vite frontend. `src/components/` (LoginForm, ChatArea, MonitorPanel, UserPane, TaskMessage), `src/api/` (auth, rag, nvidia). `.env.prod` points the UI at the real backends + Keycloak. |
| `demo/` | **Legacy, superseded.** Pre-real mock clusters (`cluster_a.py`, `cluster_b.py`, `knowledge_*.json`, `start.ps1`). Kept for reference; the real launch path is `launch_all.ps1`, not `demo/start.ps1`. Slated for deletion. |
| (root) | `docker-compose.yml`, `setup_all.py`, `launch_all.ps1`, helper scripts (`bootstrap_keycloak.py`, `enable_token_exchange.py`), and the docs below. |

---

## Security

Controls implemented across both clusters (see **SECURITY_AUDIT.md** for the full audit and the
existing **SECURITY_REVIEW.md** for the detailed findings log):

- **JWT / JWKS validation** on every request; algorithms locked to RS256 (Keycloak).
- **Per-chunk ReBAC** — OpenFGA `check` per retrieved chunk; only authorized chunks reach the LLM.
- **Human approval gate** — Temporal workflow holds sensitive answers until an approver decides.
- **HMAC-signed approval links** — `HMAC-SHA256` over `request_id + decision + expiry`; expiry is
  part of the signed message, so links cannot be forged, extended, or replayed.
- **RFC 8693 cross-cluster delegation** — the peer receives a delegated token (audience = peer
  client ID), never the raw user credential.
- **Ed25519 DID-signed A2A callbacks** — verified against a trusted, out-of-band public key, not
  any key carried in the message body.
- **Peer callback hardening** — callbacks require both an allowlisted OAuth `client_id` and an
  `awaiting_peer_callback` flag set when the outbound peer call was made.
- **Token isolation** — the user token is passed via a ContextVar, never stored in LangGraph state
  or logs/traces.
- **Pending ≠ access** — the `viewer` tuple is written only *after* approval; `pending_approval`
  alone never grants reads.
- **Per-user rate limiting** (Redis fixed-window) and an **ASGI body-size limit** (never buffers
  SSE) protect the expensive query endpoint.
- **AGT GovernanceMiddleware** (Cluster B) enforces policy and emits audit events before the graph
  runs; **trust scoring** decays a misbehaving peer's score toward a kill-switch threshold.

---

## Troubleshooting

- **Docker restart loses Qdrant data.** Qdrant/Neo4j/Redis are host containers and Qdrant is
  ephemeral; after a restart the ingested chunks are gone. Re-run
  `.venv\Scripts\python.exe setup_all.py --no-neo4j` to re-ingest and re-seed tuples (Keycloak
  realm + OpenFGA store persist via compose volumes, so user `sub` UUIDs are stable across
  restarts — only a `docker rm` of Keycloak would change them).
- **Corporate CA / NVIDIA TLS.** The backends inject `truststore` so Python uses the OS
  certificate store, and the UI is launched with `NODE_OPTIONS=--use-system-ca`. This is already
  handled in the launch path; no extra step is needed.
- **Port 8001 is intentionally avoided.** Cluster B runs on **8002**, not 8001 — a `wslrelay`
  process holds IPv6 `[::1]:8001`, which caused 404s on the health check. `setup_all.py`,
  `.env.prod` and the peer URLs all use 8002.
- **`launch_all.ps1` aborts before the UI starts.** The script still health-checks Cluster B on
  the retired port 8001, so it prints `cluster-b-api did NOT become healthy` and exits ("Aborting
  UI launch") before running Vite. The backends and workers are already up by then (Cluster A on
  8000, Cluster B on 8002 — started before the check), so just start the UI manually:
  ```powershell
  cd ui; $env:NODE_OPTIONS="--use-system-ca"; npx vite --mode prod
  ```
- **`launch_all.ps1 -Stop` misses Cluster B's API.** `-Stop` frees ports 8000 / 8001 / 5173 and
  kills the Temporal workers, but Cluster B's API on **8002** survives. Stop it separately, e.g.
  find and kill the listener on 8002 (`netstat -ano | findstr :8002` → `taskkill /PID <pid> /F`).
- **Backend won't become healthy.** Each process logs to `_<name>.out` / `_<name>.err` in the repo
  root (e.g. `_cluster-a-api.err`). Check those first.
- **NVIDIA endpoint DNS.** If LLM calls fail to resolve, the host file may pin a stale CloudFront
  IP for `integrate.api.nvidia.com`; re-resolve and update it.
