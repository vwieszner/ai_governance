# Federated RAG — Secure Multi-Agent AI Governance Platform

## What this is

A production-quality, secure **federated Retrieval-Augmented Generation (RAG)** system that
delivers real AI governance: the same agent codebase runs as **two federated clusters** —
each with its own knowledge collection and authorization scope — that collaborate to answer a
user's question **without ever sharing raw data**. Every chunk of knowledge is access-controlled
per user (relationship-based authorization), sensitive answers are gated behind **human approval**
workflows, and when one cluster needs the other's data the user's identity is **cryptographically
delegated** across the trust boundary via **RFC 8693 token exchange** and an **A2A** (agent-to-agent)
call. A side-by-side React UI shows both users at once with a live monitor of the agent
communication. Nothing is mocked — real Keycloak, OpenFGA, Temporal, Qdrant, Neo4j and an
NVIDIA-hosted LLM are wired in end to end.

> **One concept, two clusters — and two independent federations.** Each solution is a *single*
> codebase that runs as **two federating clusters**, selected by the `RAG_ENV_FILE` environment
> variable (`.env` = cluster-a, `.env.cluster-b` = cluster-b):
>
> - **`federated-rag/`** (ports 8000 / 8002) — the **A2A** federation: cross-cluster delegation via
>   **RFC 8693** OAuth token exchange and the **A2A** protocol.
> - **`agt-federated-rag/`** (ports 8010 / 8012) — the **AGT / AgentMesh** federation: the *same*
>   four governance flows, but cross-cluster trust is built on **DID identities with per-message
>   Ed25519 signatures** over a real HTTP `/a2a/query` transport, with the AgentMesh governance
>   engine deciding each agent action.
>
> The two directories are two *different governance approaches* to the same problem, each a complete
> two-cluster federation — not two halves of one system.

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
                │  federated-rag/  :8000     │   │  federated-rag/  :8002         │
                │  RAG_ENV_FILE=.env         │◀─▶│  RAG_ENV_FILE=.env.cluster-b  │
                │  FastAPI + LangGraph       │A2A│  FastAPI + LangGraph           │
                │  A2A protocol              │   │  A2A protocol                  │
                │  RFC 8693 token exchange   │   │  (same codebase, cfg differs) │
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
   │  Neo4j      :17687  graph-retrieval seam (scaffolded; current deployment is Qdrant-only) │
   │  Redis      :6379   task store          (db /1 = cluster-a, db /2 = cluster-b)   │
   └───────────────────────────────────────────────────────────────────────────────┘
```

Keycloak, OpenFGA, Temporal and Postgres run from `docker-compose.yml` (loopback-only binds,
preshared-key auth on OpenFGA, no default passwords). Qdrant, Neo4j and Redis are existing host
containers (`claude-qdrant`, `claude-neo4j`, `storyteller-redis-1`) re-seeded by `setup_all.py`.

---

## The governance story

The system makes four governance controls concrete and observable:

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
- **Hardened agent-to-agent (A2A) callbacks.** Cross-cluster push callbacks are gated by an OAuth
  `client_id` allowlist *and* an `awaiting_peer_callback` flag set only when the outbound peer call
  was made, so a callback can't be forged, replayed, or target a task the peer never participated in.
  (The separate `agt-federated-rag/` variant additionally signs callbacks with an Ed25519 DID — see
  that directory for the AgentMesh approach.)

The orchestration is a **LangGraph** state machine
(`retrieve_local → check_auth → {generate_answer | start_approval | call_peer_agent} →
format_response`). A fifth path (local-denied) exists in code for the no-access, no-peer case.

---

## The 4 governance flows

Log in as **alice** (seeded password from `RAG_SEED_PASSWORD`, default `Rag-User-2026!`) in the left (Cluster A) pane and type the query. Open the Monitor
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
| Vector retrieval | **Qdrant + FastEmbed** | Hybrid `BAAI/bge-large-en-v1.5` dense + `Qdrant/bm25` sparse, server-side RRF — **this is the retrieval that actually runs** |
| Graph retrieval | **Neo4j** (scaffolded, not yet exercised) | The `neo4j-graphrag` seam is wired into both codebases and RRF-fused with Qdrant, but **no graph traversal / entity-neighbourhood expansion is performed** and the current deployment runs Qdrant-only — see the GraphRAG note below |
| Agent governance | **AGT / AgentMesh** (the `agt-federated-rag/` federation) | DID identity, per-message Ed25519 signing, registry trust, governed actions |
| Inter-agent protocol | **A2A** | Typed `AgentCard` / `Task` / status-update messaging between clusters |
| API | **FastAPI** | Both backends; SSE streaming |
| Frontend | **React + Vite** | Side-by-side dual-user UI with live agent monitor |
| LLM | **NVIDIA NIM — `meta/llama-3.3-70b-instruct`** (configurable via `LLM_MODEL`) | Answer generation (any OpenAI-compatible model/endpoint) |

---

## Quick start

From the repo root (`D:\work\ai_governance\ai_governance\`), using the project venv:

```powershell
# 1. Start governed infrastructure (Keycloak, OpenFGA, Temporal, Postgres)
docker compose up -d
#    plus the existing host containers for vectors/graph/cache:
docker start claude-qdrant claude-neo4j storyteller-redis-1

# 2. Generate secrets (random infra passwords, OpenFGA token, HMAC keys) into a gitignored .env
.venv\Scripts\python.exe init_secrets.py          # needs NVIDIA_API_KEY in your environment

# 3a. A2A federation: OpenFGA store, Keycloak realm + users, ingest, seed tuples  (~30s, 6/6 PASS)
.venv\Scripts\python.exe setup_all.py --no-neo4j
# 3b. AGT federation: DID identities, AGT clients, ingest, seed tuples            (~30s, 6/6 PASS)
.venv\Scripts\python.exe setup_agt.py --no-neo4j

# 4. Start the backends. scripts/clusters.ps1 manages all four by name and persists across turns:
.\scripts\clusters.ps1 start a2a-a a2a-b agt-a agt-b   # or: .\scripts\clusters.ps1 start all
.\scripts\clusters.ps1 status                          # health of all four + the UI
#    (launch_all.ps1 also starts the A2A backends + workers + UI in one shot.)
```

Then open **http://localhost:5173** and log in as **alice** (left, cluster-a `:8000`) and
**bob** (right, cluster-b `:8002`) — seeded password from `RAG_SEED_PASSWORD` (default `Rag-User-2026!`). The UI drives the **A2A** federation; the **AGT**
federation (`:8010` / `:8012`) is exercised via its `POST /query` SSE endpoint (see
`agt-federated-rag/_repro_agt.py`). Stop everything with `.\scripts\clusters.ps1 stop all`.

> **Note:** after running `setup_all.py` / `setup_agt.py` (which rotate that solution's OpenFGA
> store id), restart that solution's backends so they pick up the new store —
> `.\scripts\clusters.ps1 restart a2a-a a2a-b` (or `agt-a agt-b`).

> **GraphRAG / Neo4j status (what actually runs).** Retrieval is currently **Qdrant-only**
> (hybrid dense + sparse with server-side RRF). The Neo4j graph-retrieval path is scaffolded but
> **inert**, and even when populated it does plain vector/keyword lookup of chunks — there is **no
> graph traversal or entity-neighbourhood expansion** (`neo4j_graph_hops` is reserved and unused):
> - **AGT** (`agt-federated-rag/`): the ingest pipeline only upserts Qdrant and never writes Neo4j,
>   so the graph retriever always degrades to empty and contributes nothing to fusion.
> - **A2A** (`federated-rag/`): the full ingest path *can* populate Neo4j (run `setup_all.py`
>   **without** `--no-neo4j`; slower, one LLM call per chunk) and the retriever is a `HybridRetriever`
>   (vector + keyword), but the documented bring-up runs `--no-neo4j`, so the Neo4j path is not exercised.
>
> After any Docker restart that drops Qdrant data, re-run step 2 to re-ingest and re-seed.

---

## Project layout

| Path | Contents |
|------|----------|
| `federated-rag/` | The **A2A federation** — one codebase run as **both** clusters (cluster-a `:8000` via `.env`, cluster-b `:8002` via `.env.cluster-b`). FastAPI `api/`, LangGraph `agent/` (graph + nodes + state), `rag/` (Qdrant hybrid retrieval + a scaffolded-but-unexercised Neo4j graph-retrieval seam + RRF fusion + ingest), `auth/` (OpenFGA checks, JWT validation, RFC 8693 exchange), `a2a/` (peer client + Pydantic models), `workflow/` (Temporal approval + activities + worker). Also `tests/docs/` source documents. |
| `agt-federated-rag/` | The **AGT / AgentMesh federation** — one codebase run as **both** clusters (cluster-a `:8010`, cluster-b `:8012`). Same RAG/auth/workflow structure plus `mesh/` (Ed25519 DID identity, signed peer client + the real HTTP `/a2a/query` transport), `sre.py` (SLO/SLI middleware), and an AGT `govern_action("agent.graph.invoke")` gate inside `run_query` in `agent/graph.py` (an enforcing operator kill-switch, not a wrapping middleware). Bring-up: `setup_agt.py`. |
| `ui/` | React + Vite frontend. `src/components/` (LoginForm, ChatArea, MonitorPanel, UserPane, TaskMessage), `src/api/` (auth, rag). `.env.prod` points the UI at the real backends + Keycloak. |
| `scripts/` | `clusters.ps1` (start/stop/restart/status for all four backends + workers, by name: `a2a-a a2a-b agt-a agt-b`) and `logs.ps1` (filtered tail of a backend's structured log). |
| (root) | `docker-compose.yml`, `setup_all.py` (A2A federation), `setup_agt.py` (AGT federation), `init_secrets.py`, `launch_all.ps1`, and the docs below. |

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
- **AGT graph-invocation gate** (the `agt-federated-rag/` federation) — `run_query` calls
  `govern_action("agent.graph.invoke")` (AgentMesh) before the graph is compiled, and the mesh client
  now carries a real policy (default-allow + a priority-1000 deny on `kill_switch_engaged`), so it is
  an **enforcing operator kill-switch** (deploy-time — `settings` is read once at startup, so engaging
  it requires setting `AGENT_KILL_SWITCH_ENGAGED=true` and **restarting** the agent; it is not an
  instant runtime lever, nor a trust-based auto-trip): with the flag set, the query path is refused
  (`/query` → 503) and the internal deny short-circuits before any node/retrieval/LLM. It is
  defense-in-depth — the real data-path controls are per-node `_enforce` (default-deny) + OpenFGA
  per-chunk ReBAC. Cross-cluster calls are authenticated by **per-message Ed25519 DID signatures**
  verified in both directions, with registry-membership trust gating peer actions.

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
