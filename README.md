# Federated RAG — Governed Agentic Retrieval (AGT / AgentMesh)

A production-oriented **governed federated-RAG** system built on the **Microsoft AgentMesh**
governance model. A user asks an agent a question; the agent retrieves only the data that user is
authorized to see (OpenFGA ReBAC), runs **every action through a policy engine** before executing
it, and when the answer lives in another cluster — or belongs to another person — it federates the
request and/or opens a **human approval** workflow before releasing anything.

Cross-cluster trust is **cryptographic, not credential-forwarding**: each cluster has a persistent
**Ed25519 DID identity**, every inter-agent message is signed and replay-protected, and a peer is
only trusted if its DID verifies against out-of-band-provisioned keys and clears a registry **trust
score**. This is the single AGT product line (the parallel OAuth/RFC-8693 "A2A" variant lives in a
separate repository — see `PRODUCT_REQUIREMENTS.md`, assumption A-1).

## Architecture at a glance

```
ui/ (React + Vite, :5173)
  alice  -> cluster-a  (agt-federated-rag, :8010)
  bob    -> cluster-b  (agt-federated-rag, :8012)     bob owns data + approves access

agt-federated-rag/   one codebase, run twice via RAG_ENV_FILE (.env = a, .env.cluster-b = b)
  agent/      LangGraph; EVERY node calls _enforce(action) against the AgentMesh policy engine
  agent/policies/  base / data-access / peer-comms policy YAML (OWASP-ASI aligned)
  mesh/       Ed25519 DID identity, signed peer client, real HTTP /a2a/query transport
  auth/        OpenFGA ReBAC decisions + JWT validation
  rag/         Qdrant hybrid retrieval (+ scaffolded, inert Neo4j/GraphRAG seam)
  workflow/    Temporal ApprovalWorkflow + activities + worker
  sre.py       SLO/SLI middleware
  api/         FastAPI: POST /query (SSE), approvals

Shared infra (localhost): Keycloak (:8087) · OpenFGA (:8089) · Temporal (:7233)
  · Postgres · Qdrant (:16333) · Neo4j (:17687) · Redis (:6379)
```

## Prerequisites

- Python 3.11+ with a virtualenv at `.venv` (install `agt-federated-rag/pyproject.toml`).
- Node 18+ (for the UI).
- Docker (Keycloak, OpenFGA, Temporal, Postgres come from `docker-compose.yml`).
- Running Qdrant, Neo4j, and Redis containers (the vector / graph / cache stores).
- An OpenAI-compatible LLM endpoint + key (e.g. NVIDIA NIM) — configured via env, never committed.

## Bring-up (first run, in order)

```powershell
# 1. Generate all secrets into a gitignored root .env (Keycloak admin, OpenFGA token,
#    per-cluster HMAC + client secrets). Nothing secret is tracked in git.
.venv\Scripts\python.exe init_secrets.py

# 2. Start shared infra
docker compose up -d
#    plus your Qdrant / Neo4j / Redis containers

# 3. Provision EVERYTHING for AGT (self-contained): the Keycloak realm + rag-ui client + users,
#    the AGT OpenFGA store + model, the two Ed25519 DID identities (cross-wired peer keys), the
#    agent-agt-a/b clients, document ingestion, and the per-chunk authorization tuples.
.venv\Scripts\python.exe setup_agt.py --no-neo4j

# 4. Launch both AGT backends (+ Temporal workers)
.\scripts\clusters.ps1 start agt-a agt-b
.\scripts\clusters.ps1 status            # health of both backends + UI

# 5. Start the UI
cd ui; $env:NODE_OPTIONS="--use-system-ca"; npx vite --mode prod
```

Then open **http://localhost:5173** — alice on the left (cluster-a `:8010`), bob on the right
(cluster-b `:8012`). User passwords come from `RAG_SEED_PASSWORD` (default `Rag-User-2026!`).

> After re-running `setup_agt.py` (which creates a fresh OpenFGA store id), restart the backends so
> they pick it up: `.\scripts\clusters.ps1 restart agt-a agt-b`.

## Fresh machine? One command

On a new Windows machine, the whole bring-up (venv + pinned deps + npm + per-division
Docker stacks + provisioning + federation + agents) is one script:

```powershell
# Prereqs you install yourself: Python 3.11+, Node 18+, Docker Desktop (running).
# Put your LLM key in .\.env :   NVIDIA_API_KEY=<key>
powershell -File scripts\bootstrap.ps1            # alpha + beta (the demo pair)
powershell -File scripts\bootstrap.ps1 -ThreeDivisions   # + gamma
```

It is idempotent (safe to re-run), checks prerequisites with clear errors, pins all
versions (Python deps via `agt-federated-rag/requirements.lock.txt`, Docker images
pinned in `infra/division-stack.template.yml`), and prints the demo logins when done.
Then: `cd ui; npm run start` and open http://localhost:5173. Expect the first run to
take a while (Docker image pulls); each division is ~7 containers, so 16 GB+ RAM is
comfortable for the two-division demo.

## Per-division deployment (Infrastructure-as-Code)

The production topology is one **physically-isolated stack per division** (its own Postgres,
OpenFGA, Keycloak realm, Temporal, Qdrant, Redis, DID, and ports) — not a shared backend. A
division is declared by a manifest and stood up with **no source edits**:

```powershell
# 1. Declare the division — infra/divisions/<id>.yml (declarative; see alpha/beta/gamma):
#      division_id, port_base, trusted_peers, docs_dir, residency_mode,
#      seed_viewer / seed_approval / cross_grants (per-chunk authz seed)
# 2. Render + stand up the whole stack from infra/division-stack.template.yml and provision it
#    (Keycloak realm + rag-ui client + users, OpenFGA store/model + authz tuples, Ed25519 DID,
#    document ingest). Idempotent.
.venv\Scripts\python.exe scripts\onboard_division.py infra\divisions\alpha.yml
.venv\Scripts\python.exe scripts\onboard_division.py infra\divisions\beta.yml
#    --dry-run renders configs only (no docker/network — CI-safe); --teardown = down -v + cleanup;
#    --force rotates secrets. Colliding port_bases are rejected (see _reserved_ports).

# 3. Cross-wire the federation (peer DIDs + issuers + the per-DID trust map, both directions):
.venv\Scripts\python.exe scripts\federate_divisions.py --only alpha beta

# 4. Run each division's agent + Temporal worker, and check health:
.\scripts\clusters.ps1 start all
.\scripts\clusters.ps1 status all
```

Ports derive from `port_base` so divisions never clash (alpha **9000**, beta **9100**, gamma **9200**):
`agent=base, openfga=+1, keycloak=+2, temporal=+3/+4, qdrant=+5, redis=+6`. Per-division secrets live
in `infra/generated/<id>/` (gitignored). The compose template + manifests + `onboard_division.py` are
the IaC; `tests/test_onboarding.py` unit-tests the pure rendering/port-derivation helpers, and three
divisions (alpha/beta/gamma) are stood up this way.

> **LLM latency note (real-user readiness).** The agent talks to any OpenAI-compatible endpoint via
> `OPENAI_API_BASE`/`OPENAI_API_KEY`. On a free/shared tier (e.g. NVIDIA NIM) the FIRST call after idle
> cold-starts (tens of seconds); steady-state is ~1–3 s. For production, point `OPENAI_API_BASE` at a
> provisioned/always-warm or self-hosted endpoint (`residency_mode: local` keeps inference in-boundary).
> The approval-outcome poll is LLM-free while pending and skips answer re-narration on delivery, so only
> the one answer-generation call is on the critical path.

## The governance flows

- **Local authorized** — alice asks; data is in her cluster and she's allowed; immediate answer.
- **Needs approval** — alice asks for data bob owns; the agent opens a durable Temporal approval and
  the request goes *pending*. bob decides as the verified owner.
- **Remote** — no local hits; the agent federates to the peer cluster over the signed `/a2a/query`
  transport; the peer verifies the DID, authorizes the real user, and answers.

Source documents are bundled at `agt-federated-rag/tests/docs/`; `setup_agt.py` seeds the matching
OpenFGA tuples and prints a PASS/FAIL summary.

## The governance toolkit (what is actually enforced)

- **Per-action policy evaluation.** Every LangGraph node calls `_enforce(action, context)` against
  the AgentMesh `PolicyEvaluator` (`agent/policies/*.yaml`) before doing work; denials fail closed
  and surface as a safe message. Deny-by-default with an explicit allow-list of safe actions.
- **Cryptographic agent identity.** Persistent Ed25519 DIDs; every cross-cluster message is signed
  (with timestamp + nonce for replay protection) and verified against out-of-band-provisioned peer
  keys — never a key carried in the message body.
- **Trust scoring + circuit breaker.** Peers are gated on a registry trust score; repeated failures
  decay it and trip a circuit breaker.
- **Operator kill-switch.** `govern_action("agent.graph.invoke")` refuses the whole query path when
  `AGENT_KILL_SWITCH_ENGAGED=true` (deploy-time; requires restart).
- **Output DLP.** Answers are scanned for credential/secret leakage before release; a match withholds
  the answer.
- **Per-chunk ReBAC + human approval** as above (OpenFGA + Temporal).

## Known limitation

The UI's approval flow polls `GET /tasks/{id}/result`, which the AGT backend **does not implement**
— so when a query needs approval, the *answer does not yet get delivered back to the requester*
(the A2A repo's server-side `record_decision` + `/tasks/result` delivery has not been ported to
AGT). Tracked in `PRODUCT_REQUIREMENTS.md` (FR-6).

## Security notes

- No secrets in git: `.env*`, `ui/.env.prod`, and `agent_identity_*.json` (Ed25519 private keys) are
  gitignored; only `*.env.example` templates are tracked.
- Every data/action path re-authorizes on the real user (`sub`) at the resource; federation never
  grants ambient trust.
- See `SECURITY_AUDIT.md` for the findings record.
- Known limitation (single-host dev): all clusters share one set of localhost datastores — a
  data-isolation weakness for true multi-tenant deployment, tracked in `PRODUCT_REQUIREMENTS.md`
  (FR-1.2 / NFR-2).
