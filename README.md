# AGT Federated RAG — Governed, Federated, Per-Division Agentic Retrieval

A **production-grade template** for governed retrieval-augmented generation across mutually
distrusting **divisions** (subsidiaries, jurisdictions, Chinese-wall units). A user asks an
agent a question; the agent returns **only** the data that user is authorized to see
(OpenFGA per-chunk ReBAC), runs **every action through a default-deny policy engine**, and
when the answer lives in another division — or belongs to another person — it **federates**
the request over a cryptographically-authenticated channel and/or opens a **human approval**
workflow before releasing anything.

Cross-division trust is **cryptographic, not credential-forwarding**: each division has a
persistent **Ed25519 DID**, every inter-agent message is signed + replay-protected, the user's
**identity travels as signed claims (never a replayable token)**, and the receiving division
**re-authorizes the user against its own OpenFGA**. Built on the Microsoft Agent Governance
Toolkit (Agent OS policy engine + AgentMesh DID identity), LangGraph, OpenFGA, Temporal,
Qdrant, and Keycloak.

> Each division is a **physically-isolated stack** — its own IdP realm, authorization store,
> workflow engine, vector DB, secrets, and DID. Cross-store isolation is asserted by an
> integration test that runs against live stacks (the full kill-B 3-division e2e is still
> pending — see `PROJECT_STATUS.md`). This replaced an earlier shared-infra single-host model.

> **📍 Current state:** the governance core, **offline/account-bound delivery (FR-6)**,
> **verifiable cross-division identity (FR-3.6)**, **dynamic discovery (FR-3.1/3.2)**,
> **CRL revocation (NFR-3)**, and the **division-native UI** are built and tested (223 backend tests).
> OCSP peer checking is opt-in (`TLS_OCSP_MODE`). Remaining residuals: the 3-division e2e run (needs live stacks), and an
> independent pen-test. **See `PROJECT_STATUS.md` for the verified done / not-done picture.**

---

## Capabilities

| Area | What it does | Where |
|---|---|---|
| Per-chunk authorization | OpenFGA ReBAC, re-decided live on every query (instant revoke/expiry) | `auth/openfga.py` |
| Default-deny governance | Every LangGraph node `_enforce`s a policy before acting | `agent/policies/` |
| Prompt-injection defense | LLM has no action agency + denied data pruned pre-LLM; content spotlighting + hardened prompt + audited heuristic (LLM01) | `agent/injection.py` |
| Cryptographic federation | Ed25519-DID-signed, replay-protected `/a2a/query`; per-DID issuer binding | `mesh/` |
| Human-in-the-loop approval | Durable Temporal workflow; owner inbox; **answer delivered back** to the requester | `workflow/`, `api/main.py` |
| Any-IdP identity | OIDC; configurable claim mapping (Keycloak/Entra/Okta) | `auth/token_validator.py` |
| Browser auth (production) | **BFF** — server-side PKCE; **no token in the browser**, only an `HttpOnly` session cookie; silent refresh; login-CSRF state binding; CSRF | `api/bff.py`, `ui/src/components/BffPane.tsx` |
| Group-based access | IdP groups → OpenFGA `group#member` usersets (baseline access, instant revoke) + allowlist | `auth/`, `infra/idp-presets/` |
| Production mTLS edge | nginx, route-based mutual TLS on the peer plane, JWT on the user plane | `infra/nginx/` |
| Tamper-evident audit | Hash-chained + externally-anchored log (detects tamper/truncation/deletion) | `audit_log.py` |
| Scheduled rotation | Temporal cron rotates DID creds + approval HMAC | `workflow/rotation.py` |
| Connector SDK | `content → chunks + ACL grants` contract; folder reference impl | `connectors/` |
| Pluggable retrieval | N retrievers fused (RRF): Qdrant + Neo4j seam + any number of external retrieval-as-a-service backends; every returned chunk is still per-chunk authorized (governance preserved) | `rag/retriever.py`, `config.RaasEndpoint` |
| Governed MCP tools | One governed executor, per-server allowlist gateway, no raw-token forwarding | `tools/mcp.py` |
| Data residency | Block external inference egress in local mode | `residency.py` |
| Observability | Dependency-free Prometheus `/metrics` + dashboard + alert rules | `infra/observability/` |
| Secrets backend | env-file default, Vault/KMS adapter | `secrets_backend.py` |
| Admin CLI | `agtctl` grant/revoke/list (users + groups), status, doctor | `scripts/agtctl.py` |
| One-command bring-up | `bootstrap.ps1` / `bootstrap.sh`; pinned images + frozen deps | `scripts/` |
| Kubernetes deployment | kustomize base + per-division overlays; per-namespace NetworkPolicy isolation; **one-command turnkey bring-up** `python scripts/bootstrap_k8s.py --divisions <id>` (apply → provision → ingest → DID → serve); verified Running on kind (alongside Compose) | `k8s/`, `scripts/bootstrap_k8s.py` |
| **Multi-cluster federation** | **one cluster per division** (the multi-cloud-shaped topology) federated over routable URLs + DIDs; `python scripts/multicluster.py up --divisions gamma,delta` stands up + federates + proves cross-cluster tool delegation; deploy-anywhere guide for kind/EKS/GKE/AKS/on-prem | `scripts/multicluster.py`, `k8s/MULTICLUSTER.md` |

## Architecture at a glance

```
ui/  (React + Vite, :5173)   split-screen: alice @ Division Alpha · bob @ Division Beta
        |  Vite proxy: /api/agt-a -> :9000   /api/agt-b -> :9100   /auth/* -> Keycloak
        v
Per division (e.g. alpha @ port_base 9000), each a SEPARATE Docker stack:
  agent (:9000)   FastAPI /query (SSE), /a2a/query (DID), /approvals, /tasks/*/result, /metrics
  worker          Temporal worker: ApprovalWorkflow + KeyRotationWorkflow + activities
  [edge]          nginx — production ingress: route-based mTLS (peer plane) + TLS/JWT (user plane)
  openfga (:9001) keycloak (:9002) temporal (:9003/4) qdrant (:9005) redis (:9006) postgres
  DID did:mesh:…  Ed25519 identity; trusts peers via the signed trust map

agt-federated-rag/   ONE codebase, run per division via RAG_ENV_FILE=.env.<division>
  agent/  policies/  mesh/  auth/  rag/  workflow/  connectors/  tools/  transport/  api/
```
Divisions: **alpha 9000 · beta 9100 · gamma 9200** (ports derive from `port_base`).

## Tech stack

- **Governance:** Microsoft Agent Governance Toolkit — Agent OS (policy engine, MCP gateway,
  circuit breaker) + AgentMesh (DID identity, signing, trust scoring). On public PyPI.
- **Agent:** LangGraph + LangChain; OpenAI-compatible LLM (NVIDIA NIM default, any endpoint).
- **Authorization:** OpenFGA (ReBAC). **Identity:** Keycloak / any OIDC IdP; python-jose.
- **Retrieval:** Qdrant (hybrid) + FastEmbed; Neo4j/GraphRAG is a documented inert seam.
- **Workflow:** Temporal (durable approvals + rotation cron).
- **Edge/transport:** nginx (route-based mTLS), `cryptography` (CA/cert/CRL).
- **UI:** React 18 + Vite + TypeScript; Playwright e2e; Vitest unit.
- **Infra:** Docker Compose per division; pinned images; `requirements.lock.txt` (frozen).
  Versions are pinned in `infra/division-stack.template.yml` + `agt-federated-rag/requirements.lock.txt`.

## Setup

**Prereqs:** Python 3.11+, Node 18+, a running Docker daemon, and an OpenAI-compatible LLM key
in `./.env` (`NVIDIA_API_KEY=…`). ~16 GB RAM is comfortable (each division ≈ 7 containers).

```powershell
# One command — venv + pinned deps + npm + per-division stacks + provisioning + federation + agents
powershell -File scripts\bootstrap.ps1            # alpha + beta (demo pair)
powershell -File scripts\bootstrap.ps1 -ThreeDivisions   # + gamma
# Linux/macOS: ./scripts/bootstrap.sh  [--three]
cd ui; npm run start                               # UI at http://localhost:5173
```

Idempotent. Logins are printed at the end (alice @ alpha, bob @ beta; passwords in
`infra/generated/<div>/secrets.json`). **Pre-warm the LLM** with one throwaway query per pane
before a demo — the free-tier endpoint cold-starts (~1–2 min; warm ≈ seconds).

**Add another division** (no code): write `infra/divisions/<id>.yml`, then
`onboard_division.py <manifest>` → `federate_divisions.py` → `clusters.ps1 start all`. See the
"Per-division deployment" details below and `infra/idp-presets/` to wire a corporate IdP.

## Scenarios (each proven; run them yourself)

With the stack up and the UI open:
1. **Local authorized** — alice asks a doc she's granted (`data retention policy`) → immediate answer.
2. **Cross-division federated** — alice asks beta's data (`Q4 financial results`) granted cross-division
   → alpha delegates over the signed `/a2a` channel → beta re-authorizes → answer in alice's pane.
3. **Human approval** — alice asks data she's *not* cleared for → pane parks on "⏳ Awaiting approval"
   → bob sees it in his inbox and approves → **alice's answer appears automatically** (no re-type).
   *(Offline too (FR-6): if alice closes the browser, the outcome is durably stored against her
   account and waits — `GET /inbox`, regenerated at delivery so a revoked grant can't leak stale
   data — surfaced on next login with an in-app badge.)*
4. **Denied (no leak)** — alice asks an un-granted beta doc with no cross-grant → polite nothing;
   she can't even tell whether it exists.
5. **Group access** — a user in an IdP group sees that group's doc set with **zero per-user grants**;
   removing them from the group revokes on their next token. (`agtctl grant --group …`.)
6. **Revocation** — `agtctl revoke …` (or `/access/revoke`) → the next query is denied immediately.
7. **Resilience** — stop a division's whole stack; the others keep serving (no shared point).

All seven are exercised by the test suites below; the first three are rendered-UI Playwright e2e.

## Verification

```powershell
# Backend — 254 tests (252 pass, 2 skip — skips need live division stacks): governance, authz, federation, approval, audit, transport, connectors, MCP, retrieval, offline-delivery, discovery, red-team regression, …
cd agt-federated-rag; ..\.venv\Scripts\python.exe -m pytest tests -q

# UI unit — auth + PKCE + SSE normalization
cd ui; npm test

# UI end-to-end (real browser, live divisions) — local / federated / approval flow
cd ui; npm run e2e            # needs the UI dev server (npm run start) + divisions up

# Audit chain integrity (per division)
cd agt-federated-rag; ..\.venv\Scripts\python.exe ..\scripts\verify_audit.py

# Live health + post-deploy smoke
python scripts\agtctl.py status
python scripts\agtctl.py doctor --division alpha
```

## Governance — what is actually enforced

- **Per-action policy (default-deny).** Every node calls `_enforce(action, ctx)`; an action not
  explicitly allowed (or matching a deny rule) is refused, fail-closed.
- **Per-chunk ReBAC.** OpenFGA decides each chunk for the *namespaced* principal, live — so
  revoke/expiry take effect on the next request.
- **Cryptographic identity.** Ed25519 DIDs; every cross-division message signed (ts+nonce
  replay guard) and verified against the trust map; the user's identity rides as signed claims.
- **Human approval.** Restricted access opens a durable Temporal workflow with real owner
  attribution; the answer is delivered back to the requester after approval.
- **Output DLP.** Answers are scanned for credential leakage before release (hard-deny).
- **Operator kill-switch.** Denies the whole query path when engaged.
- **Tamper-evident audit + rate limits + mTLS edge** as described above.

## Security

- **No secrets in git:** `.env*`, `ui/.env.prod`, `agent_identity_*.json`, `infra/generated/`,
  `_certs/` are gitignored; only `*.env.example` templates are tracked.
- **Federation never grants ambient trust** — every data path re-authorizes the real user at
  the resource division.
- **Full posture, residual risk, and open design decisions:** see **`THREAT_MODEL.md`**.
  Current review gate: `redteam/M0_REVIEW_*.md`. Historical findings: `docs/archive/`.

## Documentation map

- **`examples/cross-agent-pii/PROOF.md`** — **what we prove, how to reproduce it, and the
  benchmarks**: the two governance layers (data-access RAG + cross-agent tool sharing), the 6 live
  cross-department scenarios (`prove_live.py`), cluster bring-up, and tool-latency numbers.
- **`PROJECT_STATUS.md`** — **start here for current state**: what is built / partial / not built,
  verified against code + tests. Supersedes any status claim elsewhere.
- **`ARCHITECTURE.md`** — components, request **dataflow**, **callgraph**, the cross-division
  federation + offline-delivery sequence, and where each security control sits (Mermaid diagrams).
- `PRODUCT_REQUIREMENTS.md` — the target requirements (FR/NFR/SC, the spec). Its "Today:" notes are
  the original pre-implementation baseline (historical).
- `THREAT_MODEL.md` — enforced controls, deployment-dependent items, open design decisions.
- `redteam/M0_REVIEW_*.md` — the current adversarial review gate (security / prod / quality).
- `infra/idp-presets/` — connect a corporate IdP (AD/LDAP, Entra, Okta) + groups mapper.
- `infra/nginx/` — the production mTLS edge (design, enable, proof, host caveats).
- `infra/observability/` — Prometheus/Grafana/alerts + `BACKUP_RUNBOOK.md`.
- `docs/archive/` — historical: the executed `IMPLEMENTATION_PLAN.md`, prior handoff logs, the
  template-task record, and dated audits (superseded; kept for history only).

## Per-division deployment (Infrastructure-as-Code)

A division is declared by `infra/divisions/<id>.yml` (division_id, port_base, trusted_peers,
docs_dir, residency_mode, seed_viewer/seed_approval/cross_grants) and stood up with **no source
edits**:

```powershell
python scripts\onboard_division.py infra\divisions\alpha.yml   # full isolated stack + provisioning
#   --dry-run = render only (CI-safe) · --teardown = down -v + cleanup · --force = rotate secrets
python scripts\federate_divisions.py --only alpha beta          # cross-wire DIDs/issuers/trust map
.\scripts\clusters.ps1 start all                                # agents + workers; `status` for health
```
Ports derive from `port_base` (agent=base, openfga=+1, keycloak=+2, temporal=+3/+4, qdrant=+5,
redis=+6); colliding bases are rejected. Per-division secrets live in `infra/generated/<id>/`
(gitignored). The containerized profile (`--profile containerized`) adds the agent, worker, and
nginx edge as containers.

> **LLM latency:** the agent talks to any OpenAI-compatible endpoint via `OPENAI_API_BASE`. A
> free/shared tier cold-starts (tens of seconds); production points it at a provisioned/warm or
> self-hosted endpoint (`residency_mode: local` keeps inference in-boundary).
