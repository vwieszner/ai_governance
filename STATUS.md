# Project Status — Federated RAG (resume / handoff notes)

_Last updated: 2026-06-04. Read this first when resuming. Session paused by user at a verified-clean checkpoint._

## TL;DR
Two federated-RAG solutions, each running as **two clusters that federate**. Both work end-to-end;
the security/governance posture has been adversarially hardened over two rounds and is **verified
clean (0 open bypasses)**.

1. **A2A** = `federated-rag/` — A2A protocol + RFC 8693 token exchange. Clusters :8000 / :8002. **All 4 flows pass.**
2. **AGT** = `agt-federated-rag/` — Microsoft AGT / AgentMesh DID governance. Clusters :8010 / :8012. **All 4 flows pass** over a real DID-signed HTTP `/a2a/query` transport.

LLM = `meta/llama-3.3-70b-instruct` (reliable ~8s; the prior `z-ai/glm-5.1` cold-started ~184s and
timed out — root-caused to the model, not our code). Configurable via `LLM_MODEL` in each `.env`.

**Shipped to `origin/main`:** `bfdeb34` (A2A), `21d1bfd` (AGT two-cluster + model switch + scripts +
round-1 security), `76e4106` (round-2 hardening). Working tree may have an uncommitted STATUS.md (this file).

## Bring it up from cold
```
docker compose up -d
docker start claude-qdrant claude-neo4j storyteller-redis-1
.venv\Scripts\python.exe init_secrets.py          # only if ./.env missing; needs NVIDIA_API_KEY in env
.venv\Scripts\python.exe setup_all.py --no-neo4j  # A2A: store/realm/ingest/tuples -> 6/6 PASS
.venv\Scripts\python.exe setup_agt.py --no-neo4j  # AGT: DIDs/clients/ingest/tuples -> 6/6 PASS
.\scripts\clusters.ps1 start all                  # all 4 backends + workers (durable across turns)
.\scripts\clusters.ps1 status                     # health of all 4 + UI
```
NOTE: `setup_*.py` rotate that solution's OpenFGA store id -> after running setup you MUST
`.\scripts\clusters.ps1 restart a2a-a a2a-b` (or `agt-a agt-b`) so backends pick up the new store.

## The 4 governance flows (type as alice / demo; bob / demo also exists)
- A local-authorized: "What is our data retention policy for customer records?" -> grounded answer
- B local-approval: "What are the salary bands for senior engineers?" -> "pending approval"
- C cross-cluster answer: "What Kubernetes version are we running and what is the cluster topology?" -> federated answer from the peer
- D cross-cluster approval: "What was our Q4 revenue and ARR growth?" -> "approval ongoing"

Verify (real content + SSE states):
- AGT: from `agt-federated-rag/`: `..\.venv\Scripts\python.exe _repro_agt.py 8010 alice "<query>"`
- A2A: from `federated-rag/`: `..\.venv\Scripts\python.exe _repro_http.py alice "<query>"`
- AGT replay protection: from `agt-federated-rag/`, `set RAG_ENV_FILE=.env` then `..\.venv\Scripts\python.exe _repro_replay.py` (1st send 200, replay 401).
(`_repro_*.py` are gitignored dev tools — they live on disk only.)

## What is DONE (committed + verified)
**Federation:** A2A and AGT each run as two real federating clusters; all 4 flows verified with real
content + cross-hop logs (AGT Flow C returns the peer cluster's data via DID-signed `/a2a/query`).

**Security — adversarial red/blue, 2 rounds + governance audit (see `redteam/`):**
- `redteam/run_probes.py` (round 1): 43 DEFENDED / 0 VULNERABLE / 4 EXPECTED.
- `redteam/run_probes_r2.py` (round 2, deeper): 25 DEFENDED / 0 VULNERABLE / bounded findings only.
- `redteam/GOVERNANCE_AUDIT.md`: 8/8 governance items (6 OK, 2 GAP both fixed).
- `redteam/RED_FINDINGS.md` + `redteam/BLUE_FIXES.md`: full found→fixed→re-verified narrative.
- Real fixes (all verified by team-lead via restart + empirical re-test):
  - Missing-auth returned 422 -> now **401** (both `api/main.py`).
  - **Replay protection** on AGT DID transport (ts+nonce in signed body, fail-closed seen-cache) — replay -> 401.
  - **Deny-by-default** made load-order-robust (`data-access-policy.yaml` default allow->deny).
  - **Output credential-leak DLP** (both solutions, HARD-DENY, tight-6 patterns, in `format_response` so it
    covers local AND peer answers) — 6 vectors block, legit answers pass.
  - Decorative graph-level kill-switch: false docstring corrected (real controls = per-node `_enforce`
    default-deny + OpenFGA ReBAC, both verified fail-closed).
  - DEFENDED: alg/kid confusion, SSRF (callback allowlist), OpenFGA tuple-write, rate-limit spoof, IDOR, approval HMAC forgery+replay.

**Quality:** GraphRAG A2A query-embedder fixed; `scripts/clusters.ps1` (start/stop/restart/status all 4)
+ `scripts/logs.ps1`; clusters.ps1 exits 0/1 by health; code-quality scan clean (no verify=False/eval/
exec/shell=True/wildcard-CORS/swallowed-except); README rewritten to the two-independent-federations model.

## What is TO BE DONE (tracked enhancements — NONE are open security holes)
1. **GraphRAG is inert** (quality, task #9). A2A ingests Neo4j but the demo runs `--no-neo4j`; AGT never
   writes Neo4j at all (ingest only upserts Qdrant). Both use a non-traversal retriever (`neo4j_graph_hops`
   unused). TODO: either wire AGT Neo4j ingest + a VectorCypherRetriever so the KG is actually used and
   verify with Neo4j enabled (now feasible with the fast LLM), OR make README/STATUS honest that retrieval
   is Qdrant-only. The A2A query-embedder bug is already fixed.
2. **Self-trust kill-switch** (governance, design). The graph-level `govern_action("agent.graph.invoke")`
   gate is decorative (mesh client has allow-all baseline; self-trust only rises). It's defense-in-depth,
   NOT a data-path hole. TODO (design): pass a real agentmesh-format policy to `AgentMeshClient(policy_yaml=)`
   in `mesh/agent_identity.get_mesh()` AND add a downward trust signal on anomalous behaviour.
3. **Audience scoping** (security hardening, IdP). One `rag-ui` token has `aud=[all 4 backend client_ids]`
   (test-enablement mappers), so it authenticates to all 4 backends. BOUNDED — no privilege gain (every
   path re-checks sub/azp/DID). TODO: scope tokens per cluster / use RFC 8693 token-exchange (IdP config,
   not app code).
4. **Deployment readiness for two real company divisions** (from the deployment-gap analysis):
   physical per-division data isolation (own Qdrant/Neo4j/OpenFGA), TLS/mTLS everywhere, cross-org IdP
   federation, **self-hosted LLM** (data-residency — currently authorized chunks go to api.nvidia.com),
   secrets manager + key rotation, authenticated approval portal (vs HMAC deep-link), HA/backed-up
   datastores, observability (metrics/tracing across the hop), Helm/IaC, and **pick ONE federation**
   (A2A vs AGT — AGT's DID model fits cross-org better).

## Team (TaskList "agt-federation")
- team-lead (me), agt-eng (AGT transport/mesh/governance specialist), gov-auditor (governance + DLP),
  sec-redteam (adversarial probes). Tasks #1-#8,#10 complete; #9 (GraphRAG) pending/deferred.

## Gotchas (bit us this session — read before resuming)
- **Backend durability:** `scripts/clusters.ps1` uses PowerShell `Start-Process` (detached) → survives
  across turns. Teammates' `run_in_background` processes do NOT (torn down at turn boundaries) — so
  only team-lead's clusters.ps1 backends are durable. Always restart via clusters.ps1.
- **Running vs disk drift:** code edits don't take effect until you `clusters.ps1 restart`. After ANY
  source change, restart the affected backends before verifying.
- **Pushing to main needs explicit per-commit user approval** (auto-mode classifier blocks otherwise).
- **No real secrets in git:** all 4 runtime `.env`, `agent_identity_*.json`, `_repro_*.py` are gitignored.
  Verified none staged. NVIDIA key lives only in gitignored `.env` (recommend rotating it).
- Qdrant is ephemeral — after a docker restart re-run `setup_all.py --no-neo4j` / `setup_agt.py --no-neo4j`.

## Docs
README.md (two-federations model, accurate for A2A + AGT), ARCHITECTURE.md, SCENARIOS.md,
SECURITY_AUDIT.md, SECURITY_REVIEW.md, redteam/{RED_FINDINGS,BLUE_FIXES,GOVERNANCE_AUDIT}.md, ui/README.md.
