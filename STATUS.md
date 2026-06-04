# Project Status — Federated RAG (resume / handoff notes)

_Last updated: 2026-06-04 (session 2 — hardening pass: TODO #1–3 resolved, kill-switch now an enforcing
operator off-switch (live-tested), both probe suites re-verified 0 VULNERABLE, git-history secret scan clean,
CORS/replay doc accuracy fixed). Read this first when resuming. Verified-clean checkpoint._

## TL;DR
Two federated-RAG solutions, each running as **two clusters that federate**. Both work end-to-end;
the security/governance posture has been adversarially hardened over two rounds and is **verified
clean (0 open bypasses)**.

1. **A2A** = `federated-rag/` — A2A protocol + RFC 8693 token exchange. Clusters :8000 / :8002. **All 4 flows pass.**
2. **AGT** = `agt-federated-rag/` — Microsoft AGT / AgentMesh DID governance. Clusters :8010 / :8012. **All 4 flows pass** over a real DID-signed HTTP `/a2a/query` transport.

LLM = `meta/llama-3.3-70b-instruct` (reliable ~8s; the prior `z-ai/glm-5.1` cold-started ~184s and
timed out — root-caused to the model, not our code). Configurable via `LLM_MODEL` in each `.env`.

**On `origin/main`:** `bfdeb34` (A2A), `21d1bfd` (AGT two-cluster + model switch + scripts + round-1
security), `76e4106` (round-2 hardening), `ac13b29` (STATUS). **Local-only — committed, NOT pushed (needs
explicit approval):** the session-2 hardening commit (one commit ahead of `origin/main`; run `git log -1`).
Working tree is clean after it.

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
  - Graph-level kill-switch: now an **enforcing operator off-switch** (real `policy_yaml` deny on
    `AGENT_KILL_SWITCH_ENGAGED`; `/query`→503, `/a2a/query`→signed-failed; verified in-process + live).
    Real data-path controls unchanged (per-node `_enforce` default-deny + OpenFGA ReBAC, fail-closed).
  - DEFENDED: alg/kid confusion, SSRF (callback allowlist), OpenFGA tuple-write, rate-limit spoof, IDOR, approval HMAC forgery+replay.

**Quality:** GraphRAG A2A query-embedder fixed; `scripts/clusters.ps1` (start/stop/restart/status all 4)
+ `scripts/logs.ps1`; clusters.ps1 exits 0/1 by health; code-quality scan clean (no verify=False/eval/
exec/shell=True/wildcard-CORS/swallowed-except); README rewritten to the two-independent-federations model.

**Session 2026-06-04 hardening pass (team "agt-federation", all verified):**
- **Re-verified clean baseline:** all 4 governance flows green on BOTH solutions — cross-cluster hops
  traced in live routing logs (A2A Flow D = `node_call_peer_agent` on A → peer `node_start_approval` on B;
  not just message wording). Both red-team suites re-run against the frozen code: **R1 43 DEFENDED / 0
  VULNERABLE / 4 EXPECTED; R2 25 DEFENDED / 0 VULNERABLE** + the 2 known bounded FINDINGs (R2-2a audience,
  R2-8 prompt-injection) + 1 EVIDENCE. 0 open bypasses.
- **TODO #1 (GraphRAG) RESOLVED:** docs + code docstrings/comments made honest across both codebases
  (Qdrant-only retrieval; Neo4j seam inert; `neo4j_graph_hops` reserved/unused). See TO-BE-DONE #1.
- **TODO #2 (kill-switch) RESOLVED:** decorative gate → enforcing operator off-switch, live-tested. See #2.
- **TODO #3 (audience) RESOLVED:** bound verified + documented as intentional test-enablement (`SECURITY_AUDIT.md` AUD-1). See #3.
- **Doc/code accuracy:** fixed `ui/README.md` CORS note (it claimed `allow_origins=["*"]` + `allow_credentials=True`;
  the code is actually a locked-down env-driven allow-list with `allow_credentials=False` — now matches).
  Corrected stale `SECURITY_AUDIT.md` finding R-1 (A2A replay) to **REMEDIATED** (ts+nonce+freshness+seen-cache shipped, task #8).
- **Git-history secret scan (resolves the audit's open "scan history before publication" TODO):** clean —
  no real NVIDIA key (only the redacted `nvapi-ImQU…QjRR` audit text + `nvapi-change-me` placeholder) and no
  real HMAC literals were ever committed; no secrets in the tracked tree (only `*.env.example` placeholders).
- **Code-quality scan re-run clean** after all edits (no verify=False/eval/exec/shell=True/wildcard-CORS/
  swallowed-except/hardcoded-secrets); all changed `.py` byte-compile clean.
- **Legacy unit suite is stale (known quality-debt, NOT a product regression).** `federated-rag/tests/
  test_flows.py` = **5 passed / 5 failed** (pytest 9 + pytest-asyncio 1.4 installed this session). All 5
  failures are pre-existing and the assertions/harness lag deliberate improvements — NOT broken behavior:
  Flow-B expects `answer is None` but pending-approval now returns a status *message*; Flow-C/D mock
  local-but-DENIED chunks and expect `REMOTE_*`, but the **H-1 security fix** correctly routes local-denied
  to `LOCAL_DENIED` (routing to a peer would leak the query); the 2 `test_approval_workflow_*` call workflow
  methods outside Temporal's event loop, which newer `temporalio` rejects (needs `WorkflowEnvironment`).
  The actual product behavior is verified by **stronger** means — the 4 live flows (traced in routing logs)
  + 68 red-team probes. **Follow-up (separate, scoped task — do NOT bundle into hardening):** refresh
  these 5 tests to current contracts (update Flow-B/C/D expectations; port the workflow tests to
  `WorkflowEnvironment`). Tracked here so it isn't silently dropped.

## What is TO BE DONE
_Items 1–3 were RESOLVED this session (2026-06-04 hardening pass — see "Session 2026-06-04" under DONE).
Only #4 (full productionization) remains genuinely open; it is a separate project, not a demo gap._

1. **GraphRAG is scaffolded but inert — now documented as such** (quality, task #3). Retrieval in the
   demo is **Qdrant-only** (hybrid dense + sparse, server-side RRF). The Neo4j graph-retrieval seam exists
   in both codebases and is RRF-fused, but: **AGT** ingest never writes Neo4j (only upserts Qdrant), so its
   graph retriever always degrades to empty; **A2A** *can* populate Neo4j (run `setup_all.py` without
   `--no-neo4j`) and uses a `HybridRetriever`, but the documented demo runs `--no-neo4j`. Neither path does
   graph traversal / entity-neighbourhood expansion (`neo4j_graph_hops` is reserved and unused). Docs
   (README root + federated-rag, SCENARIOS, ARCHITECTURE as-built caveat) and the relevant code docstrings
   now state this precisely. Future work (NOT a gap): add an AGT Neo4j ingest path + a `VectorCypherRetriever`
   and a multi-hop corpus to actually exercise traversal.
2. **Self-trust kill-switch** (governance) — **DONE (operator off-switch) + 1 design item open.** The
   graph-level `govern_action("agent.graph.invoke")` gate is now **ENFORCING** via a real
   `AgentMeshClient(policy_yaml=)` (`default_action: allow` + a priority-1000 deny on `kill_switch_engaged`),
   and `run_query` injects `settings.agent_kill_switch_engaged` (env `AGENT_KILL_SWITCH_ENGAGED`, default
   false). When engaged: `/query` returns **HTTP 503** ("administratively disabled") before the SSE stream
   opens; `/a2a/query` returns a signed `status="failed"` (a raw 503 would break the DID-signed peer
   contract); `/health` stays 200; and the internal `govern_action` deny (`PermissionError` before graph
   compile — no node/retrieval/LLM) remains as defense-in-depth + AgentMesh audit. **Verified in-process +
   live** (engaged → 503 on `/query`, 200 on `/health`; reverted → 401/normal). DEPLOY-TIME lever (env +
   restart), NOT an instant runtime lever and NOT an automatic trust-based trip — the downward
   self-trust-degradation signal remains the open design item. Real data-path enforcement (per-node
   `_enforce` default-deny + OpenFGA ReBAC) unchanged. Files: agt `config.py`, `mesh/agent_identity.py`,
   `agent/graph.py`, `api/main.py`. Audit: `GOVERNANCE_AUDIT.md` Item 2.
3. **Audience scoping** (security hardening, IdP) — **DOCUMENTED as intentional test-enablement (bound
   verified).** One `rag-ui` token has `aud=[all 4 backend client_ids]`, so it authenticates to all 4
   backends. BOUNDED — no privilege gain: no endpoint grants data/action on token-acceptance alone (A2A
   `/tasks/send` + AGT `/query` re-check `sub` via OpenFGA; A2A callback gates on `azp` peer-allowlist —
   `rag-ui` azp is not a peer, rejected; AGT peer paths use DID signature, honor no user token). Production
   fix is IdP config: per-cluster `aud` / RFC 8693 token-exchange (A2A already ships `exchange_token`).
   Revert demo enablement: delete `aud-agent-agt-a/b` mappers from the `rag-ui` Keycloak client.
   Documented: `SECURITY_AUDIT.md` AUD-1.
4. **Deployment readiness for two real company divisions** (from the deployment-gap analysis):
   physical per-division data isolation (own Qdrant/Neo4j/OpenFGA), TLS/mTLS everywhere, cross-org IdP
   federation, **self-hosted LLM** (data-residency — currently authorized chunks go to api.nvidia.com),
   secrets manager + key rotation, authenticated approval portal (vs HMAC deep-link), HA/backed-up
   datastores, observability (metrics/tracing across the hop), Helm/IaC, and **pick ONE federation**
   (A2A vs AGT — AGT's DID model fits cross-org better).

## Team (TaskList "agt-federation")
- team-lead (me), agt-eng (AGT transport/mesh/retrieval specialist), gov-auditor (governance + DLP + IdP),
  sec-redteam (adversarial probes). Session-2 tasks: #1 flow re-verify, #2 probe re-run, #3 GraphRAG-honesty,
  #4 kill-switch, #5 audience, #6 final scan/commit — all complete. Earlier #1-#8,#10 complete; original
  "#9 GraphRAG" is now resolved as documented (see TO-BE-DONE #1). Only deployment-readiness (#4) remains open.

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
