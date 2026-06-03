# Project Status — Federated RAG (resume notes)

_Last updated: 2026-06-03. Read this first when resuming._

## TL;DR
Two federated-RAG solutions in this repo, each meant to run as **two clusters that federate**:
1. **A2A** = `federated-rag/` — A2A protocol + RFC 8693 token exchange. **WORKING: all 4 flows pass.**
2. **AGT** = `agt-federated-rag/` — Microsoft AGT / AgentMesh DID governance. **PARTIAL: local flows work; cross-cluster (C/D) needs more work — see "AGT open issues".**

Architecture principle (corrected mid-project): **one codebase = two clusters**, selected by the
`RAG_ENV_FILE` env var (`.env` = cluster-a, `.env.cluster-b` = cluster-b). The two *directories*
are two DIFFERENT governance approaches, NOT two halves of one federation.

## What is running right now (4 backends + UI; may be stopped when you resume)
| Solution | cluster-a | cluster-b | entry endpoint |
|----------|-----------|-----------|----------------|
| A2A federated-rag | :8000 | :8002 | POST /tasks/send |
| AGT agt-federated-rag | :8010 | :8012 | POST /query |
| UI (Vite, A2A only) | :5173 | | |
Infra (docker compose): OpenFGA :8089 (preshared-key auth), Keycloak :8087 (realm `rag`), Temporal :7233, Postgres. Plus host containers claude-qdrant :16333, claude-neo4j :17687 (pw `none`), storyteller-redis :6379.

## How to bring it all up from cold
```
docker compose up -d
docker start claude-qdrant claude-neo4j storyteller-redis-1
.venv\Scripts\python.exe init_secrets.py        # only if ./.env missing; needs NVIDIA_API_KEY in env
.venv\Scripts\python.exe setup_all.py --no-neo4j   # A2A: store/realm/ingest/tuples -> 6/6 PASS
.venv\Scripts\python.exe setup_agt.py --no-neo4j   # AGT: DIDs/clients/ingest/tuples -> 6/6 PASS
.\launch_all.ps1                                  # A2A backends+workers+UI (8000/8002/5173)
```
Launch AGT backends manually (launch_all.ps1 only covers A2A):
from agt-federated-rag, RAG_ENV_FILE=.env -> :8010, RAG_ENV_FILE=.env.cluster-b -> :8012 (api.main + workflow.worker each).
NOTE: setup_*.py rotate the OpenFGA store id each run -> you MUST restart that solution's backends after running setup.

## Users / creds
Keycloak realm `rag`, client `rag-ui` (public). Users: **alice / demo**, **bob / demo**.
Current subs: alice=a4c7f810-b0cb-48f0-9b6d-5920fa8914c7  bob=85f998e6-eeae-4d65-a41f-1690b63b904c
(subs persist across docker restart via Keycloak volume; only `docker rm` of keycloak changes them.)

## The 4 governance flows (queries to type as alice)
- A local-authorized: "What is our data retention policy for customer records?" -> answer
- B local-approval: "What are the salary bands for senior engineers?" -> "pending approval"
- C cross-cluster A2A: "What Kubernetes version are we running and what is the cluster topology?" -> federated answer
- D cross-cluster approval: "What was our Q4 revenue and ARR growth?" -> "approval ongoing"
Docs: federated-rag/tests/docs/cluster-a (data_retention, hr_compensation), cluster-b (technical_architecture, q4_financial).

## A2A solution — DONE / verified
All 4 flows verified end-to-end via federated-rag/_repro_http.py AND through the Vite proxy
(working->completed with real answers; B/D -> input-required). UI rag.ts collapsed to single A2A
path. THIS IS COMMITTED & PUSHED (commit bfdeb34 on origin/main).

## AGT solution — status & OPEN ISSUES (NOT committed yet)
Done this session:
- Added RAG_ENV_FILE mechanism to agt-federated-rag/config.py (run as 2 clusters).
- Built the missing DID trust bootstrap: agentmesh.trust.handshake.IdentityRegistry exists and works
  OFFLINE. Wired into mesh/agent_identity.py _get_trust_bridge(): builds an IdentityRegistry, registers
  self + peer (peer identity reconstructed from PEER_AGENT_PUBLIC_JWK), injects a registry-backed
  TrustHandshake into the TrustBridge. PROVEN in isolation: handshake verified=True score=500 when both
  DIDs share a registry.
- Wrote setup_agt.py: pre-generates both DID identities (agent_identity_agt_a.json/_b.json), cross-wires
  each .env with the PEER's DID + public JWK, distinct ports 8010/8012, Redis db /3,/4, queues
  agt-approval-a/b, collections knowledge_base_agt_a/_b, Keycloak clients agent-agt-a/b. Runs 6/6 PASS.
- Both AGT backends start healthy and report their DIDs.

PROGRESS 2026-06-03 (team agt-federation / agt-eng): real HTTP transport BUILT.
- mesh/peer_client.call_peer_agent: now does a real httpx POST of the DID-signed payload to
  peer_url + /a2a/query (120s timeout); verifies peer's Ed25519 sig on response (fail closed);
  keeps trust gate + circuit breaker + governance gate. Dropped the ProtocolBridge stub.
- api/main.py: NEW POST /a2a/query — DID-authenticated (verify_signed_message, 401 if unverified;
  trust + configured-peer-DID match); extracts user_id from signed payload; runs same governed
  run_query (user_token=""; OpenFGA re-checks on this cluster); returns DID-signed
  {status,answer,task_id,approval_request_id}. Status mapping checks approval_request_id FIRST.
- Also fixed 3 pre-existing AGT retrieval crash bugs (blocked ALL flows, not NVIDIA): (a)
  data-access-policy.yaml allowlist missing knowledge_base_agt_a/_b; (b) nodes._get_qdrant called
  nonexistent inst._init() -> ensure_collection(); (c) neo4j_retriever imported BaseEmbedder which
  the lib renamed to Embedder -> import accepts either. These were AGT-only (A2A already works).
- Verification of 4 flows IN PROGRESS (agt-eng running _repro_agt.py + checking cross-hop logs).

OLD OPEN ISSUES (now addressed by the above; kept for history):
1. AGT local Flow A returned states=["working"] with EMPTY answer (test b7wh911q5). Likely the NVIDIA LLM
   call was slow/timed out, OR /query didn't reach generate_answer. CHECK logs/agt-a-api.out for the
   request — look for node_generate_answer / agent_run_failed / auth_decision. Re-run:
   from agt-federated-rag: ..\.venv\Scripts\python.exe _repro_agt.py 8010 alice "What is our data retention policy for customer records?"
2. AGT cross-cluster (C/D) is BROKEN BY DESIGN — root cause found (2026-06-03):
   agentmesh.ProtocolBridge._send() is a STUB: it returns {"status":"sent","peer":did,"protocol":...}
   and NEVER makes a network call to the peer. So mesh/peer_client.call_peer_agent() can't actually
   deliver a query to the other cluster — the AgentMesh SDK provides governance/identity/trust but NOT
   a real transport. ALSO a real bug in peer_client.py: it does `asyncio.to_thread(bridge.send_message,...)`
   but send_message is ASYNC (a coroutine) — to_thread returns the un-awaited coroutine, not a result.
   IMPLICATION: to make AGT C/D actually federate, peer_client must be rewritten to do a REAL HTTP A2A
   call to the peer (sign payload with the DID, POST to peer's /tasks/{id}/callback or a new endpoint,
   parse SSE) — i.e. reuse the A2A transport pattern but keep AGT's DID signing/verification on top.
   DECISION NEEDED FROM USER: (a) implement a real HTTP transport for AGT peer calls (medium effort,
   makes C/D genuinely work with DID-signed messages), or (b) accept AGT as local-only governance
   (flows A/B) and document C/D as not-implemented in the SDK's transport.
3. agt-federated-rag still has a stale `agent_identity_b.json` (old) and now agent_identity_agt_a/_b.json
   (new). The old one is gitignored. Fine.
4. NOT COMMITTED: all agt-federated-rag changes + setup_agt.py + STATUS.md are uncommitted. Commit after
   the red/blue pass settles and AGT flows are verified.

## Adversarial security review — IN PROGRESS (team "redblue-sec")
A red/blue team is running:
- red-team: probing all 4 endpoints (authn bypass, IDOR, ReBAC leakage, approval HMAC forgery, A2A
  callback forgery, SSRF, injection/DoS, secret leakage, direct OpenFGA). Writing redteam/RED_FINDINGS.md.
  It built redteam/probe_lib.py. Findings not published yet when session paused.
- blue-team: idle, waiting for red's findings (task #2 blocked by task #1). Will fix real vulns at root
  in both codebases, restart, prove DEFENDED. Writes redteam/BLUE_FIXES.md.
RESUME: check redteam/RED_FINDINGS.md and redteam/BLUE_FIXES.md. If teammates ended, re-read those files
and finish any unfixed VULNERABLE/NEEDS-FIX items yourself. The team may need re-spawning (TeamCreate
redblue-sec then Agent with team_name) — or just act on the written reports directly.

## Key fixes already landed this session (don't redo)
- truststore.inject_into_ssl() at top of all 4 entry points (api.main + workflow.worker, both dirs) —
  fixes SSL CERTIFICATE_VERIFY_FAILED to NVIDIA. The real fix, not verify=False.
- Qdrant relevance gate (qdrant_score_threshold=0.55) so off-topic chunks don't block answers/routing.
- LLM timeout=60 + max_retries=2 (NVIDIA cold-connect is slow/flaky — this is an ongoing annoyance).
- RFC 8693 (A2A): audience = peer client_id (not URL); Keycloak peer-audience mapper; allowlist SSRF guard.
- A2A handle_peer_result uses state["peer_answer"] (ContextVars don't cross LangGraph nodes).
- Multi-chunk auth: grant viewer on ALL chunks of a doc (a >512-word doc splits into 2 chunks).
- openfga-sdk 0.9 renames (ClientTuple, ReadRequestTupleKey), neo4j-graphrag vector_index_name,
  qdrant explicit fastembed embedding (1.16 batch aliasing bug), multi-audience JWT manual check.
- Security hardening: OpenFGA preshared-key auth, random Postgres/Keycloak pw, 127.0.0.1 binds,
  no OpenFGA playground, secrets from gitignored .env via init_secrets.py.

## Secrets / git hygiene
- Real NVIDIA key + all secrets live ONLY in gitignored files (./.env, federated-rag/.env[.cluster-b],
  agt-federated-rag/.env[.cluster-b], ui/.env.prod/.demo, agent_identity_*.json). VERIFIED none staged.
- git remote: https://github.com/vwieszner/ai_governance.git (branch main). git uses
  http.sslBackend=schannel (Windows cert store) to push.
- RECOMMENDATION from SECURITY_AUDIT.md: rotate the NVIDIA key (it has been in plaintext .env on disk).

## Docs in repo
README.md (updated to one-concept-two-clusters; A2A accurate. AGT section may still describe it as the
"reference variant" — UPDATE once AGT federation is verified working). ARCHITECTURE.md (original spec),
SCENARIOS.md, SECURITY_AUDIT.md, SECURITY_REVIEW.md, ui/README.md.
NOTE: README still references things to re-check after AGT work — re-audit README before final commit.

## Immediate next steps when you resume
1. Read redteam/RED_FINDINGS.md + redteam/BLUE_FIXES.md; finish/verify any open security fixes.
2. Debug AGT local Flow A empty answer (logs/agt-a-api.out).
3. Investigate AGT ProtocolBridge DID->peer transport for cross-cluster C/D.
4. Re-verify all 4 AGT flows; update README AGT section.
5. Commit + push the AGT work + STATUS.md + redteam/ reports once everything is green.
