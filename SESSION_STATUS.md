# AGT Federated-RAG — Session Status & Handoff

_Last updated: 2026-06-11. Product: Microsoft Agent Governance Toolkit multi-division federated RAG (DID + Ed25519 + per-action policy + Temporal approval + OpenFGA per-chunk ReBAC). This is a PRODUCTION system for real divisions/users — not a demo._

Overarching goal (active): 100% functionality, every useful scenario proven working, security 100%, capable of real users. Execute IMPLEMENTATION_PLAN.md milestones M0→M8 + M-GOV + a ≥3-division e2e, production-grade, each with a review gate.

**MILESTONE TALLY (done & proven live): M0, M1, M2 (security-hardened), M3 (discovery + multi-peer), M4 (cross-division approval A2A callback — DONE), M5, M6, M7 (mTLS+CRL DONE + no-secrets-in-source), M8 (+failed-auth auditing), M-GOV (FR-4), + ≥3-division e2e NFR-2. The IMPLEMENTATION_PLAN.md milestone set M0→M8 + M-GOV + e2e is COMPLETE & proven. Now in the "really useful for real users" phase: the consolidated UI (Task #5).**

### SESSION 3 (in progress) — M7 mTLS done + UI repointed at live divisions
- **M7 mTLS COMPLETE (commit cb592ac, LOCAL — NEEDS PUSH).** `transport/mtls.py`: division private CA → per-division client/server certs; CERT_REQUIRED server context; CRL revocation gate; cert CN/SAN = division identity. Proven by REAL TLS handshakes via in-memory MemoryBIO (deterministic cross-platform — the threaded loopback socket has a Windows quirk; MemoryBIO is what CPython's own ssl suite uses): no-cert→reject, rogue-CA→reject, CA-signed→accept, revoked→detected, CN identifies division. Served only when `settings.require_mtls` (default off). **68 tests pass** (63 prior + 5 transport).
- **UI repointed at the LIVE divisions + verified (LOCAL, needs push for `.env.example`).** The `ui/` app was wired to a STALE topology (8000/8002/8010 + kc 8087, and `.env.example` documented `CLUSTER_A_URL` vars vite.config no longer reads). Findings: (1) `rag.ts` is already AGT-unified — BOTH panes speak POST /query + status/result/done SSE (no dead federated-rag `/tasks/send` path); the only defect was config. (2) Keycloak REFLECTS the request Host into the token `iss`, and each agent only accepts `iss=http://localhost:<kc>/realms/rag` (its OIDC_ISSUER) → the proxy's Keycloak target MUST be `localhost` (not 127.0.0.1); agent API targets are host-insensitive (127.0.0.1 fine). Fixed `ui/.env.example` (tracked) + `ui/.env.prod` (gitignored, real key preserved): AGT_A=9000, AGT_B=9100, KC_A=localhost:9002, KC_B=localhost:9102. PROVEN E2E through the running Vite proxy (`npm run start`): `/auth/a/token` → iss=http://localhost:9002/realms/rag ✅; `/api/agt-a/query` → `['status','result','done']` + real 1341-char answer ✅. UI `npm run build` (tsc) clean.
- **REMAINING UI gap (sized, not yet built):** requester-side approval delivery is broken — `ChatArea` polls `GET /tasks/{id}/result`, which the backend does NOT serve, and the backend GENERATES its own task_id (ignores the UI's), so the id wouldn't match anyway. Fix = align task_id (UI adopts the server's, or backend honours a validated client id) + add an ownership-checked, RE-AUTHORIZING `GET /tasks/{id}/result` that must NOT spawn a new approval workflow on each 4s poll (re-submitting /query would spam duplicate approvals). Security-sensitive → route through the review gate. Local query + login already work without it.
- **M4 (FR-6) PROVEN live (commit cffccf4):** cross-division approval A2A callback threaded + SSRF-validated (callback target must be the SIGNING peer's agent_url from the trust map; allowlist generalised to N peers). alice@alpha→beta q4 (pending) → bob@beta approves → beta worker `a2a_callback_sent` → alpha `peer_callback_received` (DID-verified). D-6 delivery = the callback's "re-send" → user re-runs the governed pipeline → far side regenerates. Owner inbox (FR-5.2) exists (/approvals/pending, /approvals/{id}/decision).
- **M7-NFR4 (commit adf41ad):** test_secrets — no real credentials in tracked source; secret-bearing artifacts (.env, infra/generated/, agent_identity_*.json) gitignored. **63 tests pass.**
- **M3 COMPLETE.** (a) Discovery service (commit 0783d1b): DID-secured `discovery/` (control-plane only, D-4); 3 divisions register; discover-by-capability live; unsigned/forged → 401. (b) Multi-peer data-path routing (commit ac16059, advisor-reviewed): `settings.peer_trust` map ({did:{issuer,public_jwk,agent_url,division_id}}) replaces single PEER_AGENT_* (one code path; 1-entry fallback). `verify_signed_message` resolves the signer's JWK from the map by DID (the trust decision, covering /a2a/query + /tasks/callback); `assertion_principal` binds to the SIGNER's map issuer (per-DID, fail-closed on empty); loop guard (peer-originated query never re-delegates). PROVEN: discriminating test (alpha trusting beta+gamma REJECTS a gamma-signed envelope asserting a beta/alpha-issuer user — M3 analog of the M2 cross-issuer guard) + live FR-3.7 regression PASS via the map. Discovery service runs at :8600.
- **e2e NFR-2 PROVEN:** 3 physically-isolated divisions live (alpha 9000 / beta 9100 / gamma 9200). Killed beta's ENTIRE stack (OpenFGA+Keycloak+Temporal+Qdrant+Redis+Postgres) → alpha + gamma kept serving (own authz works), beta authz DOWN, then restored. No shared point crosses a division boundary ("kill B, A still serves"). [3-way cross-division MESH still needs M3 multi-peer; pairwise alpha↔beta cross-division already proven.]
- M-GOV: default-DENY + output-DLP credential block proven (test_governance). M6 residency egress guard. M5 lifecycle (revoke+expiry). Port root-cause fix (clean 9000/9100/9200). 52 tests pass.

---

## ✅ DONE & PROVEN — SESSION 2 (all pushed; HEAD = d9ded8f)

- **Review team** (`agt-fed`): security + quality teammates reviewed M2. Security review found a real VULN (below); re-reviewed the fix → CONFIRMED CLOSED.
- **SECURITY — assertion-relay replay VULN FIXED (Option A, commit 96d207b).** M2 was forwarding the user's RAW home token as the assertion → a compromised receiving division could replay it at the user's home division. Fix: forward only DID-signed VALIDATED claims (sub/email/email_verified/iss), never a bearer token; receiver binds the asserted `iss` to the SPECIFIC signing peer (`settings.peer_agent_issuer` / `PEER_AGENT_ISSUER`, set by federate) — not the trusted-issuer set (which would let a compromised peer assert another division's user). `validate_peer_user_assertion`+peer-JWKS removed; raw-token ContextVar → claims ContextVar. `token_validator.assertion_principal()`. Trust model is now honest: in-namespace identity is VOUCHED by the DID-authenticated peer (Keycloak can't mint a receiver-audience token); cross-issuer impersonation stays blocked + tested. memory: [[m2-assertion-relay-vuln]].
- **Cross-division APPROVAL (Step 1) PROVEN** — pending_approval cross_grant (beta.yml) routes a peer-division user to approval; bob@beta approves via HMAC deep-link → workflow grants the cross-principal viewer → re-send → real answer. No check_auth change (advisor-rejected denied-owned routing).
- **Full cross-division matrix PROVEN** on the secure mechanism: IMMEDIATE (tech_arch viewer → answer), DENIED (security_incidents, no cross-grant → no leak), APPROVAL (q4 → pending→approve→answer "$48.3M"). Beta now has 3 docs.
- **LLM → meta/llama-3.1-8b-instruct** (config default + intent model). NVIDIA free-tier 70b/3.2-3b were throttled to 50-90s+/timeouts; 8b answers in ~1-2s. (M6 self-host can move back up.)
- **Approval-grant bug fix** (prior session, commit e6ddf29) — worker OpenFGA client was uninitialised; every approved user was silently denied. Fixed + proven.
- 36 tests pass. Commits this session: `96d207b` (Option A), `10abf5c` (cross_grant), `d9ded8f` (docs-honesty + denial doc).
- **M8 — tamper-evident hash-chained audit (commit a825116).** `audit_log.py`: every `agt_audit=True` event is appended to an append-only hash chain (`hash=SHA256(seq|ts|event|canonical(data)|prev_hash)`); recompute detects tamper/delete/reorder/truncate. Captured DRY via a structlog processor (format preserved). Per-(division,role) chains (agent+worker = separate processes → no write race). `scripts/verify_audit.py` CLI; 6 tests. PROVEN live: BOTH agent AND worker chains capture governance events — alpha_agent/beta_agent/beta_worker all verify OK; forged entry in a copy → "hash mismatch — entry tampered". M8 security+quality review gate in flight. NEXT: add `agt_audit=True` to FAILED/REJECTED auth events (DID-sig/assertion/peer-DID rejections, token 401s, approval HMAC-invalid) so the intrusion trail is chained too.
- **Quality [M1] fix (commit 2ae4a9c):** provisioning OpenFGA writes (`federate_divisions._apply_cross_grants` + `onboard_division._seed_division_tuples`) now fail LOUDLY via shared `_ofga_write` (swallow only 400 "already exists", raise everything else) — a run can no longer print "done" having written zero tuples. **43 tests pass.**

- **Port migration (commit 00d6471):** divisions MOVED to a clean band — alpha **9000**, beta **9100**, gamma **9200** (agent=base, openfga=base+1, kc-issuer=base+2, …). ROOT CAUSE of the OpenFGA collisions: a co-resident project reserves `BACKEND=8000+N*100+1` (=8101/8201/8301/8401) which equalled our openfga=port_base+1 on the old 8100/8200/8300/8400 bases. `onboard_division._reserved_ports()` + `assert_port_base_clean()` now REJECT colliding port_bases in `load_manifest` so it can't recur (tests pin it). alpha+beta re-onboarded + re-federated on clean ports.
- **M5 COMPLETE (FR-7) — access lifecycle.** Revocation (commits 3007c75 + IDOR fix a2b3ebe): `revoke_viewer` + owner-authenticated `POST /access/revoke` (verifies caller owns every chunk; audited) → viewer removed + pending set → re-ask re-enters approval (no stale reuse, D-6). Expiry (commit d0065f9): `non_expired` OpenFGA conditional tuples — AUTH_MODEL condition + `check()` passes `current_time` + `grant_viewer_until`; model migrated into the live stores (reversible). PROVEN live: revoke cycle + expiry (TTL 4s → allowed@t0, denied@t6s), no regression on existing grants. Follow-up: wire a TTL into the approval grant path (optional policy integration).

### Current live state
- alpha **9000** (agent 9000 / openfga 9001 / kc-issuer 9002); beta **9100** (9101 / 9102); gamma **9200** (not onboarded — for the e2e). 45 tests pass.
- Both agents run via `clusters.ps1` (reads manifests → targets 9000/9100); healthy at session end. After any agent restart, cross-division needs `PEER_AGENT_ISSUER` (set by `federate_divisions.py`) — re-run federate if 401s appear.
- KNOWN ENV: Docker control-plane can be sluggish (was responsive during the migration). NVIDIA 70b/3.2-3b throttled → using llama-3.1-8b. Direct 127.0.0.1 HTTP to division services always works.

## ✅ DONE & PROVEN — SESSION 1 (pushed; HEAD was e6ddf29)

Commits `c4cd7de..e6ddf29`:
- `f5d1902` M2 integration — `/a2a/query` enforces the verifiable user assertion (not a bare user_id).
- `fe3338a` **M2 security (advisor-caught, important)** — OpenFGA authorization principal is now `principal(claims) = "<email>|<sha256(verified-iss)[:16]>"` everywhere (local `/query` + cross-division `/a2a/query`). Bare email/sub would let ANY trusted issuer mint `email=ceo@other-div, email_verified=true` and impersonate the whole federation. Namespacing ⇒ "trust issuer A" = "A may vouch for A's own users only". `auth/token_validator.py: principal()/issuer_namespace()`; seed parity in `scripts/onboard_division.py: _seed_principal()`.
- `4c5b78c` LLM timeout 60→120s (NVIDIA NIM cold-start rides through) + dropped "demo" framing.
- `436a47c` M2 federation — `scripts/federate_divisions.py` (cross-wire PEER_AGENT_* + TRUSTED_ISSUERS + declarative manifest `cross_grants`); FR-3.7 proven.
- `a81dce9` Re-homed division **alpha** off the 8101 collision to port_base **8400** (8400–8406).
- `e6ddf29` **Approval-grant bug fix** — Temporal worker activities used an UNINITIALISED OpenFGA client (`_get_openfga()` built a bare `OpenFGAAuth()`, never ran async `_init()`), so every approved user was SILENTLY DENIED. Now async + delegates to `get_instance()`.

**Milestones:** M0 (physical isolation), M1 (per-division identity, AUD-1 fixed), M2 (verifiable cross-division identity) — COMPLETE.

**Scenarios proven live (verified in agent/worker LOGS, not just answers):**
1. Local authz — alice@alpha → `data_retention_policy` → real LLM answer (own OpenFGA).
2. Cross-division FR-3.7 — alice@alpha asks beta's data → alpha `flow=remote` → DID-signed `/a2a/query` → beta validates assertion (`iss=alpha`) → `user_id=alice@example.com|<iss-ns>` → `openfga allowed=True viewer` → immediate answer, no approval.
3. Cross-division denial — alice@alpha asks beta's `q4_financial_results` (not granted) → `allowed=False` → `flow=local_denied` → no leak (per-doc discrimination).
4. **Local approval cycle** — alice requests `hr_compensation_data` (bob owns) → pending → bob approves via HMAC deep-link → workflow grants viewer → re-query → real answer.
5. Foreign-division token rejection; physical-isolation live test now runs (no skip).

**Tests:** 34 passing (`agt-federated-rag/tests/`). Run: `.venv/Scripts/python.exe -m pytest tests/ -q` from `agt-federated-rag/`.

---

## 🔜 IN PROGRESS — Cross-division approval flow (next task, design locked by advisor)

Goal: a data owner in division B approves an EXTERNAL (peer-division) user's request to an un-granted doc, then the external user gets the answer (A2A callback says "approved, re-send").

**DECISION (advisor):** Do NOT add "denied-but-owned → approval" routing (it would invert the committed q4-denial security property, leak doc existence to any authenticated user, and enable approval spam). Instead reuse the existing `cross_grants` mechanism — it already writes arbitrary relations and `check_auth` already routes `pending_approval` → approval. Two steps, verify Step 1 before Step 2:

### Step 1 — capability, ~1 manifest line, NO code change
Add to `infra/divisions/beta.yml` `cross_grants:`
```yaml
  - {user_email: alice@example.com, home_division: alpha, relation: pending_approval, doc: q4_financial_results}
```
Then: `python scripts/federate_divisions.py --only beta` (writes the pending tuple to beta's OpenFGA; no re-onboard, no restart needed for a tuple change).
Prove the cycle (grant bug already fixed in `e6ddf29`):
- alice@alpha → q4 → beta `auth_decision flow=local_needs_approval` → returns `input_required` + approval_request_id.
- bob@beta approves via beta's HMAC deep-link (`GET /approve/{rid}?decision=approve&exp=&token=`; token = HMAC-SHA256(beta's `approval_hmac_secret`, `"{rid}:approve:{exp}"`)).
- worker `activity_grant_access` grants the cross-principal `alice@example.com|<alpha-iss-ns>` viewer; verify `openfga viewer granted: True`.
- alice@alpha re-sends q4 → real answer.
Verify in beta + worker logs.

### Step 2 — the "+A2A callback" (the only genuinely new code)
Thread `callback_url` + originating task_id from the `/a2a/query` payload → `agent.graph.run_query` (add param) → `agent.nodes.start_approval` → populate `ApprovalInput.originating_agent_url` / `originating_task_id`. The workflow's `send_a2a_callback` and alpha's `POST /tasks/{id}/callback` already exist; callback message is already "approved, re-send".
**SSRF (do this in Step 2):** validate the inbound `callback_url` against the known `settings.peer_agent_url` before the worker POSTs to it (it's DID-gated so non-blocking, but validate anyway).

### Don't lose the pure-denial negative control
After Step 1, BOTH beta docs have cross-grants (technical_architecture=viewer, q4=pending) → no doc left to demonstrate plain cross-division denial, and commit `436a47c`'s q4-denial claim goes stale. Add a THIRD beta doc (new file in `agt-federated-rag/tests/docs/cluster-b/`, e.g. `security_incidents.txt`) with NO cross-grant → cross-alice always denied. This needs a beta re-onboard (re-ingest) + re-federate. Keeps the 3 clean behaviors: viewer→immediate, pending→approval, none→denied. Note the q4 role change so the old commit's claim isn't silently false.

---

## 📋 REMAINING milestones (IMPLEMENTATION_PLAN.md)
- **M3** discovery + multi-peer (today PEER_AGENT_* is a single outbound peer; TRUSTED_ISSUERS is multi).
- **M4** offline account-bound delivery (the async push side of cross-division approval).
- **M5** access lifecycle (grant/revoke/expiry).
- **M6** residency / self-hosted inference (would let the LLM timeout drop back down).
- **M7** mTLS / IaC / secrets.
- **M8** hash-chained tamper-evident audit (pairs with the `agt_audit=True` events already emitted).
- **M-GOV** governance tests. Known item: the AUTOMATIC peer-trust-degradation kill-switch is still a DESIGN ITEM (`mesh/agent_identity.py` ~72-76); the manual kill-switch + data-path `_enforce` + OpenFGA are real/enforcing.
- **≥3-division e2e** (gamma manifest exists at port_base 8300).
- Task #5 (deferred): consolidated UI (division login + monitor + inbox).
- **Hardening:** `onboard_division.py` should pre-check every derived host port is free and abort clearly (the 8101 collision silently left alpha's OpenFGA unreachable). See `memory/division-port-collisions.md`.

---

## 🖥️ HOW TO RESUME — environment & live state

**Divisions (each = own physically-isolated Docker stack, project `agt-div-<id>`):**
| div | port_base | agent | openfga | keycloak(issuer) | onboarded | notes |
|-----|-----------|-------|---------|------------------|-----------|-------|
| alpha | **8400** | 8400 | 8401 | 8402 | yes | re-homed off 8101 collision; issuer `http://localhost:8402/realms/rag` |
| beta  | 8200 | 8200 | 8201 | 8202 | yes | issuer `http://localhost:8202/realms/rag` |
| gamma | 8300 | 8300 | 8301 | 8302 | not this session | for the 3-division e2e |

- **Agents** (api + Temporal worker) managed by `scripts/clusters.ps1 {status|start|stop|restart} <id|all>`. Logs in `logs/<id>-api.{out,err}` and `logs/<id>-worker.{out,err}`. Uses Start-Process (durable across turns).
- alpha + beta agents were running at session end; both healthy (`clusters.ps1 status`).
- **Address division services as `127.0.0.1`, NOT `localhost`** — WSL2 `wslrelay.exe` squats IPv6 `::1` and can shadow a service. The issuer string must stay `localhost` though (it's baked into token `iss` and the principal hash).
- **Foreign docker stacks on this machine** (storyteller, llm_browser, story-8-4/8-5/…, rag-*) compete for ports — `story-8-4-backend` is what stole alpha's 8101. `onboard` does NOT yet detect this.

**Credentials/secrets per division:** `infra/generated/<id>/secrets.json` (`seed_user_password`, `approval_hmac_secret`, `openfga_api_token`, …), `did.json` (`did`,`jwk`), `state.json` (`store_id`,`model_id`). All gitignored. Agent env: `agt-federated-rag/.env.<id>` (gitignored).

**Mint a user token + drive a query (pattern used all session):**
- token: `POST {issuer}/protocol/openid-connect/token` grant_type=password, client_id=rag-ui, username alice/bob, password = secrets.json `seed_user_password`, scope `openid email profile`. Tokens carry verified `email` (needed for the principal).
- query: `POST http://localhost:<agent_port>/query` (SSE) with `Authorization: Bearer`.
- principal helper: `scripts.onboard_division._seed_principal(email, issuer)` == runtime `auth.token_validator.principal(claims)`.

**LLM:** NVIDIA NIM (`meta/llama-3.3-70b-instruct`), `OPENAI_API_BASE/KEY` in `.env.<id>`. Cold-starts: first call after idle hangs 60–120s then warm ~2–3s; timeout is 120s + 2 retries. (Corporate TLS interception means raw probes need verify=off; the agent connects fine.)

**Onboard / federate / teardown:**
- `python scripts/onboard_division.py infra/divisions/<id>.yml` (idempotent; `--teardown` = down -v + remove generated artifacts; `--force` rotates secrets).
- `python scripts/federate_divisions.py [--only <ids>] [--dry-run]` then `clusters.ps1 restart <ids>`.

**Untracked (not mine):** `redteam/M0_REVIEW_prod.md`, `redteam/M0_REVIEW_quality.md` (teammate review agents).

---

## Memory pointers (C:\Users\vilmo\.claude\projects\D--work-ai-governance\memory\)
- `m2-cross-division-identity.md` — namespaced principal + federation.
- `division-port-collisions.md` — the 8101 collision + 127.0.0.1 vs localhost.
- `treat-fedrag-as-product.md` — production, not a demo.
