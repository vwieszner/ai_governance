# AGT Federated-RAG — Session Status & Handoff

_Last updated: 2026-06-11. Product: Microsoft Agent Governance Toolkit multi-division federated RAG (DID + Ed25519 + per-action policy + Temporal approval + OpenFGA per-chunk ReBAC). This is a PRODUCTION system for real divisions/users — not a demo._

Overarching goal (active): 100% functionality, every useful scenario proven working, security 100%, capable of real users. Execute IMPLEMENTATION_PLAN.md milestones M0→M8 + M-GOV + a ≥3-division e2e, production-grade, each with a review gate.

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
- **M5 revocation (FR-7.2/7.3, commit after 00d6471):** `revoke_viewer` + `POST /access/revoke` (owner-authenticated, audited) — proven live: owner revokes → viewer removed + pending set → re-ask re-enters approval (no stale reuse). REMAINING for M5: expiry (FR-7.1) via OpenFGA conditional tuples.

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
