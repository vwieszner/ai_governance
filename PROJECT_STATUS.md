# Project Status — AGT Federated RAG

> **This is the single source of truth for what is built, partially built, and not built.**
> Where any other document disagrees with this one about *current state*, this document wins.
> `PRODUCT_REQUIREMENTS.md` defines the target (the spec); the executed milestone plan is archived
> at `docs/archive/IMPLEMENTATION_PLAN.md` (history). **This file records where we actually are.**

**Last verified:** 2026-06-17
**Method:** five parallel audit agents, one per milestone slice, each verifying requirements
against the actual code (file:line) and **running the test suite** — not trusting docstrings,
comments, or prior handoff notes. Full backend suite (current): **252 passed, 2 skipped
(254 collected)**. The skips are live-infra integration tests (cross-store isolation,
admin-lifecycle) plus one honest abstention (discovery lookup is not bounded — see NFR-6).

### Update log — 2026-06-17 (post-audit fixes)
- **New feature — pluggable multi-retriever + retrieval-as-a-service.** N retrievers (Qdrant,
  Neo4j seam, any number of external RaaS endpoints) fan out and are RRF-fused; every returned
  chunk is still per-chunk authorized (governance preserved). `rag/retriever.py`,
  `config.RaasEndpoint`, `tests/test_retriever.py` (12 tests).
- **Closed FR-7.1** (grant expiry wired), **FR-8.1/NFR-9** (`GET /audit` admin export),
  **FR-4.3** (runtime kill-switch), and a chunk of the proof debt (`test_mesh`, `test_scaling`,
  `test_governance_controls`, `test_lifecycle`, `test_audit_endpoint`, `test_killswitch`).
- **Wave 2 (closed):** **FR-6** offline, account-bound delivery (durable per-user inbox seeded at
  park + `GET /inbox` regenerate-at-delivery + cross-division callback + in-app badge), **FR-2.4**
  division-native UI (N-division model), and the **3-division e2e harness authored** (SC-1…SC-12,
  skips without live stacks).
- **Newly surfaced:** discovery `registry.find()` is O(N) — NFR-6 only half-met (inbox is O(1)).
- **Wave 3 (closed):** FR-3.6 hardening (recipient-bound, short-expiry signed assertion validated
  far-side), discovery wiring (discover→negotiate→delegate + graceful fallback + observable FR-3.4),
  and bounded `registry.find` (NFR-6).
- **Wave 4 (closed):** CRL certificate-revocation now enforced at the mTLS handshake (refresh +
  distribution point); OCSP checking since added (see NFR-3 below). **All six selected gaps are now addressed.**
- **Wave 5 (independent red-team + fixes, closed):** a 4-agent adversarial pass (each finding
  demonstrated, default-DEFENDED) found **3 VULNERABLE** + several hardening items — **all fixed with
  regression tests.** Every confidentiality control held. See the Security review section below.
- **Wave 6 (production hardening + Kubernetes, closed 2026-06-18):**
  - **Lint clean + CI:** `ruff check .` is **clean** (real fixes + intentional-`E402` suppression via
    config); new `.github/workflows/ci.yml` gates ruff + pytest + vitest (mypy informational — ~949
    legacy `--strict` findings ratcheted for new code, not faked).
  - **Governance hardened:** **HMAC-keyed audit chain** — tamper-EVIDENT → tamper-PROOF when keyed
    with off-host key custody (backward-compatible; `tests/test_audit_hmac.py`); **OCSP readiness**
    (AIA responder URL in issued certs + a validated stapling hook) — now **enforced** inbound by
    `transport/ocsp.py` (see NFR-3 below); **MCP** executor proven to never forward a raw user token (`_assert_no_user_credential`).
  - **Real Kubernetes deployment** (`k8s/` kustomize, alongside Compose) — **deployed LIVE on a local
    kind cluster**: the full division (6 stateful services + agent + worker) reaches Running; agent
    `GET /health` → **200** with its DID. Fixed two real manifest bugs en route (the distroless
    `openfga` image can't use `sh -c`; a missing `AGENT_SPONSOR_EMAIL`). Per-namespace NetworkPolicy
    isolation (NFR-2). Remaining: a production cluster with a NetworkPolicy-enforcing CNI + HA stores.
- **Wave 7 (governed cross-agent tool delegation, closed 2026-06-19):** an agent that hits a
  sub-problem needing a **tool capability it lacks** now discovers the peer that advertises it and
  delegates the *tool call* over a DID-signed `/a2a/tool` channel; the peer runs **its own** governed
  tool and returns a signed result.
  - **In-process governed tool registry** (`tools/local_tools.py`) behind the existing 3-gate MCP
    executor — `calc` is an **AST-allowlist sandbox** (no `eval`; names/attribute-access/calls outside
    a fixed grammar rejected) and `units` is a fixed conversion table; both deterministic, no I/O.
  - **`/a2a/tool` secure channel** (`api/main.py`) — replicates the `/a2a/query` envelope **exactly,
    in order**: kill-switch → non-finite-number reject → Ed25519 verify + replay guard → trust gate →
    recipient-bound assertion (`aud`=this DID) → **default-deny policy on the DELEGATED user** →
    `run_local_tool` → **DID-signed** result (a tool/policy failure returns a signed `status="failed"`,
    never a 500). Sender `mesh.peer_client.call_peer_tool` reuses the same signing/mTLS/breaker +
    response-signature-verify path as `call_peer_agent`.
  - **Capability discovery by tool** (`mesh/discovery.py` `find_peer_for_capability`) reuses
    discover→negotiate; trust/url/DID come from the operator-curated `peer_trust` anchor (the broker is
    untrusted). **Orchestration** (`agent/nodes.py` `solve_with_tools`) routes the capability, runs
    **locally first** when served, else delegates, and **bounds the loop** (`max_tool_delegations`).
  - **Security invariants preserved:** no raw user token ever forwarded (identity travels as a
    recipient-bound, short-TTL assertion minted from the per-request claims ContextVar); the peer
    re-runs its **own** default-deny authorization on the delegated user (delegation never bypasses
    authz); all responses DID-signed and verified fail-closed; the calc AST allowlist is the sandbox
    boundary. Every branch audited (`agt_audit=True` → the tamper-evident chain).
  - **Security review fix — F2 (HIGH availability):** the `/a2a/tool` result was signed inside a
    try/except but **serialized outside it** — a tool result containing `inf`/`nan` (JSONResponse uses
    `allow_nan=False`) or an oversized int (CPython's int→str digit limit) raised UNCAUGHT in
    `render()` → HTTP 500 instead of the contract's signed `status="failed"`. Fixed defence-in-depth:
    the computed RESULT is now validated (`_result_is_json_safe` — non-finite floats + int bit-length
    cap) and the final sign+serialize is wrapped, so an unserializable/sign-time failure degrades to a
    signed failure, never a 500. Regression-tested (`test_a2a_tool.py`: inf/nan/oversized-int via the
    tool and via a real `pow(2, 50000)` expression). (Separately, the tools-builder bounds pow/exp at
    the sandbox — two independent guards.)
  - **Tests:** `tests/test_a2a_tool.py` (19 — 503/422/401-unsigned/403-low-trust/401-wrong-audience/
    signed-failed-unconfigured/signed-failed-policy-denied/happy-path/oversized-args/no-body-user_id +
    the F2 unserializable-result cases) and `tests/test_tool_orchestration.py` (18 — local-first,
    delegate-and-return, degrade paths, cap, router, discovery, and the no-raw-token-on-the-wire
    invariant), plus the tools-builder's `test_local_tools.py`. Full backend suite **343 passed,
    1 skipped**; `ruff check` clean.

---

## Executive summary

The **application-layer governance core is real and tested**: per-division physical isolation,
per-division identity with cross-division token rejection, DID-signed + replay-protected agent
channel, per-action default-deny policy on every node, OpenFGA per-chunk ReBAC (3-way
allowed/needs-approval/denied), durable Temporal approvals with an authenticated owner inbox,
tamper-evident hash-chained audit, output DLP, data-residency egress guard, wired mTLS serving,
and scheduled DID/HMAC rotation. These are not decorative — the audit confirmed the policy
engine, trust gate, and DLP genuinely fail closed.

**Remaining headline gaps — FR-6 is now closed; the other three are in progress or infra-gated:**

1. ✅ **Offline, account-bound delivery (FR-6) — DONE (2026-06-17).** Durable per-user outcome
   inbox seeded at park-time (offline-deliverable immediately — no tab/poll), `GET /inbox` with
   regenerate-at-delivery (revoked/expired grant → "declined", never stale data), cross-division
   via the signed callback, in-app badge. `outcome_store.py`, `tests/test_offline.py`.
2. ✅ **Verifiable cross-division user identity (FR-3.6) — DONE (2026-06-17).** The user assertion is
   now recipient-bound (`aud`=target DID), short-expiry (300s) + `jti`, riding the DID-signed
   envelope; the receiver validates recipient + expiry + signer-issuer binding, then re-authorizes
   against its own OpenFGA. Verifiable + non-replayable, no forwarded token, no new infra
   (`tests/test_assertion.py`, 19 tests). Plan D-2 / `config.py` JWKS narrative is superseded.
3. ✅ **Dynamic discovery + negotiated delegation (FR-3.1/3.2) — DONE (2026-06-17).** The agent now
   discovers a capable peer via the broker, negotiates, and delegates (graceful fallback to the
   configured peer); `registry.find()` is bounded (capability index — closes the NFR-6 skip);
   MonitorPanel renders discover→delegate events (FR-3.4). **Residual:** the signed transport still
   routes bytes to the *configured* peer — true multi-peer byte-routing needs the transport to accept
   a discovered target (single-peer demo confirms+observes but doesn't reroute).
4. 🟡 **3-division end-to-end test — AUTHORED (2026-06-17), not yet run.**
   `e2e/test_full_federation.py` maps SC-1…SC-12 (14 tests) + skips cleanly; the real assertions
   execute only against ≥3 live stacks (`RUN_E2E=1` + reachability probe).

Smaller gaps — **now closed:** grant expiry ✅, `GET /audit` ✅, runtime kill-switch ✅,
division-native UI ✅ (FR-2.4), bounded discovery lookups ✅ (NFR-6), CRL revocation ✅ (NFR-3),
proving-test debt largely ✅, OCSP checking ✅ (NFR-3; an HA production responder is deploy-time
infra). **Remaining residuals:** the 3-division e2e run (needs live stacks), and true multi-peer transport reroute (discovery
confirms+observes today). Plus pre-existing items: admin user-lifecycle API (FR-2.2), HA stores,
**independent external pen-test** (the red-team below was an internal adversarial pass, not a
third-party engagement) — see the Security review section.

---

## Independent red-team review (2026-06-17)

A 4-agent adversarial pass attacked the new code (FR-3.6 identity, FR-6 delivery, discovery/RaaS,
governance edge). Discipline: a finding counted as VULNERABLE **only if demonstrated with a runnable
probe** (default DEFENDED). Result: **3 VULNERABLE + 6 hardening items — all fixed, with regression
tests; every confidentiality control held.**

| Finding | Sev | Status |
|---|---|---|
| Never-expiring assertion — `exp: 1e400`/`inf`/`NaN` accepted (Starlette JSON parses non-finite) | **HIGH** | ✅ Fixed — `math.isfinite` guard + non-finite JSON rejected at `/a2a/query` |
| Delivery callback had no task↔delegate binding (trusted peer could overwrite/inject any task's outcome) | MED | ✅ Fixed — callback rejected unless signer DID == the task's recorded delegate + task was federated |
| RaaS content poisoning — authorized `chunk_id` could carry attacker **text** | MED | ✅ Fixed — served text re-sourced from the trusted store of record; external retrievers contribute ids/ranking only |
| Callback denial-confusion, callback replay, RaaS→metadata-IP SSRF, delegation-marker injection, badge accounting | hardening | ✅ All fixed + tested |
| `/inbox` IDOR, stale-data-after-revoke, chunk-id-set authz, trust-gating, assertion forgery/replay/audience/cross-issuer, kill-switch, `/audit` authz, CRL enforcement, grant expiry | — | **DEFENDED** (demonstrated) |

**Residuals that need deployment, not code:** the audit hash-chain is keyless with a local anchor
(forgeable only by a host-compromise attacker) → set `AUDIT_ANCHOR_URL` to a remote append-only sink;
`require_mtls` without `TLS_CRL_FILE` serves no revocation gate → set it. Both now **warn at startup**.
OCSP is now checked inbound (opt-in `TLS_OCSP_MODE=soft|hard`; `soft` also warns at startup).
Still open: a true third-party pen-test. Probes + write-ups:
`redteam/REDTEAM_*.md` + `redteam/probe_*.py`.

---

## Status legend

| Symbol | Meaning |
|---|---|
| ✅ DONE | Implemented, wired into the running system, and tested. |
| 🟡 PARTIAL | Core works; a named sub-requirement or proof is missing/unwired. |
| 🩹 STUB | Code exists but is a placeholder, unwired, or library-only (not enforced on the live path). |
| 🔴 MISSING | Not implemented (or not at the level the requirement specifies). |

---

## Milestone status

| Milestone | Requirements | Status | One-line verdict |
|---|---|---|---|
| **M0** Tenancy + onboarding | FR-1, NFR-2, NFR-8 | ✅ DONE | Physical per-division stacks + manifest-driven onboarding (`--dry-run/--force/--teardown`); `division_id` threaded + signed. Kill-B/cross-store proof exists but skips without live stacks. |
| **M1** Per-division identity | FR-2 | ✅ DONE | Backend rejects foreign-division tokens (issuer+audience+key, tested); **UI now division-native** — N-division model via `VITE_DIVISIONS`, FR-2.4. Residual: admin user lifecycle is script-driven, no self-service API (FR-2.2). |
| **M2** Verifiable X-division identity | FR-3.6, FR-3.7 | ✅ DONE | FR-3.7 (authorized→immediate vs needs-approval) works; **FR-3.6 now hardened** — recipient-bound (`aud`=target DID), 300s-expiry, `jti` signed assertion validated far-side (recipient+expiry+signer) then re-authorized (`test_assertion.py`). |
| **M3** Discovery + negotiation | FR-3.1–3.5 | ✅ DONE | FR-3.3 signed/replay-protected agent identity ✅; **discovery now wired** — discover→negotiate→delegate with graceful fallback, bounded `registry.find()`, observable FR-3.4 markers in MonitorPanel. Residual: signed transport still routes to the configured peer (true multi-peer reroute is a transport follow-up). |
| **M4** Offline delivery | FR-5, FR-6 | ✅ DONE | FR-5 durable approval + authenticated owner inbox; **FR-6 now done** — durable per-user inbox seeded at park, `GET /inbox` regenerate-at-delivery, cross-division callback delivery, in-app badge (`outcome_store.py`, `test_offline.py`). |
| **M5** Access lifecycle | FR-7 | ✅ DONE | Revoke (FR-7.2) owner-gated; **expiry (FR-7.1) now wired** — approvals honor `approval_grant_ttl_seconds` via `grant_viewer_until`; re-ask re-enters approval on both revoke and expiry (`test_lifecycle.py`). |
| **M6** Data residency | NFR-1 | ✅ DONE | Egress guard wired into **both** the answer LLM and the intent LLM; fail-closed. Self-hosted backend is operator-supplied (config-driven), not bundled — acceptable per plan. |
| **M7** Transport + IaC + secrets | NFR-3,4,5,8,10 | ✅ MOSTLY DONE | mTLS serving + outbound peer certs ✅; rotation ✅; secrets ✅; **CRL revocation enforced** at the handshake + **OCSP checking** of inbound peers (opt-in soft/hard; proven live vs `openssl ocsp`). **Real Kubernetes deployment** (`k8s/` kustomize, per-namespace NetworkPolicy isolation) — **deployed + verified Running on a local kind cluster** (agent `/health`→200); Compose path retained. Remaining: an HA production OCSP responder (infra), HA stores, a NetworkPolicy-enforcing CNI in prod. |
| **M8** Audit & accountability | FR-8, NFR-9 | ✅ DONE | Tamper-evident hash chain + anchor, now **optionally HMAC-keyed → tamper-PROOF** with off-host key custody (`test_audit_hmac.py`); admin-gated division-scoped **`GET /audit`** export + CLI `verify_audit.py`. |
| **M-GOV** Governance | FR-4, NFR-6, NFR-7 | 🟡 MOSTLY DONE | Per-node `_enforce` ✅, trust gate ✅, output DLP ✅, needs-approval-from-ReBAC ✅, injection containment ✅ — now with named proving tests (`test_governance_controls.py`, `test_mesh.py`). **Kill-switch is now a runtime lever** (`POST /admin/kill-switch`, FR-4.3). NFR-6: inbox lookup is O(1) (`test_scaling.py`) **and discovery `registry.find()` is now bounded** (capability index, `test_discovery_wiring.py`). NFR-7 is measure-and-log, not a budget gate. |

---

## What is NOT done — the open work, prioritized

### P0 — Goal-defining gaps (the product's stated reason to exist)

- ✅ **FR-6 — Offline, account-bound delivery — DONE (2026-06-17).** Durable per-user outcome
  store (`outcome_store.py`, Redis hash keyed on namespaced principal, 30-day retention, no short
  TTL), seeded at `/query` park-time so it's offline-deliverable immediately; `GET /inbox` +
  `POST /inbox/{id}/ack` regenerate the answer through the governed pipeline at delivery (no stale
  leak — revoked/expired → "declined"); cross-division outcomes land in the requester's home-division
  store via the signed callback (FR-6.6); in-app badge (FR-6.5). `tests/test_offline.py` (8 tests).

- ✅ **FR-3.6 — Verifiable cross-division user identity — DONE (2026-06-17).** The home agent binds
  the user assertion with `aud`=target DID, `iat`, `exp` (300s), `jti` inside the DID-signed envelope
  (`mesh/peer_client._bind_user_assertion`); the receiver
  (`auth/token_validator.validate_cross_division_assertion`, called from `api/main.py` a2a_query)
  validates recipient (`aud`==self DID) + expiry + signer-issuer binding, then re-authorizes against
  its own OpenFGA. Verifiable + non-replayable, no forwarded token, no new infra. `tests/test_assertion.py`.

- ✅ **FR-3.1 / FR-3.2 — Discovery + negotiation — DONE (2026-06-17).** `mesh/discovery.py`
  (discover→negotiate→delegate, lazy self-register, trust gated by `peer_trust` not broker membership)
  wired into `agent/nodes.py` delegation with graceful fallback to the configured peer.
  **Residual:** the signed transport still routes bytes to the configured peer (true multi-peer
  reroute is a transport follow-up); discovery confirms+observes the peer today.

- 🟡 **e2e — `e2e/test_full_federation.py` — AUTHORED (2026-06-17), runs only with live stacks.**
  Maps SC-1…SC-12 (14 tests) incl. browser-closed offline delivery + kill-B isolation; collects
  clean and skips without ≥3 live stacks (`RUN_E2E=1` + reachability probe gate). Real assertions
  pending a live 3-division bring-up.

### P1 — Spec'd controls that are partial/unwired

- ✅ **FR-7.1 — Grant expiry — DONE (2026-06-17).** Approvals honor `approval_grant_ttl_seconds`
  via `grant_viewer_until`; `tests/test_lifecycle.py`.
- ✅ **FR-8.1 / NFR-9 — `GET /audit` — DONE (2026-06-17).** Admin-gated, division-scoped,
  tamper-evident export; `tests/test_audit_endpoint.py`.
- ✅ **FR-4.3 — Runtime kill-switch — DONE (2026-06-17).** `POST /admin/kill-switch` + a Redis
  flag honored per request on `/query` (and `/a2a/query`), no restart; `tests/test_killswitch.py`.
- ✅ **NFR-3 — CRL revocation — DONE (2026-06-17).** Enforced at the inbound mTLS handshake
  (`VERIFY_CRL_CHECK_LEAF`, mtime-cached CRL refresh, `CRLDistributionPoints` in issued certs,
  `--revoke` to republish); `test_transport.py`. **OCSP — DONE (2026-11-03):** `transport/ocsp.py`
  checks the authenticated peer leaf right after the handshake verifies it (an `sslobject_class`
  hook on the server context — the stdlib has no in-handshake OCSP callback), POSTing a nonce'd
  request to the cert's AIA URL (or `TLS_OCSP_RESPONDER_URL`), verifying signer (CA or CA-delegated
  `OCSPSigning`), CertID, nonce and thisUpdate/nextUpdate, caching per serial until nextUpdate.
  `TLS_OCSP_MODE=off` (default) | `soft` (outage/unknown → allow + warn) | `hard` (fail closed);
  REVOKED always refused. Issuer: `issue_division_certs.py --ocsp-url`. Hermetic `tests/test_ocsp.py`
  (30) + **live proof** `examples/mtls-ocsp/prove_ocsp_live.py` (real `openssl ocsp` responder +
  uvicorn via `tls_serving_kwargs`: good accepted, revoked/unknown refused, hard vs soft on outage).
  Caveats: a cache miss blocks the event loop for ≤`TLS_OCSP_TIMEOUT` (3s); server-side stapling
  still needs a TLS front-end; the **nginx-edge** mode needs `ssl_crl`/`ssl_ocsp` wired separately.
- ✅ **NFR-6 — Bounded lookups — DONE (2026-06-17).** Inbox is O(1); `discovery/registry.py::find()`
  now uses a capability→DIDs index (point read, not O(N) scan); `test_discovery_wiring.py` proves the
  lookup touches only matching entries regardless of registry size.
- ✅ **FR-2.4 / M1 UI — Division-native UI — DONE (2026-06-17).** UI now uses an N-division model
  (`Division` type + `VITE_DIVISIONS`), "cluster"→"division" throughout, division explicit at login;
  `npm test` 14 passed + build clean. Residual: `vite.config.ts` proxy still lists 2 divisions (a 3rd
  needs a proxy entry).

### P2 — Proof/quality debt

- **Missing plan-named proving tests:** `test_offline`, `test_lifecycle`, `test_approval_inbox`,
  `test_mesh`, `test_monitor`, `test_scaling`, `test_perf`, `test_iac`, `test_portability`,
  `test_durability`, plus several named functions in `test_a2a`/`test_governance`/`test_approval`.
  Many *controls* exist and are covered by differently-named tests; some (offline, lifecycle,
  discovery wiring) are genuinely unproven.
- **Live-infra proofs skip in CI:** `test_division_cannot_read_peer_store`,
  `test_admin_user_lifecycle`. Add a hermetic config-invariant unit and/or an integration lane.
- **Stale k8s manifests** (`agt-federated-rag/k8s/*`) describe the retired shared-registry
  2-cluster model — delete or replace with real per-division IaC.

---

## Test reality

- Full backend suite: **343 passed, 1 skipped** (as of 2026-06-19, post Wave-7 cross-agent tool
  delegation + its F2 security-review fix; was **252 passed, 2 skipped** at the 2026-06-17 audit,
  itself up from 138/2 at first audit — the growth is this session's retriever feature + gap-fix +
  red-team + hardening + Wave-7 governed-tool-delegation regression tests).
- The remaining skip is an honest abstention: `test_scaling.py` — discovery `registry.find()` is an
  O(N) in-memory scan, not a bounded point read (NFR-6; the bounded lookup is the Redis approval
  index). The earlier cross-store-isolation / admin-lifecycle skips now run when live stacks exist.
- UI: vitest unit tests (auth/PKCE/SSE) + Playwright e2e (local / federated / approval-with-tab-open)
  exist and pass per prior runs (not re-run in this audit).
- **The plan's requirement→test traceability matrix is aspirational, not actual** — roughly ten
  named test files/functions in it do not exist. Treat the matrix as a TODO, not a record.

---

## Documentation map (current vs historical)

**Authoritative / current:**
- `README.md` — entry point, setup, capabilities (corrected; see caveats it now carries).
- **`PROJECT_STATUS.md`** — this file: what is / isn't built.
- `PRODUCT_REQUIREMENTS.md` — the target requirements (FR/NFR/SC, the spec). Its "Today:" notes
  describe the **original pre-M0 baseline** and are historical — read current state here, not there.
- `THREAT_MODEL.md` — security posture, deployment-dependent items, open design decisions.
- `redteam/M0_REVIEW_{security,prod,quality}.md` — the current milestone review gate (note:
  the prod review's "no teardown" blocker is itself stale — `--teardown` exists).

**Historical / superseded** (moved to `docs/archive/`):
- `IMPLEMENTATION_PLAN.md` — the milestone plan, now **fully executed** (M0–M8 + the gap-closures +
  red-team). No longer pending work; some references are stale (k8s/Helm never built — it's Compose;
  D-2 superseded). History only.
- `SESSION_STATUS.md`, `TEMPLATE_TASKS.md` — prior handoff logs. They claim "M0–M8 + e2e all
  complete & proven live"; this audit shows that **over-claims** (FR-3.6, FR-6, discovery,
  revocation, `/audit`). Kept for history, not as status.
- `SECURITY_AUDIT.md` — dated static audit (2026-06).
- `docs/archive/redteam-legacy/` (`RED_FINDINGS.md`, `BLUE_FIXES.md`, `GOVERNANCE_AUDIT.md`) —
  reference the **retired** dual A2A+AGT topology (ports `:8000/:8002/:8010/:8012`, the removed
  `federated-rag/` directory). Historical only.

### The three narratives this file reconciles
1. **PRD "Today:" notes** → pre-M0 baseline (nothing multi-division). Historical.
2. **SESSION_STATUS / TEMPLATE_TASKS** → "everything done." Optimistic; contradicted above.
3. **redteam M0 reviews** → rigorous restart at M0 (and even these have drifted, e.g. teardown).

This document supersedes all three for questions of current state.
