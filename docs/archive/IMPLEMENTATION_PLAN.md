> **⚠️ ARCHIVED — HISTORICAL, EXECUTED PLAN.** This was the milestone plan for the multi-division
> build. As of 2026-06-17 it is **fully executed** (M0–M8 + M-GOV + the six gap-closures + an
> independent red-team), so it no longer describes pending work — and some of it is stale (e.g. the
> "real k8s/Helm" M7 item was never done; the deployment is Docker Compose, not k8s; decision D-2 was
> superseded). **For current state see `PROJECT_STATUS.md`.** Kept only for development history.

# AGT Federated-RAG — Multi-Division Implementation Plan

## Context

`PRODUCT_REQUIREMENTS.md` defines a multi-division federated-RAG product: N isolated, governed
divisions where users log in to their own division and agents collaborate across divisions over the
internet — securely and identifiably — so a question one division can't answer is answered, with
consent, by another, and the outcome reaches the requester's account even if they were offline.

The repo today is a working **2-cluster AGT** system (Microsoft Agent Governance Toolkit: DID +
Ed25519 + per-action policy + Temporal approval + OpenFGA ReBAC). Three goal capabilities are **not
present**: real multi-division tenancy, cross-division discovery, and offline account-bound delivery.
A fourth was decided during review: cross-division user identity must be **verifiable (1b)**, not
agent-vouched.

This plan implements **all** FR/NFR/SC requirements as ordered milestones, proves **every** requirement
with a named test, gates each milestone with **three adversarial review perspectives**
(security / production-readiness / code-quality), and ends with a **≥3-division end-to-end test** that
exercises all scenarios — including the headline (approve/deny with the browser fully closed →
outcome on next login, cross-division, no 1h cap).

## Settled decisions

| # | Decision | Rationale |
|---|---|---|
| **D-1** | **AGT is the base; A2A retired.** | Confirmed by user (PRD A-1). |
| **D-2** | **User identity is verifiable (1b).** SPIKE OUTCOME (M2): Keycloak token-exchange works same-realm but CANNOT mint a token whose audience is another division's client (cross-realm `aud` → 400 "Audience not found"). So the assertion is the user's HOME-division token, forwarded inside the DID-signed envelope; the receiver validates it against a **trusted-issuer set** (the home issuer's JWKS) — signature+issuer+expiry+sub, audience NOT enforced (the DID-signed, replay-protected envelope + trusted-issuer allow-list provide the binding) — then re-authorizes the sub via its OWN OpenFGA. Still verifiable/cryptographic (not agent-vouched). | User chose 1b. Spike replaced the cross-realm-exchange assumption with home-issuer validation; no new dependency (`auth.token_validator.validate_peer_user_assertion`). |
| **D-3** | **Physical per-division isolation** — each division is its own stack/network with its own OpenFGA store, Qdrant, Redis, Keycloak realm, Temporal. | User choice. Satisfies NFR-2 (no shared point whose loss crosses a boundary); enables "different clouds" e2e + "kill B, A still serves." |
| **D-4** | **Dynamic discovery service** — a standalone, DID-secured registry/broker agents publish to and query at runtime. | User choice. Satisfies FR-3.1/3.2/3.5 incl. multi-hop. Control-plane only (capability metadata + endpoints/DIDs, **no division data**); its loss degrades discovery, never grants data access (agents still verify DIDs + re-authorize). |
| **D-5** | **No third-party libraries folded in** unless production-grade AND development-accelerating. ZeroID / ANP are **context only**, not dependencies. Token exchange = Keycloak; discovery service = built in-house to production quality. | User constraint. |
| **D-6** | **Offline delivery re-generates at delivery time**, not push-at-approval — re-runs the full governed pipeline (re-delegate → far side re-authorizes → regenerate) on next login, so a revoked/expired grant (FR-7) cannot leak stale data (FR-6.2). | Couples FR-6 × FR-7 correctly. |
| **D-7** | **Tamper-evident audit = a durable hash-chained store** (`audit/store.py`), not `structlog agt_audit=True`. | FR-8.2 / NFR-9. |

> **⚠️ As-built reconciliation (2026-06-17 audit — see `PROJECT_STATUS.md`).** Two items in this
> plan have drifted from the code: **(1) D-2 is stale** — the shipped cross-division user identity
> is *agent-vouched* (receiver checks `iss` + `email_verified` only), **not** the home-issuer-JWKS
> validation (signature/issuer/expiry) described above; that JWKS path was not built. **(2) The
> requirement→test traceability matrix below is aspirational, not actual** — roughly ten of its
> named test files/functions do not exist (`test_offline`, `test_lifecycle`, `test_mesh`,
> `test_monitor`, `test_scaling`, `test_perf`, `test_iac`, `test_portability`, `test_durability`,
> `test_approval_inbox`, and several named functions). Treat the matrix as a TODO list.

**Open items needing a human call during execution (do not block planning):** cross-division
issuer-trust bootstrap shape (verify Keycloak token-exchange cross-realm audience in M2 spike);
FR-7.1 expiry mechanism (OpenFGA conditional tuples vs external grant-ledger + sweep); self-hosted
inference target (vLLM / Ollama / keep NVIDIA configurable); out-of-band channel (in-app inbox vs
email vs push); mTLS cert authority + CRL/OCSP source.

---

## Milestone sequence

`M0 → M1 → M2 → M3` is a hard chain. `M4` needs M2. `M5` needs M4. `M6/M7/M8` parallelize after M2/M4.
`M-GOV` is cross-cutting (writes the missing proving tests for governance that already works).
**Each milestone ends with the 3-perspective adversarial review gate (see "Review gates").**

### M0 — Tenancy foundation + parameterized onboarding (FR-1.1–1.4, NFR-2, NFR-8)
<!-- NFR-10 (no hardcoded localhost / portability) is proven in M7 by
test_portability::test_no_hardcoded_localhost, not M0 — M0's render_agent_env still
emits localhost endpoints. Removed from M0's Proves set (m0-quality review). -->
- `config.py`: add `division_id` (+ trusted-peer set, residency, transport settings used later).
- New `scripts/onboard_division.py` + `infra/division-stack.template.yml`: generalize the hardcoded
  `setup_agt.py write_env` into a parameterized **physical stack** generator (own OpenFGA store,
  Qdrant, Redis, Keycloak realm, Temporal, agent DID) from a division manifest — **no source edits**.
- `scripts/clusters.ps1`: discover N division manifests instead of the hardcoded `agt-a`/`agt-b`.
- Thread `division_id` through token claim, OpenFGA audit records, A2A envelope (`source_division`).
- **Proves:** `test_onboarding::{test_three_divisions_from_config, test_onboard_no_source_edit}`,
  `test_tenancy::test_division_id_threaded`, `test_isolation::test_division_cannot_read_peer_store`.

### M1 — Per-division identity & login (FR-2.1–2.4; fixes AUD-1)
- Per-division Keycloak realm (from M0 onboarding). **Delete the dual-audience mapper** in
  `setup_agt.py` (`kc_ensure_ui_client`) — that mapper *is* AUD-1. `auth/token_validator.py`'s
  existing `issuer=`/`audience=` checks then reject foreign-division tokens **for free** (FR-2.4).
- `ui/src/LoginForm.tsx` + `types.ts`: make the user's division explicit; division-scoped auth base.
- Admin role management (data owner / member / division admin) via realm roles + onboarding script.
- **Proves:** `test_identity::{test_token_scoped_to_division, test_foreign_division_token_rejected,
  test_admin_user_lifecycle}`, `test_authz::test_three_way_decide_deny_by_default`.

### M2 — Verifiable cross-division user identity (FR-3.6, FR-3.7) — **the 1b core**
- `mesh/peer_client.call_peer_agent`: before sending, mint a short-lived **user assertion** via
  Keycloak token exchange (`aud` = target division's agent), embed it in the signed payload.
- `api/main.py` `/a2a/query`: stop trusting the bare `user_id` string; **validate the embedded user
  assertion** against the home division's JWKS (trusted-issuer set), extract `sub`, then re-authorize
  against this division's OpenFGA (existing `check_auth` path).
- `auth/token_validator.py`: generalize from one issuer to a **trusted-issuer set** (peer divisions).
- FR-3.7: when the validated user is already authorized → return immediately, **no approval**.
- **Spike first** (H-DEC): confirm Keycloak cross-realm token-exchange audience shape.
- **Proves:** `test_a2a::{test_user_assertion_validated, test_forged_user_assertion_rejected,
  test_expired_assertion_rejected, test_authorized_immediate_no_approval, test_unauthorized_routes_to_approval}`.

### M3 — Dynamic discovery service + negotiated delegation + observable conversation (FR-3.1–3.5)
- New `discovery/` service (FastAPI): DID-signed **registration** (agent publishes endpoint +
  advertised capabilities + division), **query** (find capable peers), health/heartbeat,
  multi-party/multi-hop routing. TLS + DID-auth; holds **no division data**.
- `mesh/agent_identity.py`: refactor `verify_signed_message` / `_build_identity_registry` to resolve
  the signer's key **by claimed DID from a multi-peer registry** (preserve key-from-trusted-config-
  not-body, replay protection, trust gate). Removes single-hardcoded-peer assumption.
- `mesh/discovery.py`: client — discover → negotiate ("can you help with X?") → delegate.
- `ui/src/MonitorPanel.tsx`: surface the inter-agent / cross-division conversation (FR-3.4).
- **Proves:** `test_discovery::{test_find_capable_peer, test_negotiation_round_trip,
  test_multi_hop_three_divisions, test_unsigned_registration_rejected}`,
  `test_mesh::{test_multi_peer_did_resolution, test_replay_rejected, test_untrusted_peer_rejected}`,
  `test_monitor::test_interagent_events_surfaced` (+ UI vitest).

### M4 — Offline, account-bound delivery (FR-5, FR-6) — implements D-6
- Durable **per-user outcome store** (server-side, identity-bound, no short TTL) replacing the 1h
  Redis-poll model. `workflow/activities.py` `notify_user_of_decision`: stop being a log-only stub —
  write the durable outcome + fire the out-of-band notification (FR-6.5).
- New `GET /tasks/{id}/result` (the endpoint `ChatArea.tsx` already polls but doesn't exist) and
  `GET /inbox` (next-login retrieval) — both **regenerate the answer at delivery** through the full
  pipeline (FR-6.2), cross-division via the existing signed, SSRF-guarded `send_a2a_callback`.
- FR-5.2 authenticated owner inbox (verified owner, not deep-link-only).
- **Proves:** `test_offline::{test_outcome_durable_when_offline, test_regenerated_at_delivery,
  test_declined_message, test_retrievable_next_login_no_ttl_cap, test_out_of_band_notification_fired,
  test_cross_division_offline_delivery}`, `test_approval::{test_durable_survives_restart,
  test_approve_grants_and_records, test_deny_records}`, `test_approval_inbox::test_owner_authenticated`.

### M5 — Access lifecycle: grant, expiry, revocation (FR-7)
- Time-bound grants + `auth/openfga.py::revoke_viewer` (reuse `_delete_tuple`); `POST /access/revoke`.
- Re-ask of an expired/revoked grant **re-enters approval** (no stale reuse) — ties to D-6 regenerate.
- **Proves:** `test_lifecycle::{test_grant_expires, test_revoke_grant, test_reask_reenters_approval}`.

### M6 — Data residency / self-hosted inference (NFR-1)
- Residency mode for **both** `_get_llm` AND `_get_intent_llm` (both egress to api.nvidia.com today);
  configurable self-hosted backend; "external egress" configurable **off** and not required.
- **Proves:** `test_residency::{test_no_external_egress_when_local_mode, test_inference_within_boundary}`.

### M7 — Transport hardening + IaC (NFR-3, NFR-4, NFR-5, NFR-8, NFR-10)
- mTLS + cert-identity validation + **revocation (CRL/OCSP)** on internet-facing agent + discovery
  endpoints; wire `mesh.agent_identity.rotate_credentials` to a scheduled job (NFR-3 key rotation).
- Per-division secrets management (no secrets in source; rotate the known NVIDIA key); real k8s/Helm
  replacing placeholder manifests.
- **Proves:** `test_transport::{test_mtls_required, test_revoked_cert_rejected, test_no_auth_bypass_modes}`,
  `test_secrets::test_no_secrets_in_source`, `test_iac::test_division_standup_via_iac`,
  `test_portability::test_no_hardcoded_localhost`, `test_durability::test_state_survives_restart`.

### M8 — Audit & accountability (FR-8, NFR-9)
- New `audit/store.py`: durable, **hash-chained tamper-evident** audit (who asked what, retrieved/
  released, approved/denied + when, every cross-division delegation), division-scoped; `GET /audit`.
- **Proves:** `test_audit::{test_audit_trail_complete, test_hash_chain_tamper_evident,
  test_denials_audited, test_evidence_export_per_division}`.

### M-GOV — Governance proving tests (FR-4) — cross-cutting, runs alongside M0–M8
- The FR-4 controls already exist (per-node `_enforce`, trust gate, kill-switch, output DLP,
  OpenFGA-driven needs-approval) but have **no tests**. Write them.
- **Proves:** `test_governance::{test_every_node_enforces, test_low_trust_refused, test_kill_switch_halts,
  test_output_dlp_withholds, test_needs_approval_from_authz}`.
- **Scalability/perf** (NFR-6, NFR-7): `test_scaling::{test_inbox_lookup_bounded,
  test_discovery_lookup_bounded}`, `test_perf::{test_local_latency_budget, test_cross_division_budget}`.

---

## Requirement → test traceability (every requirement has a proof)

| Req | Proven by |
|---|---|
| FR-1.1/1.2/1.3/1.4 | `test_onboarding::*`, `test_tenancy::test_division_id_threaded`, `test_isolation::test_division_cannot_read_peer_store` |
| FR-2.1/2.2/2.3/2.4 | `test_identity::*`, `test_authz::test_three_way_decide_deny_by_default` |
| FR-3.1/3.2/3.4/3.5 | `test_discovery::*`, `test_monitor::test_interagent_events_surfaced` |
| FR-3.3 | `test_mesh::{test_multi_peer_did_resolution, test_replay_rejected, test_untrusted_peer_rejected}` |
| FR-3.6/3.7 | `test_a2a::{test_user_assertion_validated, test_forged_user_assertion_rejected, test_authorized_immediate_no_approval, test_unauthorized_routes_to_approval}` |
| FR-4.1/4.2/4.3/4.4/4.5 | `test_governance::*` |
| FR-5.1/5.2/5.3 | `test_approval::*`, `test_approval_inbox::test_owner_authenticated` |
| FR-6.1/6.2/6.3/6.4/6.5/6.6 | `test_offline::*` |
| FR-7.1/7.2/7.3 | `test_lifecycle::*` |
| FR-8.1/8.2/8.3 | `test_audit::*` |
| NFR-1 | `test_residency::*` |
| NFR-2 | `test_isolation::*` + e2e kill-B |
| NFR-3 | `test_transport::*` |
| NFR-4 | `test_secrets::test_no_secrets_in_source` |
| NFR-5 | `test_durability::test_state_survives_restart` |
| NFR-6 | `test_scaling::*` |
| NFR-7 | `test_perf::*` |
| NFR-8 | `test_iac::test_division_standup_via_iac` |
| NFR-9 | `test_audit::test_evidence_export_per_division` |
| NFR-10 | `test_portability::test_no_hardcoded_localhost` |

Tests live under `agt-federated-rag/tests/` (pytest + pytest-asyncio, already configured;
`asyncio_mode=auto`). UI tests under `ui/` (vitest, already configured).

---

## Adversarial review gates (the agent spawns)

**After every milestone**, before it is "done," spawn **three review agents in parallel**, each
seeing the milestone diff. Any **VULNERABLE** or critical finding **blocks** the milestone → fix →
re-run the gate. Reuse the `redteam/` model (verdicts DEFENDED / VULNERABLE / EXPECTED / FINDING,
recorded under `redteam/` — e.g. `M0_REVIEW_{security,prod,quality}.md`; legacy probe findings
are archived in `docs/archive/redteam-legacy/`).

| Perspective | What it checks (tailored per milestone) | Output |
|---|---|---|
| **Security** | Extends `redteam/` with new `probe_*` functions for the milestone's new surface: tenant-isolation breakout (M0/M1), foreign-division token acceptance (M1), **user-assertion forgery / token-exchange & delegation abuse / replay** (M2), unsigned/forged discovery registration + multi-peer DID spoof + SSRF (M3), outcome-store IDOR + cross-user delivery + notification spoofing (M4), stale-grant reuse after revoke (M5), egress leak in "local" mode (M6), mTLS/revocation bypass + secret exposure (M7), audit-chain forgery/truncation (M8). | Verdicts in the milestone's `redteam/*_REVIEW_*.md`; VULNERABLE blocks. |
| **Production-readiness** | Fail-closed on every new gate; durability across process/host restart; idempotency (esp. Temporal activities, outcome writes, grant revokes); observability (structured logs, OTel, `sre.py` SLO events); resource bounds (registry/inbox lookups not super-linear — NFR-6); rollback/feature-flag; graceful degradation (discovery/peer down → local still serves). | Findings list + must-fix blockers. |
| **Code-quality** | `ruff check`, `mypy --strict` clean; **reuse vs duplication** (e.g. reuse `_delete_tuple`, `sign_outbound_message`, existing `_enforce`); fail-closed correctness review; test adequacy vs the traceability row; no dead/decorative policy rules. | PR-style review; blockers fixed. |

A new `.github/workflows/ci.yml` runs `ruff` + `mypy --strict` + `pytest` + `vitest` on every change
so the gates are enforced continuously, not just at milestone end.

---

## Final end-to-end test (covers all requirements together)

`e2e/test_full_federation.py` (+ `e2e/compose/` per-division stacks). Stands up **three divisions
A, B, C** as **separate docker-compose stacks on isolated networks** (simulating different clouds) plus
the discovery service. Each `SC` maps to an executable, asserting step:

| Scenario | e2e assertion |
|---|---|
| SC-1 onboard new division | Stand up C from manifest, no source edits; C registers + is discoverable. |
| SC-2 provision users | Create carol(member)/dave(owner) in a division; carol logs in & queries; dave gets approvals; **neither authenticates to another division**. |
| SC-3 local authorized answer | Immediate governed answer; no approval; audit recorded. |
| SC-4 local needs-approval → granted → **offline** | alice asks bob's data; **close browser**; bob approves later; on alice's **next login** the answer (regenerated server-side) is waiting + out-of-band notification; **no 1h cap**. |
| SC-5 denied → declined offline | Same but bob denies; alice sees "declined" (+reason) on next login. |
| SC-6 cross-division discovery, user authorized in B | alice (A) asks; A **discovers** B via the service (not hardcoded); alice's **verifiable identity validated by B**; B finds her authorized → **immediate answer, no approval**; monitor shows the exchange; both agent identities verified. |
| SC-7 cross-division needs-approval → **offline** | Like SC-6 but not pre-authorized; B's owner approves; alice offline; outcome reaches her **account in A** on next login (FR-6.6), cross-machine. |
| SC-8 expiry & revocation | Approved access expires/revoked; re-ask **re-enters approval**, no stale reuse. |
| SC-9 governance stop | Kill-switch / trust / policy / DLP trips mid cross-division request → fail closed + safe message + audited. |
| SC-10 out-of-scope query | Chit-chat answered locally, no cross-division call, no data exposure. |
| SC-11 audit review | Division admin reconstructs "who accessed bob's data, who approved" — complete, division-scoped, tamper-evident. |
| SC-12 isolation under failure | **Kill division B's stack**; A keeps serving local queries; only B-dependent cross-division requests degrade with a clear message; **assert A cannot read B's store directly** and no A data exposed. |
| Multi-party (FR-3.5) | A discovers across **both** B and C (N≥2 not fixed; multi-hop). |

---

## Verification (how to run)

```
# Infra per division (e2e): separate stacks
docker compose -f e2e/compose/division-a.yml up -d   # repeat for b, c + discovery

# Unit + integration (every requirement)
agt-federated-rag> python -m pytest

# Lint + types (code-quality gate)
ruff check agt-federated-rag/ ; mypy --strict agt-federated-rag/

# Adversarial probes (security gate)
python redteam/run_probes.py ; python redteam/run_probes_r2.py   # + new per-milestone probes

# UI
cd ui ; npm test ; npm run build

# Full end-to-end across 3 divisions (the headline)
python -m pytest e2e/test_full_federation.py
```

A change is "done" only when: its milestone tests pass, the 3 review-gate agents report no
unresolved VULNERABLE/blocker findings, CI (ruff+mypy+pytest+vitest) is green, and — at the end —
`e2e/test_full_federation.py` passes with all SC steps asserting, including browser-closed offline
delivery cross-division and the kill-B isolation proof.

## Critical files
- `agt-federated-rag/api/main.py` — `/a2a/query` user-assertion validation (M2); new `/tasks/{id}/result`, `/inbox`, `/access/revoke`, `/audit` (M4/M5/M8).
- `agt-federated-rag/mesh/agent_identity.py` — multi-peer DID resolution refactor + rotation (M3/M7).
- `agt-federated-rag/mesh/peer_client.py` + new `mesh/discovery.py` + new `discovery/` service — discovery & negotiated delegation (M2/M3).
- `agt-federated-rag/auth/token_validator.py` — trusted-issuer set + assertion validation (M2).
- `agt-federated-rag/auth/openfga.py` — grant expiry + `revoke_viewer` + audit emit (M5/M8).
- `agt-federated-rag/workflow/activities.py` (+ `workflow/approval.py`) — durable offline delivery, regenerate-at-delivery (M4).
- `agt-federated-rag/config.py` + new `scripts/onboard_division.py` + `infra/division-stack.template.yml` — tenancy, onboarding/IaC, trusted-peer/residency/transport config (M0/M6/M7).
- new `audit/store.py` (M8); new `e2e/` + `.github/workflows/ci.yml`; `ui/src/{LoginForm,MonitorPanel,ChatArea}.tsx` (M1/M3/M4).
