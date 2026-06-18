# End-to-end federation suite (`e2e/`)

The headline end-to-end proof (the executed plan's *Final end-to-end test*, archived at
`docs/archive/IMPLEMENTATION_PLAN.md`):
maps every product scenario **SC-1 … SC-12** to a named, asserting test against
**≥3 live divisions** (alpha = A, beta = B, gamma = C) plus the discovery service —
including the two showpieces:

- **Browser-closed offline delivery, cross-division** (SC-4 / SC-5 / SC-7)
- **Kill-B isolation** (SC-12)

It drives the **real governed pipeline** through the agents' HTTP surface (no mocks):
real Keycloak access tokens, real `/query` SSE, real cross-division `/a2a` delegation,
real Temporal approvals, real OpenFGA re-authorization, real tamper-evident audit.

## SC → test mapping

| Scenario | Test function | Headline assertion |
|---|---|---|
| SC-1 onboard new division | `test_sc01_onboard_new_division_isolated_and_discoverable` | gamma live from manifest (no source edits), own DID, **discoverable** via broker |
| SC-2 provision users | `test_sc02_users_scoped_to_their_division` | member queries; owner has inbox; **alpha token rejected by beta** (FR-2.4) |
| SC-3 local authorized | `test_sc03_local_authorized_answer_no_approval` | immediate answer, **no approval** |
| SC-4 needs-approval → granted → **offline** | `test_sc04_local_needs_approval_granted_offline_delivery` | approval opened → owner approves → **fresh-context** poll gets regenerated answer |
| SC-5 denied → declined **offline** | `test_sc05_local_denied_declined_message_offline` | owner denies → fresh-context poll gets **declined, never data** |
| SC-6 cross-division discovery, **authorized** | `test_sc06_cross_division_discovery_authorized_immediate` | A **discovers** B (not hardcoded), verifiable identity validated by B → **immediate, no approval**, observable remote flow |
| SC-7 cross-division needs-approval → **offline** | `test_sc07_cross_division_needs_approval_offline_delivery` | bob@**B** approves → outcome reaches alice in **A** on next login (FR-6.6) |
| SC-8 expiry & revocation | `test_sc08_revocation_reenters_approval_no_stale_reuse` | owner revokes → re-ask **re-enters approval**, no stale reuse |
| SC-9 governance stop | `test_sc09_governance_stop_fail_closed_and_audited` | kill-switch → **fail closed (503)**, no leak, **audited + chain-verified** |
| SC-10 out-of-scope query | `test_sc10_out_of_scope_query_answered_locally` | chit-chat **local only**, no peer call, no data |
| SC-11 audit review | `test_sc11_audit_review_division_scoped_tamper_evident` | admin export **verified + division-scoped**; non-admin **403** |
| SC-12 isolation under failure | `test_sc12_kill_b_isolation_a_keeps_serving` | **B down** → A still serves local; B-dependent degrades; **A can't read B's store directly** |
| Multi-party (FR-3.5) | `test_multiparty_discovery_across_b_and_c` | A discovers **both** B and C (N≥2, not one fixed peer) |
| FR-6.4 forward probe | `test_inbox_next_login_retrieval_endpoint_exists` | `GET /inbox` — **xfail** (not built; records the gap) |

## The skip-guard (how it stays honest)

Every SC step is gated **twice**, exactly like `tests/test_isolation.py`:

1. **Opt-in** — `RUN_E2E=1` must be set. Without it the suite skips, so the hermetic
   unit suite never spends minutes probing docker stacks that aren't there.
2. **Reachability probe** — `e2e/conftest.py` loads each division from the artifacts the
   onboarder wrote (`infra/generated/<id>/{div-<id>.env, secrets.json, did.json}`),
   derives its ports with the **same** `scripts.onboard_division.derive_ports` the IaC
   uses, and probes each agent (`/health` must report the matching division id) and
   OpenFGA (`/healthz` = `SERVING`). If any required division isn't up, the suite
   **skips with a clear reason** — it never fails for a missing stack.

The full assertion logic lives **behind** the guard, so the moment the 3 stacks exist
the steps actually run and assert. No SC step is a placeholder `pass`.

Loopback is addressed as `127.0.0.1` (not `localhost`) for the same reason
`test_isolation.py` documents: on Windows `localhost` resolves to `::1` first, where
WSL2 mirrored networking can squat IPv6 loopback and shadow the real service.

## Bring up 3 divisions and run it

From the **repo root**, with the project venv (`.venv\Scripts\python.exe`) and
`NVIDIA_API_KEY` in `./.env`:

```powershell
# 1. Onboard the three divisions (each = its own isolated docker-compose stack).
.venv\Scripts\python.exe scripts\onboard_division.py infra\divisions\alpha.yml
.venv\Scripts\python.exe scripts\onboard_division.py infra\divisions\beta.yml
.venv\Scripts\python.exe scripts\onboard_division.py infra\divisions\gamma.yml

# 2. Federate them (peer DID/JWK trust map, trusted issuers, cross_grants).
.venv\Scripts\python.exe scripts\federate_divisions.py

# 3. Start each division's agent + worker (reads infra/divisions/*.yml).
.\scripts\clusters.ps1 start all

# 4. Start the discovery broker (control-plane only). Each agent registers itself.
$env:RAG_ENV_FILE = ".env.alpha"; $env:DISCOVERY_PORT = "8600"
.venv\Scripts\python.exe -m discovery.service   # in agt-federated-rag/

# 5. Run the e2e suite (from the repo root).
$env:RUN_E2E = "1"
.venv\Scripts\python.exe -m pytest e2e -q
```

Bash equivalent for step 5 (from repo root):

```bash
RUN_E2E=1 .venv/Scripts/python.exe -m pytest e2e -q
```

### Without live stacks

```
.venv\Scripts\python.exe -m pytest e2e -q
```

collects cleanly and **SKIPS every SC step** with a reason (opt-in off / stack not
reachable) — never a failure. This is the expected result in CI and on any machine
that doesn't have the three division stacks running.

## Honesty notes (what still needs live stacks / what isn't built)

- **Everything asserting actually needs the 3 stacks.** This environment has no live
  divisions, so the suite only proves it *collects and skips cleanly* here. The real
  SC assertions execute only once alpha/beta/gamma + the broker are up (the steps above).
- **`GET /inbox` (FR-6.4) is not built.** Offline next-login retrieval is asserted
  through the **built** path — `GET /tasks/{id}/result`, which regenerates the answer
  server-side at delivery (D-6). The "browser closed" property is asserted structurally:
  the outcome is reconstructed entirely from durable division state on a **fresh token /
  no carried client state**. A dedicated `GET /inbox` probe is included as **xfail** so
  the gap is recorded without a false green; it flips to a real pass when `/inbox` ships.
- **Cross-division identity is currently agent-vouched, not JWKS-verified** (FR-3.6,
  PROJECT_STATUS M2). SC-6/SC-7 assert the *behavioural* contract (B re-authorizes the
  propagated identity against its own OpenFGA; authorized → immediate, unauthorized →
  approval). They do not assert the cryptographic strength of the assertion — that
  hardening is tracked separately.
- **Discovery wiring** (SC-6 expecting a `remote`/`peer` flow from `/query`) depends on
  the agent actually calling the discovery client during delegation. PROJECT_STATUS notes
  the broker exists but the agent-side wiring is partial; if delegation is still on the
  configured peer, SC-6's discovery *registration* assertion still holds, and the flow
  assertion exercises whatever delegation path is wired.
