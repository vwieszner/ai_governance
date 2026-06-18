# M0 Production-Readiness Review

**Scope:** `git diff 72585ee..HEAD` — `scripts/onboard_division.py`, `infra/division-stack.template.yml`,
`scripts/clusters.ps1`, and the `division_id` threading in `agt-federated-rag/{config.py, mesh/peer_client.py,
auth/openfga.py, api/main.py}`.

**Verdict:** M0 delivers the tenancy threading and a config-driven physical-stack generator that works on a
clean first run. It is **not yet operationally safe** for a real (product, not demo) deployment: a re-run or
any partial failure leaves a broken, unrecoverable division, and the in-flight approval workflows are stored
non-durably. Three blockers below; the rest are must-fix or nice-to-have hardening.

Reviewer constraint: no backend source edited, no infra restarted. Findings are from static reading of the
diff plus container-runtime semantics (Postgres init, Compose project namespacing, Temporal `start-dev`).

---

## BLOCKERS (must fix before this is a deployable onboarding tool)

### B-1. Onboarding is non-idempotent and a re-run produces a permanently broken division

This is the headline operational hazard. Re-running `onboard_division.py <same manifest>` does NOT converge —
it breaks the division, and the break is not recoverable with the tooling provided.

Two independent, verifiable causes (the second is the one that actually bites, and it holds regardless of how
Compose decides to recreate vs reuse containers):

1. **New secrets every run.** `make_division_secrets()` (`onboard_division.py:225`) mints fresh
   `postgres_password`, `openfga_api_token`, `keycloak_admin_password`, etc. on every invocation. Nothing is
   persisted-and-reused.

2. **Postgres ignores the new password on an existing volume — the killer.** The stack volumes are
   project-namespaced and durable (good — see B-2), so on a second run `div-postgres-data` already exists.
   The `postgres:16-alpine` entrypoint only runs `initdb` (and applies `POSTGRES_PASSWORD`) when the data
   directory is **empty**. On a re-run the volume is non-empty, so Postgres keeps the **old** password while
   `openfga-migrate` / `openfga` are handed the **new** `OPENFGA_DATASTORE_URI` password
   (`division-stack.template.yml:45,57`). OpenFGA can no longer authenticate to its datastore → never goes
   healthy → `provision()`'s `_wait(... OpenFGA ...)` (`onboard_division.py:297`) loops for ~180s and raises
   `RuntimeError`. The division is now down with a credential mismatch on its own datastore.

3. **Unconditional new store, even when reachable.** Independently, `provision()` POSTs a brand-new OpenFGA
   store on every run (`onboard_division.py:302`) with no "does this division already have a store?" check, and
   re-creates the Keycloak realm/clients. So even in the (theoretical) case where auth lined up, you'd get a
   second store while the running agent still points at the first via its persisted `.env.<id>`.

> Note on the originally-suspected mechanism (compose reuses the old container with the old preshared token):
> that one does NOT reliably hold — `docker compose up -d` with a changed `--env-file` will typically
> *recreate* the openfga container because its config hash changed, in which case the new token matches on both
> ends. Don't anchor the finding there. **The Postgres-init fact above is the durable, infra-free proof.**

**Fix (idempotent onboarding):**
- Persist per-division secrets to `infra/generated/<id>/secrets.env` on first run (owner-only, like the other
  secret files) and **reuse them** if the file exists. New secrets only on a fresh/forced onboard.
- Make store creation reuse-if-present: look up the division's existing store (by `name=div-<id>`) / the
  `OPENFGA_STORE_ID` recorded in `.env.<id>` and skip the POST if it resolves; only create when absent.
- Add a `--force` flag that explicitly tears down + re-provisions from scratch.

### B-2. No teardown/offboard command exists — so "recover by re-provisioning" is not actually possible

Durability of the stack volumes is good and confirmed: each division runs under its own Compose project
(`compose_up` passes `-p agt-div-<id>`), and the template's top-level named volumes
(`div-postgres-data`, `div-keycloak-data`, `div-qdrant-data`, `div-redis-data`) are therefore project-prefixed
(`agt-div-<id>_div-postgres-data`), so divisions don't share state and state survives `restart: unless-stopped`
and host reboot.

The flip side: there is **no command anywhere** to tear a division down. `clusters.ps1 stop` only kills the
agent api/worker **processes** (`Stop-Port` / `Stop-Worker`) — it never runs `docker compose ... down`.
A repo-wide search for `compose down` / `down -v` / `offboard` / `teardown` returns nothing. Consequently:

- The B-1 idempotency fix that says "require explicit teardown" presupposes tooling that does not exist.
- After any failed/partial onboard, an operator has no supported way to get back to a clean slate except
  hand-running `docker compose -p agt-div-<id> down -v` and manually deleting `infra/generated/<id>/`,
  `agt-federated-rag/.env.<id>`, and `agent_identity_<id>.json`.

**Fix:** add an `offboard`/`down` path (e.g. `onboard_division.py --teardown <manifest>` or
`clusters.ps1 offboard <id>`) that runs `docker compose -p agt-div-<id> down -v` and removes the generated
artifacts. This is also the precondition for `--force` in B-1.

### B-3. Temporal state is non-durable — in-flight approval workflows are lost on restart

The template's `temporal` service (`division-stack.template.yml:74-81`) runs `server start-dev` with **no
volume and no `--db-filename`**. `temporal server start-dev` defaults to an **in-memory** datastore, so all
Temporal state is lost whenever the container restarts — on a crash (`restart: unless-stopped`), a host reboot,
or a `docker compose restart`.

Temporal holds this product's **in-flight human-approval workflows** — the headline offline-approval scenario
("approve/deny with the browser fully closed → outcome on next login," PRD/D-6). Losing those on a restart is a
real durability gap for the product's defining feature, not a dev nicety. Postgres/Keycloak/Qdrant/Redis were
all given named volumes; Temporal was the one stateful service left out.

**Fix:** give Temporal a named volume and point its dev store into it, e.g.
`command: ["server","start-dev","--ip","0.0.0.0","--log-level","warn","--db-filename","/data/temporal.db"]`
with `volumes: [div-temporal-data:/data]` and a matching top-level `div-temporal-data:` entry. (Longer term, a
real Temporal+Postgres deployment is M-later; the dev-stack just needs to not silently drop approvals.)

### Partial-failure behavior (rolls up into B-1/B-2)

`onboard()` (`onboard_division.py:492`) has no try/except and no rollback. `provision()` writes the secret-
bearing `.env.<id>` **before** ingest+seed (`onboard_division.py:337`, then `_run_division_ingest` /
`_seed_division_tuples` at 345-347). So a failure in ingest (NVIDIA outage, bad docs) or seeding leaves a
half-provisioned division: containers up, `.env.<id>` written, store created, but no chunks / no tuples — and
re-running hits the B-1 wall. **Fail-closed is satisfied for the data path** (per-node `_enforce` default-deny +
OpenFGA per-chunk ReBAC are unchanged by this diff), but **onboarding itself is not fail-safe**: it can leave
partial state that only manual cleanup can clear. The fix is the B-1 (idempotent reuse) + B-2 (teardown) pair.

---

## MUST-FIX (before multi-division operation)

### M-1. `clusters.ps1` silently tolerates duplicate/malformed manifests → port collisions

Discovery (`clusters.ps1:36-46`) builds `$CLUSTERS` keyed by `division_id` with no check that two manifests
don't share a `port_base` (or a `division_id`). Two manifests with the same `port_base` would bind the same
ports and the second division would fail to start with an opaque error; a duplicate `division_id` silently
overwrites the earlier hashtable entry. Also, a manifest missing `division_id` or `port_base` is silently
dropped by the `if ($id -and $base)` guard with no warning — an operator gets "division not found" with no clue
why. `onboard_division.py:load_manifest` validates a single manifest but nothing validates the **set** for
uniqueness.

**Fix:** in discovery, detect duplicate `division_id` and duplicate `port_base` across manifests and fail loud;
warn on skipped/malformed manifests.

### M-2. `provision()` declares "onboarded" without waiting for Temporal or Redis health

`provision()` health-gates OpenFGA, Keycloak, and Qdrant (`onboard_division.py:297-299`) but **not** Temporal
or Redis. The agent the operator launches next (`clusters.ps1 start <id>`) connects to both
(`TEMPORAL_ADDRESS`, `REDIS_URL`). On a cold host where Temporal/Redis are slower to come up than the three
gated services, onboarding prints "division onboarded" while the agent's first start can still fail to reach
them. Add `_wait` probes for Temporal (gRPC/UI port) and Redis before declaring done.

---

## OBSERVABILITY (item 4) — groundwork delivered, correctly scoped

`division_id` IS threaded into the structured logs that M0 claims:
- `auth/openfga.py:163` — every `openfga.check` event carries `division_id=settings.division_id` (+ `agt_audit=True`).
- `api/main.py` `a2a_query_received` — carries both `source_division` (from the signed envelope) and the local
  `division_id`, so a cross-division call is attributable on the receiving side.
- `mesh/peer_client.py:169` — `source_division` is in the **signed** A2A payload, so the attribution is
  authenticated, not spoofable post-hoc.

This is enough to attribute OpenFGA decisions and inbound federation calls to a division. **Frame it as FR-8
groundwork, not FR-8 done:** per the plan's D-7, real tamper-evident attribution is the durable hash-chained
`audit/store.py`, which is a later milestone — `structlog agt_audit=True` is explicitly NOT the FR-8 store. M0
only claims the threading, and the threading is present and signed. (Minor completeness gap: the top-level
`/query` request log path was not shown to carry `division_id`; add it for symmetry with `/a2a/query`.)

---

## RESOURCE BOUNDS / SCALING (item 5) — context, not a defect

Each division is a full 7-container stack (postgres, openfga-migrate, openfga, temporal, keycloak, qdrant,
redis) including a **Keycloak JVM** per division. The practical ceiling on a single dev host is a handful of
divisions (Keycloak + Temporal JVMs dominate RAM); this is acceptable because the intended production topology
is **per-cloud** (D-3: each division is its own stack/network, deployed separately), and every published port
binds `127.0.0.1` so nothing is network-reachable in dev. No change required for M0 — flagging the ceiling so
the ≥3-division e2e is sized against host RAM, and so reviewers don't read "N divisions on one laptop" as the
deployment model.

---

## NICE-TO-HAVE

- **N-1.** `_wait` retries any `<500` as healthy. Keycloak returns 404 on `/realms/master` before the realm
  subsystem is fully up in some boots; the current `<500` check would treat that 404 as healthy and a
  subsequent admin call could 404. Low risk (the admin token grant would then fail loudly), but a stricter
  per-service readiness check (e.g. `/health/ready` for Keycloak via `KC_HEALTH_ENABLED`, already set) is
  sturdier.
- **N-2.** `onboard_division.py:344` ingests only when `docs_dir` resolves under `AGT/`; a typo'd `docs_dir`
  silently produces a division with **zero chunks** and no warning (it skips ingest + seed). Warn when
  `docs_dir` is set but does not resolve.
- **N-3.** The seed flow scrolls Qdrant with `limit: 256` (`onboard_division.py:467`) with no pagination — a
  larger corpus would silently seed only the first page. Fine for the current fixture corpus; note for scale.
- **N-4.** `SEED_USER_PASSWORD` defaults to a hardcoded literal (`onboard_division.py:46`); fine for the seeded
  demo users, but document that these are demo principals, not real accounts.

---

## Summary table

| ID  | Severity     | Finding |
|-----|--------------|---------|
| B-1 | **Blocker**  | Onboarding non-idempotent; re-run breaks the division (Postgres keeps old password vs new secret; new store every run). |
| B-2 | **Blocker**  | No teardown/offboard command — broken/partial divisions are unrecoverable with provided tooling. |
| B-3 | **Blocker**  | Temporal `start-dev` has no volume → in-flight approval workflows lost on restart (the product's headline feature). |
| M-1 | Must-fix     | `clusters.ps1` doesn't detect duplicate `port_base`/`division_id` or warn on malformed manifests. |
| M-2 | Must-fix     | `provision()` doesn't health-gate Temporal/Redis before declaring "onboarded". |
| —   | Info         | Observability: `division_id` threaded correctly; FR-8 groundwork (not the durable audit store, by design). |
| —   | Info         | Scaling: 7 containers/division incl Keycloak JVM; per-cloud deploy is the real model (D-3). |
| N-1..4 | Nice-to-have | `_wait` `<500` laxity; silent zero-doc division on bad `docs_dir`; unpaginated seed scroll; hardcoded seed password. |
