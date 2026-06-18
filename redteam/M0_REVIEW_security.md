# M0 Review — SECURITY perspective

**Scope:** `git diff 72585ee..HEAD` on `main` (M0: physical per-division tenancy
isolation + parameterized onboarding generator).
**Reviewer:** m0-security (review gate, IMPLEMENTATION_PLAN.md "Adversarial review gates").
**Method:** static read of the full diff + key callees (`mesh/agent_identity.py`,
`auth/token_validator.py`, `auth/openfga.py`), unit-test run, and **read-only live
probes** against the running `alpha` stack. Verdicts: DEFENDED / VULNERABLE / EXPECTED /
FINDING (bounded). Claims verified against code/runtime, not comments.

**Bottom line:** No VULNERABLE / critical / blocker findings. The 5 reviewed security
properties are real, not cosmetic. Three bounded FINDINGs (one operational footgun, one
predictable-seed-credential, one Windows file-mode) are non-blocking for M0 but should be
tracked into M7 (secrets management). M0 security gate: **PASS**.

---

## Evidence I reproduced (so claims aren't trusted from comments)

- `python -m pytest tests/test_tenancy.py tests/test_onboarding.py tests/test_isolation.py`
  → **10 passed, 1 skipped** (isolation skips cleanly when the 2 stacks aren't both up).
- `git check-ignore` + `git ls-files`: all secret-bearing paths
  (`infra/generated/`, `agt-federated-rag/.env.*`, `**/agent_identity_*.json`) are
  **gitignored and untracked**; `git status` shows **zero untracked files** even though
  `infra/generated/{alpha,beta}` exist on disk. Only `*.env.example` + `init_secrets.py`
  (pre-existing, outside diff) match secret-ish patterns in the tracked set.
- Generated secret value lengths: POSTGRES_PASSWORD 32 hex (`token_hex(16)`, 128-bit),
  OPENFGA_API_TOKEN 32 (`token_urlsafe(24)`, 192-bit), KEYCLOAK_ADMIN_PASSWORD 24
  (`token_urlsafe(18)`, 144-bit) — strong, per-division, no placeholders.
- **Per-division credential distinctness (live files):** alpha vs beta differ for
  `OPENFGA_API_TOKEN`, `POSTGRES_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD` — all `True`.
- **Live alpha OpenFGA preshared-auth (positive + negative control):**
  `GET /stores/{real_store_id}` correct token → **200**; wrong token → **401**;
  `GET /authorization-models` correct token → **200**; no token → 401;
  `GET /playground` → **404 (disabled)**; `/healthz` → 200.
  (Positive control matters: it proves auth *accepts the right key*, so the 401 on the
  wrong key is real isolation, not a server rejecting everything.)

**Not independently reproduced by me:** the full **2-stack cross-rejection** probe
(`beta` is currently down; restart is out of scope for this gate). I reviewed the
`test_isolation.py` design (sound) and rely on the team-lead's prior run that populated
`infra/generated/{alpha,beta}`. The verdict below leads with the architecture, which is
airtight regardless of beta being up; the probe + test corroborate.

---

## 1. Tenant isolation — can one division read another's store/data/secrets? — **DEFENDED**

**Architecture (the load-bearing argument):** each division is its own compose project
(`name: agt-div-${DIV_ID}`) → its own default network, its own `div-<id>-postgres` +
`div-<id>-openfga` containers, its own named volumes (`div-postgres-data` etc., namespaced
per project), its own preshared OpenFGA key, its own Keycloak realm host. A `store_id` on
alpha's OpenFGA server is **structurally meaningless** on beta's server — different process,
different Postgres, different network. There is no shared datastore whose loss crosses a
boundary (NFR-2).

**Corroboration:**
- `test_isolation::test_division_cannot_read_peer_store` asserts both halves: (store) beta
  cannot `check` alpha's store_id (`not (200 and allowed)`), and (credential) alpha's token
  is rejected by beta's server and vice-versa (`401/403`). Real cross-stack assertions, not
  a `division_id` label on shared infra.
- Live: alpha/beta `OPENFGA_API_TOKEN`s are **distinct**; alpha's running OpenFGA returns
  **401 to a wrong token, 200 to the correct one** — preshared auth genuinely enforced.

Verified, not cosmetic. The `division_id` field is *attribution*; the *isolation* is the
separate physical stacks + separate credentials.

## 2. Onboarding generator secret handling — **DEFENDED** (+ FINDING-1, FINDING-3)

- Per-division random secrets via `make_division_secrets()` (`secrets.token_hex/urlsafe`,
  128–192-bit) — NFR-4 satisfied; none shared across divisions (verified live).
- `_write_secret()` uses `os.open(O_CREAT|O_TRUNC, 0o600)` — mode applied atomically at
  creation (no write-then-chmod world-readable window). Used for the stack env, agent
  `.env.<id>`, `did.json`, and the Ed25519 private-key identity file.
- **No secret leakage in logs:** secrets appear only in HTTP request bodies/headers and in
  `_write_secret` file writes. Every `log()`/`print()` emits ids/ports/paths only. The one
  subprocess `print` (`_run_division_ingest` stdout/stderr on failure) cannot contain these
  secrets — the ingest child only receives `RAG_ENV_FILE` (a filename), not secret values.
- Nothing secret is committed: gitignore verified effective (`git status` clean despite
  on-disk generated dirs).

## 3. rag-ui audience mapper (`_kc_add_ui_audience`) — no AUD-1 reintroduction — **DEFENDED**

`_kc_add_ui_audience(c, kc, h, f"agent-{division_id}")` adds an `oidc-audience-mapper`
that injects **only this division's** agent client id into rag-ui access-token `aud`
(single-division audience; no cross-division mapper — the dual-audience mapper *was* AUD-1).

**Can a division-A token be accepted by division-B's agent? No — three independent gates:**
1. **Audience:** `auth/token_validator.validate_token` calls `jwt.decode(...,
   audience=settings.agent_client_id, ...)` (token_validator.py:219). A-token `aud =
   agent-alpha`; B's agent requires `agent-beta` → reject.
2. **Issuer:** same call enforces `issuer=settings.oidc_issuer` (token_validator.py:220).
   `OIDC_ISSUER` is per-division (`http://localhost:<div-kc-port>/realms/rag`) →
   different host:port per division → reject.
3. **Signature:** each division's Keycloak realm has its own signing keys; an A-token won't
   verify against B's JWKS.

`render_agent_env` confirms `AGENT_CLIENT_ID=agent-{division_id}` and a per-port
`OIDC_ISSUER`/`OIDC_JWKS_URI`. AUD-1 is not reintroduced.

## 4. `division_id` / `source_division` threading — forgeable? — **DEFENDED (with note)**

- Outbound (`peer_client.call_peer_agent`): `source_division = settings.division_id` is put
  in `payload` **before** `sign_outbound_message`, which signs `_canonical_bytes(signed)` =
  the whole body minus the `_agentmesh` envelope (agent_identity.py:119-126, 296). So
  `source_division` is **inside the Ed25519-signed bytes**.
- Inbound (`api/main.py` `a2a_query`): the signature is verified at **line 661** (fail-closed
  401) *before* `source_division` is read at **line 707**. A MITM cannot tamper the field
  without breaking the signature; `ts`+`nonce` are also signed (replay-protected).
- `test_tenancy::test_division_id_threaded_into_a2a_envelope` exercises the real
  `call_peer_agent` path and asserts the **signed** payload carries
  `source_division == settings.division_id`.

**Note (not a blocker; forward-looking for M3):** signing proves the field *came from a
trusted, DID-authenticated peer* — it does **not** cryptographically bind a DID to a
division, so a trusted peer populates its own `source_division` value. For M0 this is benign:
`source_division` is **audit-only**, `signer_did` (the cryptographic truth) is logged
alongside it, and there is a single configured peer. **If M3's multi-peer work ever feeds
`source_division` into an authorization decision (vs. audit), the DID→division binding must
be verified there.** Flagging so the gate surfaces it before that lands.

## 5. division-stack template — **DEFENDED** (start-dev TLS = EXPECTED for M0)

- **Every published port binds `127.0.0.1`** (loopback) — openfga/keycloak/temporal/
  qdrant/redis all `"127.0.0.1:${...}:..."`. Nothing network-reachable in dev.
- OpenFGA: `OPENFGA_AUTHN_METHOD: preshared` + `OPENFGA_AUTHN_PRESHARED_KEYS:
  ${OPENFGA_API_TOKEN:?...}` (required, no default), `OPENFGA_PLAYGROUND_ENABLED: "false"`
  (live: `/playground` → 404). Postgres/Keycloak admin creds use `${VAR:?set in division env}`
  — fail-closed if unset.
- **No secrets in the template** — only `${VARS}` resolved from the gitignored generated
  env file.
- Each compose project gets its **own default network**, giving real east-west isolation
  between divisions.
- **EXPECTED:** Keycloak + Temporal run `start-dev` (no TLS / dev mode), and the template
  header says the internet-facing surface gets mTLS in **M7**. Correct scoping for M0.

---

## Bounded FINDINGs (non-blocking for M0; track to M7 secrets/IaC)

**FINDING-1 — secret-rotation / idempotency footgun in `onboard()` (operational).**
`make_division_secrets()` mints **fresh** secrets on **every** `onboard()` call and
`render_*_env` rewrites both env files, but a **re-run does not re-key the already-running
containers** (OpenFGA keeps its original preshared key; Postgres keeps its password in the
volume). Confirmed live: `OPENFGA_API_TOKEN` in `infra/generated/alpha/div-alpha.env` no
longer matches `agt-federated-rag/.env.alpha`, and the stale stack-env token now **401s**
against the running container while the agent-env token returns 200. Impact: a second
onboard of an existing division silently desynchronizes credentials → confusing auth
failures, and the regenerated Postgres password is dead-on-arrival against the existing
volume. *Fix direction:* make onboarding idempotent — load existing per-division secrets
if present (don't regenerate), or refuse/`--rotate` explicitly. M7 (per-division secrets
management) is the natural home.

**FINDING-2 — predictable seed credential with real data grants (bounded by loopback).**
`SEED_USER_PASSWORD` defaults to the **hardcoded** `"Rag-User-2026!"` (overridable via
`RAG_SEED_PASSWORD`). This isn't an inert demo detail: the seeded `alice`/`bob` receive
**real OpenFGA grants** (alice `viewer` on `seed_viewer`; bob `owner` on `seed_approval`),
and `rag-ui` is provisioned `publicClient: true` + `directAccessGrantsEnabled: true`
(onboard_division.py:319-322) — so a password grant mints a **working access token** for
anyone who can reach the Keycloak port. Predictable creds + public direct-grant client +
real data grants = genuine data access in any **non-loopback** deployment. Contained today
only by the loopback bind (hence bounded). *Fix direction:* generate a random per-division
seed password (and surface it once), or gate seeding behind an explicit dev flag, in M1/M7.

**FINDING-3 — `0o600` is POSIX-only; generated secret files are world-readable on Windows.**
`_write_secret` documents this honestly, but on the Windows dev host the generated
`div-<id>.env`, `.env.<id>`, `did.json`, and the Ed25519 private-key file are `-rw-r--r--`
(NTFS ACLs govern; the mode arg is ignored). On a single-user dev box this is low-risk; a
Windows-hosted deployment would need explicit ACL hardening (`icacls`). Track to M7.

---

## DEFENDED summary

| # | Property | Verdict | Strongest evidence |
|---|----------|---------|--------------------|
| 1 | Cross-division store/data/secret read | DEFENDED | separate stacks + distinct creds (live) + `test_isolation` design |
| 2 | Onboarding secret handling / no log leak / no git leak | DEFENDED | `git status` clean; strong random; `_write_secret` atomic 0o600 |
| 3 | rag-ui audience scoped to local division (no AUD-1) | DEFENDED | `validate_token` aud+iss enforced (token_validator.py:219-220) + per-realm keys |
| 4 | `source_division` attribution unspoofable in transit | DEFENDED | signed before send (peer_client:169→171), verified before read (main.py:661→707) |
| 5 | Template loopback / preshared / playground-off / no secrets | DEFENDED | all binds `127.0.0.1`; `/playground`→404 live; `${VAR:?}` fail-closed |

No VULNERABLE / blocker findings. **M0 security gate: PASS** with 3 bounded FINDINGs routed to M1/M7.
