# Security Audit — Federated RAG System (AGT / AgentMesh)

**Date:** 2026-06-01 (original) · trimmed to the AGT product line 2026-06-05
**Auditor:** Automated security review (read-only; no servers run)
**Scope:** JWT/auth, AGT (DID) cross-cluster federation, OpenFGA authorization, approval workflow,
secrets handling, CORS, input validation, Docker/infra.
**Method:** Static read of source + configuration. Git tracking state verified via `git ls-files` /
`git status` (working-tree state; full history not scanned — see Finding S-1).

> **Note on scope.** This audit originally covered two parallel solutions (A2A + AGT). The A2A
> (`federated-rag`) solution now lives in a separate repository; this report has been trimmed to the
> AGT (`agt-federated-rag`) product line that remains here. Findings that were purely A2A-specific
> (RFC 8693 token-exchange, the OAuth `client_id` callback allowlist) have been removed; shared-infra
> findings are retained.

## Executive Summary

This is a genuinely well-secured codebase. The core security model — deny-by-default per-chunk
authorization, cryptographic **DID** verification of cross-cluster messages with the public key
taken from trusted config, HMAC-signed and time-bound approval links, and JWT validation that
verifies signature/exp/iss — is sound, with per-action policy enforcement layered on top.

The findings below are dominated by **deployment-hardening items that must be fixed before any
production deployment**, plus a **secrets-hygiene residual** (a live NVIDIA key in the gitignored
`ui/.env.prod`) and a couple of **bounded residual Low items** (approval-link replay).

| # | Severity | Area | Location | Issue |
|---|----------|------|----------|-------|
| S-1 | **Medium** | Secrets | `ui/.env.prod` | A live NVIDIA API key sits in `ui/.env.prod`. The file is gitignored (not committed), but the key is real and should be **rotated** and sourced from a secret manager / build-time injection. (The earlier hardcoded-secret literals in `setup_all.py` / `bootstrap_keycloak.py` are resolved — those scripts were removed; `setup_agt.py` sources every secret from the gitignored root `.env`.) |
| I-1 | **Medium** | Docker/infra | `docker-compose.yml` | Default-ish credentials and dev servers (Keycloak admin, Postgres, OpenFGA, Temporal `start-dev`). Now generated into a gitignored `.env` by `init_secrets.py`, but the Temporal dev server + exposed admin surfaces are development defaults; must be fixed before prod. |
| I-2 | **Medium** | Infra | `config.py` (`host`), k8s manifests | App binds broadly and OpenFGA is called over plaintext HTTP. Development default; prod needs network policy + mTLS/TLS. |
| R-1 | **Low → REMEDIATED** | AGT replay | `agt-federated-rag/mesh/agent_identity.py` | ~~AgentMesh signed envelope had no nonce/timestamp; an identical signed message re-verified (replay).~~ Fixed: signed `ts`+`nonce`, freshness window + bounded seen-nonce cache (fail-closed). See §2. |
| AUD-1 | **Low** (intentional test-enablement) | Audience / IdP | Keycloak `rag-ui` client audience mappers | The public `rag-ui` token carries `aud` for both AGT backends (`agent-agt-a`, `agent-agt-b`), so one UI token authenticates to both clusters. **BOUNDED — no privilege gain:** every data/action path re-authorizes on `sub` (OpenFGA) or DID (peer paths). See §2. |
| R-2 | **Low** | Approval replay | `api/main.py` `/approve` | Approval deep-link can be replayed until its signed `exp`; no single-use nonce. Bounded by short expiry. |
| O-1 | **Low** | Rate limit | `api/main.py` `_check_rate_limit` | Per-subject rate limiter fails **open** on Redis error. Intentional availability trade-off; document it. |
| Q-1 | **Info** | Approval audit | `api/main.py` `/approve` | Approver identity recorded as a constant deep-link marker (no authenticated human attribution). |
| Q-2 | **Info** | Approval HMAC | `workflow/activities.py` | Approval `reason` query param is not covered by the HMAC. Tamperable but capped and non-authorizing. |

### Controls verified as correctly implemented (no action needed)

- **JWT validation** — signature, `exp`, `iat`, `iss` verified by `jose`; algorithm allow-list from
  config; alg/kid key-confusion guard; `alg=none` and RS/HS confusion not possible.
- **DID message auth** — Ed25519 signature verified against the peer public key from **trusted
  config**, never the message body; signer DID must equal configured peer DID; registry trust gate +
  AGT policy gate layered on top.
- **OpenFGA** — deny-by-default; a user with no `viewer`/`editor`/`owner` tuple gets `DENIED` and
  denied-chunk text is pruned from state.
- **CORS** — non-wildcard origin allow-list, `allow_credentials=False`, methods/headers restricted.
- **Task ownership** — task reads enforce `owner_id == caller`, returning 404 otherwise.
- **Input/DoS** — query length cap, pure-ASGI body-size limit (SSE-safe), rate limiting, free-text
  truncation, ID sanitization, docs disabled by default.
- **Per-action policy** — every LangGraph node calls `_enforce(action)` against the AgentMesh
  `PolicyEvaluator` before doing work (default-deny + explicit allow-list).

---

## 1. JWT / Authentication

**File:** `agt-federated-rag/auth/token_validator.py`

**Assessment: correctly implemented.** No findings.

Signature / `exp` / `iat` / `iss` are verified by `jose` with `options={"verify_exp": True,
"verify_iat": True}`; JWKS is fetched from the configured `oidc_jwks_uri` (not from the token), with
a double-checked-locking cache and TTL. `alg` is constrained to the configured allow-list (live
`.env` = `RS256` only), so `alg=none` is impossible; `_find_key` rejects a key whose declared `alg`
disagrees with the header (key-confusion guard across a kid collision).

---

## 2. AGT / Cross-Cluster Federation (DID)

**Files:** `agt-federated-rag/mesh/agent_identity.py`, `mesh/peer_client.py`, `/a2a/query` +
`/tasks/{id}/callback` in `api/main.py`, `workflow/activities.py`.

### DID signature verification — correctly implemented
`task_callback` / `/a2a/query` call `verify_signed_message()`, which:
1. Resolves the peer public key from **`settings.peer_agent_public_jwk` (trusted config), never from
   the message body** — the crux of the fix, done correctly.
2. Requires the configured-key DID to equal the envelope `sender_did`, and (if set) to equal
   `settings.peer_agent_did`.
3. Verifies the Ed25519 signature over canonical bytes (excluding the `_agentmesh` envelope), failing
   closed on any error.

The endpoint then layers a registry trust-score gate (`verify_peer_identity`), a configured-peer
match, and an AGT policy gate (`_enforce("peer.receive_callback", …)` with the **real** verification
results, not hardcoded optimism). Defense-in-depth done right. The outbound callback URL is validated
against the configured peer origin (`scheme`+`netloc`) — a genuine SSRF guard.

### Replay protection — R-1 (Low) — REMEDIATED
`sign_outbound_message` adds a fresh `ts` (unix seconds) and `nonce` (uuid4) to the body **before**
signing — so both are covered by the Ed25519 signature — and `verify_signed_message` calls
`_check_freshness_and_nonce`, which rejects any message outside a ±300s freshness window or whose
`(sender_did, nonce)` has already been seen, with a bounded seen-cache that fails closed when full.
Applies to both directions (peer_client outbound + `/a2a/query` / callback inbound).

### Audience — AUD-1 (Low; intentional test-enablement)
The public `rag-ui` token carries `aud = [agent-agt-a, agent-agt-b, account]` so one UI token
authenticates to both backends. **Impact — BOUNDED, no privilege gain:** authenticating to a backend
is necessary but never sufficient. Data reads (`POST /query`) re-authorize on the JWT **`sub`** via
OpenFGA `batch_decide` — no tuple, no read, regardless of `aud`. The AGT peer paths (`POST
/a2a/query`, `POST /tasks/{id}/callback`) are authenticated by the **Ed25519 DID signature** and
honor **no user bearer token at all**. So the shared audience is *authenticate-everywhere,
authorize-nowhere-extra*. **Recommendation (prod, IdP config):** scope `rag-ui` tokens per cluster
(per-cluster public clients, or RFC 8693 token-exchange) so a session for cluster A does not carry
cluster B's audience; to revert this dev-time enablement, delete the `aud-agent-agt-a` /
`aud-agent-agt-b` protocol-mappers from the `rag-ui` Keycloak client.

---

## 3. OpenFGA Authorization

**Files:** `agt-federated-rag/auth/openfga.py`, `agt-federated-rag/agent/nodes.py` (`check_auth`).

**Assessment: deny-by-default, correctly implemented.** No findings.

- `decide()` returns `ALLOWED` only when `check(viewer)` is true, `NEEDS_APPROVAL` only for an
  explicit `pending_approval` tuple, and `DENIED` otherwise. A user with no tuple gets `DENIED`.
- `check_auth` serves only `ALLOWED` chunks; `generate_answer` filters to allowed chunk ids again,
  and denied-chunk **text** is pruned from `AgentState` so unauthorized content never leaks into
  traces/spans.
- The authorization model (write-once at startup, `setup_agt.py`) makes `viewer`/`editor` derive from
  `owner` — the intended ReBAC hierarchy.

---

## 4. Approval Workflow

**Files:** `agt-federated-rag/workflow/approval.py`, `workflow/activities.py`, `/approve/{request_id}`
in `api/main.py`.

**Assessment: strong.** Minor/info residuals.

- **HMAC + expiry (correct):** deep-links carry `token = HMAC_SHA256(secret,
  "{request_id}:{decision}:{exp}")`; the expiry is **part of the signed message**, so a leaked link
  cannot be replayed indefinitely; `/approve` rejects `exp < now` before any work; verification uses
  `hmac.compare_digest`; `request_id` enforced via `_validate_safe_id`.
- **R-2 (Low):** a valid approval URL is a bearer credential reusable until `exp` (24h default); no
  single-use nonce. Once consumed the workflow already has the decision, so a replay is largely a
  no-op. *Recommendation:* shorten the timeout and/or mark the `request_id` consumed (Redis) on first
  signal so the link is single-use.
- **Q-1 (Info):** `approver_id` is a constant deep-link marker — no authenticated human attribution.
  Production should gate `/approve` behind an authenticated session and record the real approver.
- **Q-2 (Info):** `reason` is outside the HMAC (tamperable, capped to 500 chars, display/audit only).

---

## 5. Secrets Handling — Finding S-1 (Medium)

**Files:** `ui/.env.prod`; `.gitignore`; `init_secrets.py`; `setup_agt.py`.

### Ground truth
- **`.env` files ARE gitignored and untracked** (`.gitignore` covers `.env`, `*.env`, `.env.*`,
  `ui/.env.prod`). Tracked config is clean — only `*.env.example` and k8s manifests are committed and
  those use **placeholders** (`nvapi-your-nvidia-nim-key`, `nvapi-xxxx`, `change-me`).
- **`setup_agt.py` sources every secret from the gitignored root `.env`** (created by
  `init_secrets.py` with `secrets.token_*`) — no secret literals in tracked source. (The earlier
  `setup_all.py` / `bootstrap_keycloak.py` hardcoded-secret finding is resolved: those scripts were
  removed when the A2A solution was extracted.)
- **Residual:** `ui/.env.prod` contains a real, billable NVIDIA API key. It is gitignored (not
  committed), but a real key on disk should be **rotated** and injected at build time / from a secret
  manager rather than living in a tracked-adjacent file.

### Recommendation
1. **Rotate** the NVIDIA API key in `ui/.env.prod`; inject it server-side at build time, not via a
   committed-adjacent file.
2. Keep all secrets sourced from the gitignored `.env` / a secret manager (already the pattern in
   `init_secrets.py` + `setup_agt.py`).
3. Before any publication, run a history secret-scan (`git log -p -S nvapi-`, gitleaks/trufflehog)
   and rotate regardless of local tracking state.

---

## 6. CORS

**Files:** `agt-federated-rag/api/main.py`, `config.py` (`cors_origins`).

**Assessment: correctly locked down.** No findings. `allow_origins` is an explicit allow-list (dev
default `http://localhost:5173`), **not** a wildcard; `allow_credentials=False`; methods/headers
restricted. *Recommendation (Info):* set `CORS_ORIGINS` to the real UI origin(s) in production.

---

## 7. Input Validation / Injection / DoS

**Files:** `agt-federated-rag/api/main.py`, `config.py`.

**Assessment: well covered.** No findings.

- **Query length** capped (4096) with 400 on exceed; empty/whitespace rejected.
- **Body size:** pure-ASGI `_LimitBodySizeMiddleware` enforces the max on both `Content-Length` and
  chunked paths **without buffering SSE responses**; 413 sent directly over ASGI.
- **Rate limiting:** per-subject fixed-window via Redis (60/min) before expensive retrieval/LLM work.
- **Injection surfaces:** `request_id`/`task_id` sanitized to `[a-zA-Z0-9-]`; X-Request-ID sanitized +
  length-capped (CRLF guard); approval URL params percent-encoded; free-text capped at 500 chars;
  callback payloads validated with Pydantic → 422 not 500.
- **Error hygiene:** internal/Temporal errors not leaked; `jose` error strings (which embed token
  material) deliberately not logged.

### O-1 (Low) — rate limiter fails open
`_check_rate_limit` allows the request on any Redis error (intentional availability-over-security
choice, documented in code). *Recommendation:* for production decide explicitly whether the expensive
LLM endpoint should fail closed (or degrade to a stricter in-process limiter) during a Redis outage.

---

## 8. Docker / Infrastructure — Findings I-1, I-2 (Medium, deployment-hardening)

**Files:** `docker-compose.yml`; k8s manifests; `config.py` server defaults.

**Development defaults** that **must be fixed before any production deployment:**

- **I-1 — credentials & exposed surfaces:** Keycloak/Postgres credentials are now generated into a
  gitignored `.env` by `init_secrets.py` (good), but the OpenFGA HTTP/gRPC/playground surfaces and the
  Temporal `start-dev` (in-memory) server are dev defaults. *Recommendation:* enable OpenFGA
  preshared-key/OIDC auth, disable the OpenFGA playground in prod, run a production Temporal cluster
  with TLS+auth, and restrict published ports behind network policy.
- **I-2 — plaintext transport & broad bind:** the app binds broadly and infra is reached over
  plaintext `http://`/`bolt://`. *Recommendation:* enforce mTLS (`STRICT`) in k8s, use TLS for
  Keycloak/OpenFGA, and constrain bind/exposure via NetworkPolicy.

---

## Appendix — Prior findings confirmed remediated

Earlier review findings are addressed in the current tree: cryptographic callback-signature
verification (key-from-config), approval-link expiry inside the HMAC, real (non-hardcoded) policy
context on the callback entry point, the AGT policy gate on the HTTP callback path, denied-chunk text
pruning, rate limiting, and the decision-channel audit field. (Verified by reading the source; this
audit did not execute the modules.)
