# Security Audit — Federated RAG System (`federated-rag` + `agt-federated-rag`)

**Date:** 2026-06-01
**Auditor:** Automated security review (read-only; no files modified except this report, no servers run)
**Scope:** JWT/auth, A2A cross-cluster delegation, OpenFGA authorization, approval workflow, secrets handling, CORS, input validation, Docker/infra.
**Method:** Static read of source + configuration. Git tracking state verified via `git ls-files` / `git status` (working-tree state; full history not scanned — see Finding S-1).

## Executive Summary

This is a genuinely well-secured codebase. It has been through multiple prior review rounds (tags `C-1`, `S-5`, `H-5`, `H-7`, `Finding #1…#8`, `MED-7`, etc.) and the overwhelming majority of those controls are correctly implemented and still hold. The core security model — deny-by-default per-chunk authorization, cryptographic DID verification of cross-cluster callbacks with the public key taken from trusted config, HMAC-signed and time-bound approval links, multi-audience JWT validation that still verifies signature/exp/iss — is sound.

The findings below are dominated by **deployment-hardening items that are fine for a local demo but must be fixed before any real deployment**, plus **one real secrets-hygiene issue** (live credentials hardcoded in setup scripts that are not protected by `.gitignore`) and a couple of **bounded residual Low items** (callback replay).

| # | Severity | Area | Location | Issue |
|---|----------|------|----------|-------|
| S-1 | **High** | Secrets | `setup_all.py:41,258,299`, `bootstrap_keycloak.py:26-27`, `ui/.env.prod:14`, `.gitignore` | Live NVIDIA API key, approval HMAC signing key, and agent client secrets hardcoded in source/setup files that are **not** covered by `.gitignore` (only `.env` and `ui/.env.demo` are). One `git add .` commits them. |
| I-1 | **Medium** | Docker/infra | `docker-compose.yml:25-26,56-57,89-90` | Default credentials (Keycloak `admin/admin`, Postgres `openfga/openfga`); OpenFGA HTTP API + playground and Temporal dev server exposed on host ports with no auth. Acceptable for local demo; must be fixed before prod. |
| I-2 | **Medium** | Infra | `config.py` (`host: 0.0.0.0`), k8s manifests | App binds `0.0.0.0` and OpenFGA is called over plaintext HTTP. Demo-acceptable; prod needs network policy + mTLS/TLS. |
| R-1 | **Low** → **REMEDIATED** (task #8) | A2A replay | `agt-federated-rag/mesh/agent_identity.py` (`sign_outbound_message` / `verify_signed_message` / `_check_freshness_and_nonce`) | ~~AgentMesh signed envelope has no nonce/timestamp; an identical signed callback re-verifies (replay).~~ Now fixed: signed `ts`+`nonce`, freshness window + bounded seen-nonce cache (fail-closed). See §2. |
| AUD-1 | **Low** (intentional test-enablement) | Audience isolation / IdP | Keycloak `rag-ui` client audience mappers (IdP config, not app code) | One `rag-ui` user token carries `aud = [all 4 backend client_ids]`, so it authenticates to all four backends of both solutions. **BOUNDED — no privilege gain:** every data/action path re-authorizes on `sub`/`azp`/DID, so authenticating ≠ being authorized (detail in §2). Intentional demo test-enablement; prod fix is IdP audience hygiene (per-cluster aud / RFC 8693 token-exchange). |
| R-2 | **Low** | Approval replay | `api/main.py` `/approve` (both clusters) | Approval deep-link can be replayed until its signed `exp`; no single-use nonce. Bounded by short expiry. |
| O-1 | **Low** | Rate limit | `api/main.py` `_check_rate_limit` (both) | Per-subject rate limiter fails **open** on Redis error. Intentional availability trade-off; document it. |
| Q-1 | **Info** | Approval audit | `api/main.py` `/approve` (both) | Approver identity recorded as constant `"approval-deeplink"` (no authenticated human attribution). Known/accepted (Finding #8). |
| Q-2 | **Info** | Approval HMAC | `workflow/activities.py:98-118` | Approval `reason` query param is not covered by the HMAC. Tamperable but capped to 500 chars and non-authorizing. |

### Controls verified as correctly implemented (no action needed)

- **JWT validation** — signature, `exp`, `iat`, `iss` all verified by `jose`; algorithm allow-list from config; alg/kid key-confusion guard (MED-7); `alg=none` and RS/HS confusion not possible.
- **Manual audience check** (`token_exchange.py`) — `verify_aud=False` is compensated by a **deny-by-default** manual allow-list check; this is correct (detail below), not a vulnerability.
- **A2A SSRF guards** — token-exchange target audience and A2A callback URL both validated against the configured peer origin (scheme + netloc).
- **DID callback auth** — Ed25519 signature verified against the peer public key from **trusted config**, never the message body; signer DID must equal configured peer DID; registry trust gate + AGT policy gate layered on top.
- **OpenFGA** — deny-by-default; a user with no `viewer`/`editor`/`owner` tuple gets `DENIED` and denied-chunk text is pruned from state.
- **CORS** — non-wildcard origin allow-list, `allow_credentials=False`, methods/headers restricted.
- **Task ownership** — `GET /tasks/{id}` enforces `owner_id == caller`, returns 404 otherwise.
- **Input/DoS** — query length cap, pure-ASGI body-size limit (SSE-safe), rate limiting, free-text truncation, ID sanitization, docs disabled by default.

---

## 1. JWT / Authentication

**Files:** `federated-rag/auth/token_exchange.py`, `agt-federated-rag/auth/token_validator.py`

**Assessment: correctly implemented.** No findings.

### Signature / exp / iat / iss — verified
Both validators call `jwt.decode()` with `issuer=settings.oidc_issuer` and rely on `jose`'s defaults, which verify signature, `exp`, and `iat`. `agt-federated-rag` additionally sets `options={"verify_exp": True, "verify_iat": True}` explicitly. JWKS is fetched from the configured `oidc_jwks_uri` (not from the token), with double-checked-locking cache and TTL.

### Manual audience check (`token_exchange.py:206-222`) — sound, NOT a vulnerability
The recent change to `options={"verify_aud": False}` is **immediately followed** by a manual, deny-by-default check:

```python
token_aud = claims.get("aud", [])
if isinstance(token_aud, str):
    token_aud = [token_aud]
if not any(a in valid_audiences for a in token_aud):
    raise JWTError(...)   # rejects any token whose aud matches none of the accepted values
```

This is correct and is actually *stricter* than `jose`'s single-string matcher. The reason for the bypass is legitimate: `jose`'s `audience=` argument cannot express "accept ANY of {client_id, agent_url}", which is required for delegated cross-cluster tokens. Signature/exp/iss remain fully verified by `jose`. A token with a wrong/empty audience is rejected. **Confirmed: this should not be flagged.**

### Algorithm confusion — mitigated
- `alg` is constrained to `settings.allowed_jwt_algorithms_list` (the live `.env` sets `RS256` only). `alg=none` is impossible because `none` is never in the allow-list and `jose` would also reject a `None` key.
- RS256/HS256 confusion is not possible: keys are constructed from the asymmetric JWKS (`jwk.construct`), and `token_validator._find_key` additionally rejects a key whose declared `alg` disagrees with the header (MED-7), preventing key-confusion across a kid collision.
- **Recommendation (Info):** in production, pin `ALLOWED_JWT_ALGORITHMS` to exactly the IdP's algorithm (already done in the live `.env` = `RS256`); the *code default* of `RS256,ES256` is broader than necessary — keep the env override.

---

## 2. A2A / Cross-Cluster Delegation

**Files:** `federated-rag/a2a/client.py`, `agt-federated-rag/mesh/agent_identity.py`, `mesh/peer_client.py`, `/tasks/{id}/callback` in both `api/main.py`, `workflow/activities.py`.

### RFC 8693 token exchange + SSRF — correctly guarded
`exchange_token()` (`token_exchange.py:70-85`) validates `target_audience` against `settings.peer_agent_url` using **origin comparison** (`scheme` + `netloc`), explicitly rejecting prefix-match bypasses like `https://peer.internal/api.evil.com`. The outbound A2A callback (`activities.send_a2a_callback` → `_is_allowed_peer_url`, `activities.py:227-238`) likewise rejects any callback URL not under the configured peer origin (S-3). Both are genuine SSRF guards.

> Minor consistency note (not a vulnerability): the delegation node passes `target_audience=str(settings.peer_agent_url)` (the URL), while the peer's `validate_token` accepts `aud ∈ {agent_client_id, agent_url}`. The chain is internally consistent because the agent URL is an accepted audience. No action needed.

### DID signature verification on callbacks — correctly implemented (Finding #1 fix holds)
`agt-federated-rag` `task_callback` (`api/main.py:617-665`) calls `verify_signed_message()`, which:
1. Resolves the peer public key from **`settings.peer_agent_public_jwk` (trusted config), never from the message body** (`agent_identity.py:230-239`) — this is the crux of the Finding #1 fix and it is done correctly.
2. Requires the configured-key DID to equal the envelope `sender_did`, and (if set) to equal `settings.peer_agent_did`.
3. Verifies the Ed25519 signature over canonical bytes (excluding the `_agentmesh` envelope), failing closed on any error.

The endpoint then layers a registry trust-score gate (`verify_peer_identity`), a configured-peer match, and an AGT policy gate (`_enforce("peer.receive_callback", …)` with the **real** verification results, not hardcoded optimism — Finding #4 fix). This is defense-in-depth done right.

`federated-rag`'s callback (`api/main.py:572-630`) uses a different but valid model for the OIDC variant: the caller's JWT `client_id` must be in `peer_agent_client_ids_list` (C-4), empty list denies all (Q-4), and the target task must carry `awaiting_peer_callback` so a peer cannot overwrite local-only tasks (Finding #3).

### Replay protection — Finding R-1 (Low) — REMEDIATED (task #8)

> **UPDATE (verified by re-reading `agt-federated-rag/mesh/agent_identity.py`):** this finding is now **REMEDIATED** and should no longer be treated as open. `sign_outbound_message` adds a fresh `ts` (unix seconds) and `nonce` (uuid4) to the body **before** signing — so both are covered by the Ed25519 signature — and `verify_signed_message` calls `_check_freshness_and_nonce`, which (after signature verification) rejects any message outside a ±300s freshness window or whose `(sender_did, nonce)` has already been seen, with a bounded seen-cache that fails closed when full. This applies to both directions (peer_client outbound + `/a2a/query` / callback inbound). The original-finding text below is retained for history.

**Issue (original, now fixed):** The AgentMesh signed envelope (`sign_outbound_message`/`verify_signed_message`) contained only `sender_did`, `signature`, `alg`. There was no nonce, timestamp, or single-use marker, and the callback verifier did not track seen signatures. An attacker who captured one valid signed callback could replay the identical bytes and it would re-verify and re-apply the status update.
**Impact (bounded, as originally assessed):** A replay could only re-assert the *same* status the legitimate peer already sent, for a task that genuinely belonged to the peer relationship, between two mutually-configured clusters. It could not forge a new status or target an arbitrary task. Low.
**Recommendation (implemented):** Add a monotonic `nonce`/`timestamp` to the signed envelope and reject stale or already-seen values (a freshness window + bounded seen-nonce cache). Applied to both `peer_client.call_peer_agent` payloads and the inbound verifier.

### Cross-cluster audience isolation — Finding AUD-1 (Low; intentional test-enablement)

**Issue.** A single `rag-ui` user token (e.g. alice's) carries `aud = [agent-cluster-a, agent-cluster-b, agent-agt-a, agent-agt-b, account]` — every backend client ID across **both** solutions and **both** clusters. So one user token authenticates to all four backends. The cause is **IdP configuration, not app code:** `setup_agt.py` created the `agent-agt-a/b` Keycloak clients but the demo then added matching `oidc-audience-mapper`s to the public `rag-ui` client (mirroring the pre-existing A2A ones) so the AGT backends would accept the same UI token. This is a deliberate **test-enablement** choice for a single-IdP local demo, recorded as found, not an app vulnerability.

**Impact — BOUNDED, no privilege gain (verified by reading the auth path of every endpoint in both solutions).** The discriminating question is: *does any endpoint grant data or perform an action on token-acceptance alone?* The answer is **no** — authenticating to a backend is necessary but never sufficient; every path re-authorizes on a second factor the shared `aud` does not satisfy:
- **Data reads** (A2A `POST /tasks/send`, AGT `POST /query`): the user flows through `check_auth` → OpenFGA `batch_decide` keyed on the JWT **`sub`**. A user with no `viewer`/`editor`/`owner` tuple for a chunk is `DENIED` regardless of which backends their token's `aud` covers. Per-chunk ReBAC is the real boundary (§3).
- **A2A peer callback** (`POST /tasks/{id}/callback`): gated on the caller's **`azp`/`client_id`** being in `peer_agent_client_ids_list` (`api/main.py`). A `rag-ui` token's `azp` is `rag-ui`, which is **not** a peer agent client — so a user token is **rejected** here despite a valid `aud`. (Additionally the task must carry `awaiting_peer_callback`.)
- **AGT peer endpoints** (`POST /a2a/query`, `POST /tasks/{id}/callback`): authenticated by the **Ed25519 DID signature** in the `_agentmesh` envelope, verified against the peer's public key from trusted config; **no user bearer token is honored on these paths at all.** A user JWT cannot drive them.

So the shared audience means *authenticate-everywhere, authorize-nowhere-extra*: it lets a UI token reach more backends, but each backend independently re-checks `sub` (OpenFGA), `azp` (A2A callback allowlist), or DID (AGT peer paths). No endpoint authorizes on token-acceptance alone, so there is no escalation, no cross-tenant read, and no peer-impersonation from the shared `aud`. The app-layer audience checks are themselves correct and deny-by-default (§1); A2A even ships `exchange_token()` with an exact-match audience allowlist, implying direct cross-cluster token reuse was meant to be impossible — which the per-path re-checks above enforce in practice.

**Recommendation (production — IdP config, not app code).** Scope `rag-ui` tokens per cluster so a UI session for cluster A does not carry cluster B's audience: either issue per-cluster public clients with only their own `aud` mapper, or adopt **RFC 8693 token-exchange** (already implemented for A2A in `auth/token_exchange.py`) so the UI obtains a narrowly-scoped token per backend on demand. To revert the demo enablement, delete the `aud-agent-agt-a` / `aud-agent-agt-b` protocol-mappers from the `rag-ui` Keycloak client. No application change is required; the bound above holds either way.

---

## 3. OpenFGA Authorization

**Files:** `federated-rag/auth/openfga.py`, `federated-rag/agent/nodes.py` (`check_auth`).

**Assessment: deny-by-default, correctly implemented.** No findings.

- `decide()` returns `ALLOWED` only when `check(viewer)` is true, `NEEDS_APPROVAL` only for an explicit `pending_approval` tuple, and `DENIED` otherwise (`openfga.py:92-103`). A user with no tuple gets `DENIED`.
- `check_auth` serves only chunks classified `ALLOWED`; `generate_answer` filters to `allowed_chunk_ids` again (`nodes.py:272-276`), and denied-chunk **text** is pruned from `AgentState` so unauthorized content does not leak into traces/spans (Finding #6).
- The authorization model (write-once at startup, `setup_all.py:60-87`) makes `viewer`/`editor` derive from `owner`, which is the intended ReBAC hierarchy. A user cannot read a chunk they lack a `viewer`/`editor`/`owner` tuple for.
- `revoke_pending_approval` checks the HTTP status code (404 = idempotent no-op; 5xx/4xx re-raised) rather than string-matching (M-3) — correct.

---

## 4. Approval Workflow

**Files:** `federated-rag/workflow/approval.py`, `workflow/activities.py`, `/approve/{request_id}` in both `api/main.py`.

**Assessment: strong.** Two minor/info residuals.

### HMAC + expiry — correctly implemented (C-2 + Finding #2)
- Deep-links carry `token = HMAC_SHA256(approval_hmac_secret, "{request_id}:{decision}:{exp}")` (`activities.py:98-118`).
- The expiry `exp` is **part of the signed message**, so a leaked link cannot be replayed indefinitely; `/approve` rejects `exp < now` before any work (`api/main.py:657-662`).
- Verification uses `hmac.compare_digest` (timing-safe).
- `request_id`/`reason` are length-capped; `agt-federated-rag` additionally enforces `_validate_safe_id`.

### R-2 (Low) — approval link replay within the expiry window
A valid approval URL is a bearer credential reusable until `exp` (24h default via `approval_timeout_seconds`); there is no single-use nonce. Once consumed, the Temporal workflow has already received the decision so a replay is largely a no-op, but the link remains valid in mail/Slack archives until expiry.
**Recommendation:** shorten the approval timeout where workflows allow, and/or mark the `request_id` as consumed (Redis) on first successful signal so the link is single-use.

### Q-1 (Info) — no human attribution
`approver_id` is the constant `"approval-deeplink"` (`api/main.py:679`, `agt:751`). This is a known/accepted limitation (Finding #8): full attribution requires an authenticated approval UI. Anyone holding a valid signed link can approve. For production, gate `/approve` behind authenticated session + record the real approver.

### Q-2 (Info) — `reason` outside the HMAC
The `reason` query param is not covered by the signature, so it is tamperable. It is capped to 500 chars and is non-authorizing (display/audit only). Acceptable; note it.

---

## 5. Secrets Handling — Finding S-1 (**High**)

**Files:** `setup_all.py:41` (NVIDIA key), `:258,:299` (HMAC secrets), `:43-44` (agent secrets); `bootstrap_keycloak.py:23,26-27` (admin + agent secrets); `ui/.env.prod:14` (NVIDIA key); `.gitignore`.

### Ground truth (verified, differs from the task's premise)
The task framing was "committed `.env` files / `.env` should be gitignored." The **actual state is different and must be reported as found**:

- **`.env` files ARE gitignored and untracked** (`.gitignore` line 3 = `.env`). `git ls-files --error-unmatch federated-rag/.env` → not tracked. **This part is correct.**
- **Tracked config is clean:** `git ls-files` shows only `*.env.example` and the k8s `agent-deployment.yaml` files are committed, and those use **placeholders** (`nvapi-your-nvidia-nim-key`, `nvapi-xxxx`, `change-me`, `your-client-secret`). Good.
- **The real problem:** live secrets are hardcoded in files that are **NOT** protected by `.gitignore`:
  - `setup_all.py` — real `NVIDIA_KEY = "nvapi-ImQU…QjRR"`, real `APPROVAL_HMAC_SECRET` literals for both clusters (`3f9a2b7c…`, `a1b2c3d4…`), agent client secrets.
  - `bootstrap_keycloak.py` — Keycloak `admin/admin`, agent client secrets.
  - `ui/.env.prod` — real `NVIDIA_API_KEY=nvapi-ImQU…QjRR`.
  - `.gitignore` covers only `.env` and `ui/.env.demo` — it does **not** match `*.env.prod` or the `.py` setup scripts. These files are currently untracked only because nobody ran `git add`; a single `git add .` would commit all of them.

### Why High (not just key hygiene)
The hardcoded `APPROVAL_HMAC_SECRET` literals in `setup_all.py` are the **signing keys for the C-2 approval-link control**. Anyone who obtains that file can forge valid approve/deny deep-links for either cluster, defeating the human-approval gate entirely. Combined with a live, billable NVIDIA API key sitting in plaintext, this is more than cosmetic.

### Recommendation
1. **Treat the exposed credentials as compromised and rotate them now:** the NVIDIA API key, both `APPROVAL_HMAC_SECRET` values, and the agent client secrets. Change the Keycloak admin password.
2. **Source all secrets from environment / a secret manager** in `setup_all.py` and `bootstrap_keycloak.py` (e.g. `os.environ["NVIDIA_API_KEY"]`, `secrets.token_hex(32)` generated and written only to the gitignored `.env`). No literals in tracked-able source.
3. **Broaden `.gitignore`** to `*.env*` (keep an explicit un-ignore for `*.env.example`), and ensure the setup scripts carry no literal secrets so they are safe to track.
4. **Scan git history** before any publication: this audit verified working-tree state only (files are `??`/untracked, so almost certainly never committed *in the current tree*), but run a history secret-scan (e.g. `git log -p -S nvapi-`, gitleaks/trufflehog) and rotate regardless. **Note:** the repo root contains `push-fixes.bat` through `push-fixes-round6.bat`, indicating this repository has an active push pipeline to a remote — so "untracked locally" does **not** guarantee the secrets never left this machine. Rotate regardless of local tracking state.

---

## 6. CORS

**Files:** `federated-rag/api/main.py:350-356`, `agt-federated-rag/api/main.py:425-431`, `config.py` (`cors_origins`).

**Assessment: correctly locked down.** No findings.

- `allow_origins=settings.cors_origins_list` — an explicit allow-list (dev default `http://localhost:5173`), **not** a wildcard.
- `allow_credentials=False`, `allow_methods=["GET","POST","OPTIONS"]`, `allow_headers` restricted to the needed set.
- **Recommendation (Info):** in production set `CORS_ORIGINS` to the real UI origin(s). The current default is dev-only, which is appropriate.

---

## 7. Input Validation / Injection / DoS

**Files:** both `api/main.py`, `config.py`.

**Assessment: well covered.** No findings.

- **Query length:** capped at `max_query_length` (4096) with a 400 on exceed; empty/whitespace queries rejected.
- **Body size:** pure-ASGI `_LimitBodySizeMiddleware` enforces `max_request_body_bytes` (1 MB) on both the `Content-Length` fast path and chunked slow path, **without buffering SSE responses** (S-1/Q-1). 413 sent directly over ASGI.
- **Rate limiting:** per-subject fixed-window via Redis (`rate_limit_per_minute` = 60) before expensive retrieval/LLM work (Finding #7). See O-1 below.
- **Injection surfaces:** `request_id`/`task_id` sanitized to `[a-zA-Z0-9-]`; X-Request-ID sanitized + length-capped (CRLF-injection guard); approval URL params percent-encoded; free-text (`message`, `reason`) capped at 500 chars; callback payloads validated with Pydantic → 422 not 500.
- **Error hygiene:** internal/Temporal errors not leaked to clients; `jose` error strings (which embed token/claim material) are deliberately not logged.

### O-1 (Low) — rate limiter fails open
`_check_rate_limit` returns (allows the request) on any Redis error. This is an intentional availability-over-security choice and is documented in code. **Recommendation:** acceptable for a demo; for production decide explicitly whether the expensive LLM endpoint should fail closed (or degrade to a stricter in-process limiter) when Redis is unavailable, to avoid an unmetered-cost path during a Redis outage.

---

## 8. Docker / Infrastructure — Findings I-1, I-2 (Medium, deployment-hardening)

**File:** `docker-compose.yml`; k8s manifests; `config.py` server defaults.

These are **fine for a local demo** but **must be fixed before any real deployment**:

- **I-1 Default credentials & exposed admin surfaces:**
  - Keycloak `admin/admin` (`docker-compose.yml:89-90`).
  - Postgres `openfga/openfga` (`:25-27,:44,:57`), `sslmode=disable`.
  - OpenFGA HTTP API (`8089`), gRPC (`8081`), and **playground (`3000`)** exposed on host with no preshared-key auth (`OPENFGA_AUTHN_*` not set).
  - Temporal **dev server** (`start-dev`, in-memory) on `7233`/`8233` — not for production.
  **Recommendation:** strong unique passwords from a secret manager; enable OpenFGA preshared-key/OIDC auth; disable the OpenFGA playground in prod; run a production Temporal cluster with TLS+auth; restrict published ports / put everything behind network policy.

- **I-2 Plaintext transport & broad bind:**
  - App binds `HOST=0.0.0.0`; OpenFGA/Keycloak/Temporal reached over plaintext `http://`/`bolt://`.
  **Recommendation:** in k8s the manifests already assume Istio mTLS (sidecar injection annotations) and Cilium ClusterMesh — ensure mTLS/`STRICT` is actually enforced and that intra-cluster traffic is encrypted; use TLS for Keycloak/OpenFGA endpoints; constrain bind/exposure via NetworkPolicy.

---

## Appendix — Prior findings confirmed remediated

The earlier `SECURITY_REVIEW.md` (2026-05-22) Findings #1–#8 are all addressed in the current tree and were verified during this audit: #1 callback signature verification (now cryptographic, key-from-config), #2 approval-link expiry in the HMAC, #3 `awaiting_peer_callback` task gating, #4 real (non-hardcoded) policy context, #5 AGT policy gate on the HTTP callback entry point, #6 denied-chunk text pruning, #7 rate limiting, #8 decision-channel audit field. The previously-noted `SyntaxError` in `federated-rag/api/main.py` is addressed: the specific defect cited by the prior review (parameter without a default following a defaulted parameter) is fixed — `request: Request` now precedes the `Query(...)`-defaulted parameters in `handle_approval` (`api/main.py:635-645`, FA-5). (Verified by reading the source; this audit did not execute the module.)

SDK-drift fixes (openfga-sdk `ReadRequestTupleKey`/`ClientTuple`, neo4j-graphrag, qdrant explicit embedding, multi-audience JWT) were explicitly out of scope for this security pass and were not re-flagged.
