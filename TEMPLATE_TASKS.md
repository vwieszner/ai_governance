# Template-Completion Task List

_Goal: make this a **general, secure, easy-to-deploy template** — every integration seam
generic with one working reference implementation; everything company-specific is config._

_Baseline (done & proven): all milestones M0–M8 + M-GOV + 3-division e2e; rendered-UI
Playwright proofs (local / federated / approval); one-shot `scripts/bootstrap.ps1` with
pinned images + frozen deps. See `SESSION_STATUS.md` for the full record._

Status legend: `[ ]` todo · `[~]` partially exists (seam/scaffold present) · `[x]` done

---

## Phase 1 — Identity & deploy seams (~2 weeks)

The gaps that block deployment against a real corporate IdP and network.

- [x] **1. PKCE / Auth-Code login in the UI** — OIDC Auth-Code + PKCE added as an
      additive production mode (`VITE_AUTH_MODE=pkce` + `VITE_OIDC_*`), discovery-driven
      so it works against Entra/Okta/Auth0/Keycloak with no browser secret; the bundled
      two-pane demo keeps password grant.
      _Done: `src/api/oidc.ts` (PKCE verifier/challenge, authorize redirect, state-CSRF
      guard, code exchange, discovery); LoginForm shows "Sign in with SSO" when configured;
      App handles the `?code=&state=` callback. 6 unit tests (incl. CSRF state-mismatch),
      and the 3 Playwright e2e scenarios still pass unchanged (password mode default)._

- [x] **2. Configurable claim mapping** — `PRINCIPAL_CLAIM`, `REQUIRE_VERIFIED_PRINCIPAL`,
      `GROUPS_CLAIM` in config; `principal()` reads the configured subject claim and only
      enforces `email_verified` for an email subject under the policy.
      _Done: defaults keep the hardened Keycloak posture (83 tests green); tested live
      against an Entra-style `preferred_username` token with no `email_verified`._

- [x] **3. Group-based grants end-to-end** — `group#member` wired into chunk `viewer`
      in the AUTH_MODEL; `extract_groups()` parses the IdP group claim (list/str,
      Keycloak `/path` stripping); `openfga.check/decide/batch_decide` thread groups as
      LIVE contextual `member` tuples (never persisted); groups flow
      api `/query` + `/tasks/{id}/result` → `run_query` → state → `check_auth`.
      _PROVEN LIVE on alpha's OpenFGA (throwaway store, deleted): a user with ZERO
      per-user tuples is DENIED without group membership and ALLOWED with it — so leaving
      the IdP group revokes on the next token. Persistent grant = `group:G#member` viewer
      on a doc; membership = contextual, from the token._
      _Remaining for a full UI demo (Phase-1 #4 territory): seed a Keycloak groups
      protocol-mapper + a group, and push the new model to the live division stores
      (re-onboard — additive/reversible)._

- [x] **4. IdP presets for the bundled Keycloak** — `infra/idp-presets/`: AD/LDAP
      user-federation, Entra broker, Okta/OIDC broker, and a **groups protocol-mapper**,
      each an importable admin-API payload with a README (apply steps + matching agent
      claim-mapping table per IdP).
      _PROVEN LIVE: applied groups-mapper.json to alpha's rag-ui client, created group
      `finance`, added a user — the user's token now carries `groups:['finance']`. With the
      earlier OpenFGA proof this closes the full chain: IdP group → claim → contextual
      member tuple → group#member viewer → allowed._

- [x] **5. Containerize agent + Temporal worker** — `agt-federated-rag/Dockerfile`
      (+`.dockerignore`) builds one image for both roles from the frozen lock; opt-in
      `containerized` compose profile adds `agent`+`worker` services (compose-DNS endpoints,
      healthcheck, fastembed cache volume) without disturbing the host-process flow.
      _PROVEN LIVE: image built (1.06 GB); ran on alpha's network → `/health` 200, Temporal
      connected, and a full authenticated `/query` returned LOCAL_ALLOWED + a real answer.
      Documented caveats: Keycloak issuer-host (OIDC_ISSUER stays host value, JWKS internal)
      and cross-division container networking (shared net/host-mode for federation)._

- [x] **6. Linux/macOS bootstrap parity** — `scripts/bootstrap.sh` (bash twin of
      bootstrap.ps1): prereq checks, venv from the lock, npm, onboard alpha/beta (+gamma),
      federate, launch agents+workers as nohup procs, health-check, demo instructions.
      _Done: `bash -n` clean; same idempotent steps. (Reverse-proxy/TLS for production is
      covered by item 7's mTLS + the README TLS preset note; the localhost demo stays HTTP.)_

## Phase 2 — Security finishing: default-secure out of the box (~1 week)

- [x] **7. mTLS serving + outbound client certs, turnkey** — `require_mtls` is now WIRED:
      `tls_serving_kwargs` makes uvicorn serve CERT_REQUIRED mTLS; `peer_tls_context` makes
      peer_client present this division's cert outbound; `scripts/issue_division_certs.py`
      issues a shared federation CA + per-division certs. Fails LOUD if enabled without
      certs (no silent plaintext downgrade).
      _Done: 5 new transport tests (serving kwargs, fail-loud, issued-cert roundtrip
      handshake) — total 87 backend tests green. Default stays off so the localhost demo is
      HTTP; the certless-peer rejection is proven by the handshake tests. (Production flips
      REQUIRE_MTLS=true after issuing certs — documented in the script + config.)_

- [x] **8. Scheduled key rotation** — `workflow/rotation.py`: `KeyRotationWorkflow`
      (Temporal cron) + `rotate_keys_activity` rotate the DID credentials and roll the
      approval HMAC secret (with a prior-value overlap window); registered in the worker;
      started via `scripts/schedule_rotation.py --division <id> --cron`. Logic factored
      into `perform_rotation()` (best-effort: one leg failing never aborts the other).
      _Done: 5 hermetic tests (HMAC roll+overlap, best-effort isolation, worker wiring)._

- [x] **9. Audit-chain anchoring + field allowlist** — each append publishes the chain
      HEAD (seq, hash) to an external anchor (local sidecar by default, or `AUDIT_ANCHOR_URL`
      remote sink); `verify_chain` cross-checks the tail against the highest anchored head,
      so **tail truncation and whole-file deletion are now detected** (the open M8 finding).
      The structlog processor switched to an explicit `AUDIT_FIELD_ALLOWLIST` — a future
      bound token/answer/PII can never enter the immutable chain (only a `count_dropped`).
      _Done: 4 new audit tests (truncation-via-anchor, whole-file-deletion, allowlist drop);
      verify_audit CLI excludes anchor sidecars. 96 backend tests green._

## Phase 3 — Extension seams + ops kit (~1.5–2 weeks)

- [x] **10. Connector SDK contract** — `connectors/`: `base.py` defines the contract
      (`DocumentChunk`, `AccessGrant`, `Connector` protocol) + a generic `ingest()` engine
      that upserts chunks to Qdrant AND writes ACL grants to OpenFGA (user/group/owner/
      pending), with doc-title fan-out. Because emitting grants is part of the interface, a
      connector cannot land content without declaring authz. `folder.py` is the reference
      impl (stable chunk ids matching the legacy ingest). Added `grant_group_viewer` for
      ACL-mirroring of group perms.
      _Done: 3 hermetic tests (all grant kinds, title fan-out, FolderConnector roundtrip)._

- [x] **11. MCP executor** — `tools/mcp.py`: one governed `call_mcp_tool` for ALL MCP
      tools (servers are config in `MCP_SERVERS`, not new nodes). Three gates: policy
      `_enforce("mcp.call")` default-deny, the toolkit's `McpAuthPolicy` gateway (per-server
      allowlist + auth method, unconfigured → fail-closed), and caller-side OpenFGA filtering
      of results. The user's RAW token is never forwarded (per-server `auth_mode`:
      oauth_obo token-exchange | service_rebac); transport is injected (protocol-agnostic).
      _Done: 4 hermetic tests (default-deny, unlisted→rejected, allowed→transport, no token
      leak). 103 backend tests green._

- [ ] **12. `agtctl` admin CLI** — `grant`/`revoke`/`list` for users *and* groups,
      `doctor` (packaged post-deploy smoke probes from the existing test suites),
      `status` across divisions.
      _Why: day-2 ops; today grants are seeding scripts._ (~2–3 d)

- [ ] **13. Observability preset + backup/restore runbook** — Prometheus metrics,
      Grafana dashboard, alert rules (auth-failure spikes, circuit-breaker open,
      approval backlog age, audit-verify failures); scripted backup/restore for
      Postgres / Qdrant / Keycloak realm / OpenFGA store / DID keys. (~3–4 d)

- [ ] **14. Secrets backend abstraction** — env-file (default) | Vault/KMS adapter
      behind one interface. (~2 d)

---

## Deliberately OUT of the template (per-deployment or deferred)

- **Specific connectors** (Jira, SharePoint, file shares) — built per deployment
  *against* the #10 contract.
- **Customer IdP configuration** — covered by the #4 presets.
- **Helm / Kubernetes** — wait for demand; compose covers v1.
- **Admin web console** — `agtctl` covers ops; console is a later nicety.
- **Per-user credential vault / Kerberos constrained delegation** — alternative
  patterns for non-OAuth sources; implement only when a target source requires them.

## Known production caveats (documented, not blockers)

- LLM latency is endpoint-bound: free-tier NVIDIA cold-starts ~1–2 min; production
  points `OPENAI_API_BASE` at a provisioned/self-hosted endpoint
  (`residency_mode: local` for in-boundary inference).
- Keycloak/Temporal run in dev mode, single replica — HA hardening is part of a
  production rollout, not the template (see README + SWOT discussion).
- Audit chain is single-writer-per-(division,role); horizontal agent scaling needs a
  writer-coordination change (tracked under #9's anchoring work).
