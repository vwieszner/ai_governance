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

- [ ] **1. PKCE / Auth-Code login in the UI** — replace the password-grant (ROPC) flow
      with OIDC Authorization Code + PKCE redirect.
      _Why: ROPC fails at any IdP with MFA/Conditional Access (i.e., most corporates)._
      _Accept: alice logs in via a redirect to the IdP (incl. MFA) and the existing
      Playwright e2e suite passes unchanged._ (~3–4 d)

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

- [ ] **4. IdP presets for the bundled Keycloak** — ready-made realm configs:
      AD/LDAP user-federation template, Entra broker, Okta broker.
      _Why: the zero-code path for "corporate has Windows users"._
      _Accept: documented import-and-go preset per IdP; agent token contract unchanged._ (~2–3 d)

- [ ] **5. Containerize agent + Temporal worker** into the division compose stack.
      _Why: removes the host-process/PowerShell dependency; one `docker compose up`
      per division._
      _Accept: `onboard_division.py` brings up agent+worker as containers with
      healthchecks; `clusters.ps1` becomes optional._ (~2–3 d)

- [ ] **6. Linux bootstrap + reverse-proxy/TLS preset** — bash parity for
      `bootstrap.ps1`; nginx/traefik preset with DNS-named issuers/agents and real certs.
      _Note: issuer/agent URLs are already pure config; localhost values are dev defaults.
      Mind the Keycloak issuer-host reflection (documented in `ui/.env.example`)._
      _Accept: fresh Linux machine → one command → all e2e proofs green over TLS._ (~3 d)

## Phase 2 — Security finishing: default-secure out of the box (~1 week)

- [~] **7. mTLS between divisions ON by default** — fold CA/cert issuance into
      onboarding; serve with `require_mtls=true`.
      _Scaffold: full CA/cert/CRL machinery in `transport/mtls.py`, proven by handshake
      tests; serving is config-gated off._
      _Accept: peer call without a division cert is rejected live; e2e still green._ (~2–3 d)

- [~] **8. Scheduled key rotation** — DID keys + approval HMAC secrets on a Temporal
      cron schedule, with peer trust-map refresh.
      _Scaffold: rotation function exists; no schedule._
      _Accept: rotation runs unattended; federation keeps working across a rotation._ (~1–2 d)

- [ ] **9. Audit-chain anchoring + field allowlist** — periodically publish each chain
      head (seq, hash) to a remote/append-only sink; switch the audit processor from
      copy-all to an explicit field allowlist.
      _Why: closes the open M8 review finding (tail-truncation / full-rewrite are
      undetectable without an external anchor)._
      _Accept: truncating a chain is detected against the anchor; no PII beyond the
      namespaced principal enters the chain._ (~2–3 d)

## Phase 3 — Extension seams + ops kit (~1.5–2 weeks)

- [~] **10. Connector SDK contract** — formalize the ingest interface:
      `content → chunks + OpenFGA tuples + periodic ACL re-sync hook`; today's
      folder-docs ingest becomes the reference implementation.
      _Why: makes per-deployment connectors (Jira, SharePoint, …) contract work, not
      template work. Non-OAuth sources use the ACL-mirroring pattern (service account +
      per-user OpenFGA filter; group tuples when source perms are AD-group-shaped)._
      _Accept: folder connector re-implemented against the contract; a connector
      author guide._ (~3–4 d)

- [~] **11. MCP executor node** — one governed `call_mcp_tool` node wired to the
      toolkit's installed gateway (`agent_os.mcp_gateway`, `McpAuthPolicy` allowlist,
      response scanner); per-server auth mode config (OAuth token-exchange passthrough |
      service-cred + ReBAC mediation); side-effecting tools route through the approval flow.
      _Rule: never relay the user's raw token (M2 lesson)._
      _Accept: unlisted server/tool is denied by default-deny; a listed read tool works;
      a write tool parks on approval._ (~3–4 d)

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
