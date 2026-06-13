# Threat Model & Security Posture

Honest security posture for the AGT federated-RAG template: what is enforced (and proven),
what is deployment-dependent, and the open design decisions that need an owner's call before
they can be built to production spec. Written so a security reviewer can see the boundaries
without reverse-engineering the code.

---

## 1. Trust model (what the system assumes)

- **Users** authenticate to their division's IdP (Keycloak, or a brokered Entra/Okta/LDAP).
  The agent trusts the IdP's signed token; it does not manage users.
- **Divisions** are mutually-distrusting tenants. Each has its own IdP realm, OpenFGA store,
  Temporal, vector DB, secrets, and **Ed25519 DID**. No shared authority crosses a division
  boundary.
- **Cross-division identity is *vouched delegation*, not receiver re-verification.** When
  division A delegates a user's query to B, A sends the user's **validated claims** (sub /
  email / email_verified / iss) inside an **A-DID-signed, replay-protected** envelope — never
  the user's raw token. B binds the asserted issuer to A's specific DID and re-authorizes the
  user against **B's own** OpenFGA. Consequence (documented, accepted): a compromised-but-
  trusted peer can assert any identity **within its own issuer namespace**, but the per-DID
  issuer binding confines that blast radius to its own users — it can never reach across
  divisions. This is the standard cross-trust-domain delegation model and is strictly safer
  than forwarding a replayable bearer token.

## 2. Controls that are ENFORCED and PROVEN (in code + tests)

| Threat (OWASP-ASI / general) | Control | Evidence |
|---|---|---|
| Unauthorized data access | OpenFGA per-chunk ReBAC, re-decided live on every query | `auth/openfga.py`, `test_authz.py` |
| Privilege escalation via federation | Namespaced principal `email\|sha256(iss)`; per-DID issuer binding | `token_validator.py`, `test_a2a.py` |
| Token replay across divisions | DID-signed claims, never the raw token; ts+nonce replay guard | `mesh/`, `test_a2a.py` |
| Forged/unsigned peer calls | Ed25519 signature verify + trust-score gate on `/a2a/query` | `api/main.py`, `test_multipeer.py` |
| Group-claim escalation | Per-division `RECOGNIZED_GROUPS` allowlist; membership is contextual (never persisted) | `token_validator.extract_groups`, `test_identity_mapping.py` |
| Untrusted retrieval source | Policy `block-untrusted-collection` (default-deny) | `agent/policies/`, `test_governance.py` |
| Credential leak in output | Output DLP hard-deny at the single choke point | `agent/nodes.format_response`, `test_governance.py` |
| Prompt/agent action abuse | Default-deny policy engine on every node action | `agent/policies/base-policy.yaml` |
| Cost / DoS on expensive paths | Per-principal rate limit on `/query` + the poll/approval/revoke endpoints | `api/main._check_rate_limit` |
| Recon via metrics | `/metrics` gated by `METRICS_TOKEN` when set | `api/main.metrics`, `test_metrics.py` |
| Transport interception (peer) | Route-based **mTLS** at the nginx edge (federation-CA client cert required on peer routes) | `infra/nginx/`, `test_transport.py` |
| Audit tamper (offline) | Hash-chained log + external head anchor (truncation/deletion detected) | `audit_log.py`, `test_audit.py` |
| Operator emergency stop | Kill-switch denies the whole query path | `agent/graph.py`, `test_governance.py` |
| Worker-startup regression | AST guard: no sandbox-hostile import in a workflow module | `test_worker_sandbox.py` |

## 3. Deployment-dependent (must be done by the operator; NOT code we can "finish")

These are real production requirements the template supports but cannot self-satisfy:

- **mTLS ON + a host without TLS interception.** The edge is built and the client-cert gate is
  proven, but server-cert pinning is broken locally by AV/corporate MITM (e.g. Norton re-signs
  the cert). Enable `require_mtls`/the edge in prod on a clean host.
- **HA stores.** Keycloak + Temporal run in `start-dev`/single-replica here. Production needs
  real HA Temporal (also removes the inbox visibility lag the Redis index works around) and
  clustered Keycloak with persistent storage.
- **Secrets in a vault.** `SECRETS_BACKEND=vault` is built; make it the prod default and put
  the real secrets behind KMS/Vault (not env files).
- **Backups + log shipping.** Run `backup_division.py` on a schedule; ship audit chains to a
  remote/WORM sink (`AUDIT_ANCHOR_URL`).
- **Independent pen-test + supply-chain scanning** (SBOM, image signing, dependency CVEs) — the
  AGT toolkit is young (v3.x) and moving.

## 4. OPEN design decisions (need an owner's call before building to spec)

These are deliberately **not** implemented, because a half-built version would create false
assurance — worse than the honest current state. Each needs a decision, then real work.

### 4.1 Audit-chain key custody (raise tamper-evidence to tamper-PROOF)
- **Now:** hash-chained + externally anchored → detects offline edits, truncation, deletion.
- **Gap:** an attacker who compromises the agent *process* can recompute the chain AND the
  local sidecar anchor (the hash is keyless and the process owns both).
- **Decision needed:** where does a signing key live that the agent process does **not** hold?
  Options: (a) per-entry HMAC/signature via a **separate signer service / KMS** the agent calls
  but can't read; (b) near-real-time shipment to a remote append-only collector (the local file
  becomes a cache). Recommended: (b) as the default + (a) for high-assurance.
- **Why not done:** doing HMAC with a key the agent can read is security theater. Needs the
  KMS/collector decision.

### 4.2 MCP tool authentication (per-server)
- **Now:** `tools/mcp.py` governs every call (default-deny + the toolkit gateway allowlist) and
  documents "never forward the raw user token"; the actual transport is injected.
- **Gap:** no vetted default transport — a deployer could wire an insecure one.
- **Decision needed:** the canonical auth per server — OAuth **on-behalf-of token exchange**
  (when the MCP server is an OAuth resource server) vs. **service credential + agent-side ReBAC
  mediation** (for legacy). Needs a real MCP server + IdP OBO to build and test against.
- **Why not done:** writing untested auth code against no live system is exactly the risk to avoid.

### 4.3 Browser token storage (UI)
- **Now:** PKCE tokens in `sessionStorage`.
- **Gap:** XSS could exfiltrate them (same exposure as the password-grant tokens in React state).
- **Decision needed:** in-memory tokens + silent refresh (token lost on reload — a UX trade-off)
  and a tuned Content-Security-Policy. Both are product decisions, not mechanical fixes.

## 5. Residual risk summary

The **application-layer security architecture is complete, enforced, and tested**: cross-agent
calls are cryptographically authenticated and the user's identity governs every data decision.
The residual risk is concentrated in (a) operator deployment choices (§3) and (b) three design
decisions (§4) whose correct implementation depends on infrastructure not present in this
environment. None are silent gaps — they are listed here so they are decided, not discovered.
