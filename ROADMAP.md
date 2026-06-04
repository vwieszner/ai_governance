# Roadmap — Federated RAG (A2A + AGT) as a Product

_Saved 2026-06-04. This is the durable task list. The system is treated as a **product**, not a
demo — these items are real, ordered by what unblocks first. Application-layer security is already
hardened (0 red-team bypasses); these are the gaps between "works + secure app layer" and
"shippable / demonstrable product."_

Status snapshot: both federations work end-to-end (4 governance flows), 0 open security bypasses,
docs match reality. Committed locally (one commit ahead of `origin/main`, not pushed).

---

## Tier 0 — Showability (blocks demonstrating the product to a team)

These prevent a clean end-to-end walkthrough in front of an audience.

- [ ] **T0-1 — Human approval cannot be completed in a demo (the headline governance feature
  dead-ends at "pending").** The `/approve/{request_id}` endpoint works and is HMAC-secure, and a
  Temporal approval workflow waits for the signal — but nothing surfaces the signed approve link:
  `start_approval` passes `approver_slack_id=None` + `approver_email=None`, so `notify_approver`
  hits the `no_notification_channel` branch and emits nothing. The UI has no approve/deny button
  (`ui/src/api/rag.ts` only submits queries + displays state). Net: an audience sees "pending
  approval" and it never resolves unless someone hand-computes the HMAC URL.
  **Fix options (pick one):** (a) quick — have the no-channel fallback LOG the signed approve/deny
  URLs so a presenter can click them; (b) better for a team demo — add an "approver inbox" +
  Approve/Deny buttons in the UI (call `/approve/{id}?...` with the link the backend provides);
  (c) wire Slack (set `slack_bot_token` + a real `approver_slack_id`). Also fix
  `approval_ui_base_url` per solution (AGT default is `:8000`, the A2A port — wrong cluster).
- [ ] **T0-2 — Drop "demo" framing in the docs.** README title is "…AI Governance **Demo**";
  SECURITY_AUDIT/STATUS/SCENARIOS say "acceptable for local demo" / "test-enablement". For a
  product these should read as product status + named gaps, not as a demo disclaimer. (README
  "What this is" is otherwise clear and good for explaining purpose to a team.)
- [ ] **T0-3 — One-command bring-up + a guided walkthrough.** Bring-up is multi-step
  (docker + setup_all + setup_agt + clusters.ps1) and the UI must be started separately (it shows
  `down` today). A `make demo` / single script + a 5-minute "show this to a team" script in
  SCENARIOS would make the purpose self-evident.

## Tier 1 — Production hardening (blocks shipping as a product)

Ordered by severity. #1 is a hard gate before any real/sensitive data touches the system.

- [ ] **P1 — Data residency: self-hosted LLM. 🔴 Critical.** Authorized chunks (customer records,
  salary, revenue) are sent to `api.nvidia.com`. Switch to a self-hosted endpoint (vLLM/KServe, or
  the `claude-ollama` already running) so sensitive data never leaves the trust boundary.
- [ ] **P2 — Kill default credentials + lock network exposure. 🔴 Critical.** Keycloak `admin/admin`,
  Postgres `openfga/openfga`; services bind `0.0.0.0`; OpenFGA playground/Temporal dev UI exposed.
- [ ] **P3 — TLS/mTLS everywhere. 🔴 Critical.** OpenFGA, inter-cluster `/a2a/query`, and IdP are
  plaintext HTTP today. Sensitive data + tokens in the clear; cross-cluster identity unprotected.
- [ ] **P4 — Secrets management + rotation. 🟠 High.** NVIDIA key, approval HMAC keys, client
  secrets live in plaintext `.env`. Move to a secrets manager; rotate the currently-on-disk key.
- [ ] **P5 — Authenticated approval portal + real approver attribution. 🟠 High.** Replace the
  HMAC deep-link with an authenticated approver UI; today the approver is recorded as the constant
  `"approval-deeplink"` — no human attribution on data-access decisions (audit/compliance gap).
  (Overlaps T0-1: doing P5 well also solves the demo gap.)
- [ ] **P6 — HA + backups + observability. 🟠 High.** Qdrant is ephemeral, single instances, no
  backups; no metrics/tracing across the federation hop.
- [ ] **P7 — Per-cluster audience scoping. 🟡 Medium.** One UI token authenticates to all 4
  backends (bounded today — no privilege gain). Use per-cluster `aud` / RFC 8693 token-exchange.
- [ ] **P8 — Helm/IaC + pick ONE federation. 🟡 Medium.** Not repeatably deployable; choose A2A vs
  AGT for production (AGT's DID model fits cross-org better) and IaC it.

## Tier 2 — Quality debt

- [ ] **Q1 — Refresh the legacy unit suite.** `federated-rag/tests/test_flows.py` is 5/10 passing;
  the 5 failures are stale assertions (pre-H-1 routing; pending-approval now returns a message) +
  Temporal harness drift (port the workflow tests to `WorkflowEnvironment`). Product behavior is
  verified by live flows + 68 red-team probes, but the suite must be green.
- [ ] **Q2 — Decide GraphRAG: build it or cut it.** The Neo4j graph-retrieval seam is scaffolded
  but inert (retrieval is Qdrant-only; no traversal). Either wire AGT Neo4j ingest + a
  `VectorCypherRetriever` + a multi-hop corpus and verify, or remove the dead seam.
