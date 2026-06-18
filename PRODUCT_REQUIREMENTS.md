# Federated RAG Governance — Product Requirements (Multi-Division Deployment)

> **Scope of this document:** functional requirements (FR), non-functional requirements (NFR),
> and the scenarios the product must cover. This is **analysis + requirements only** — no
> implementation design, no file-level change plan, no sequencing. Acceptance criteria are
> included per requirement so each can be validated, but *how* to build them is deliberately
> out of scope.
>
> **Status note:** the "*(Today: …)*" parentheticals throughout describe the **original
> pre-implementation baseline** and are kept as the gap rationale — they are **not** current
> state. For what is actually built against each requirement, see **`PROJECT_STATUS.md`**.

---

## Context — why this document exists

The repository today contains a working **governed federated-RAG system**: a user asks an agent
a question, the agent retrieves only data the user is authorized to see (OpenFGA ReBAC), enforces
governance policy on every action (DID-signed agents, per-action policy evaluation, trust scoring,
kill-switch), and — when the data belongs to someone else — opens a human **approval** workflow
(Temporal) before releasing anything. It runs as **two clusters** of **two parallel
implementations** (an OAuth RFC 8693 "A2A" variant and a Microsoft-AgentMesh DID "AGT" variant).

The product goal is bigger than what exists: **deploy this anywhere — cloud-agnostic / portable — across different
company (and potentially partner-organization) divisions**, where each division is its own governed
instance, **users within a division
log in to their division**, and **agents in different divisions can collaborate** — so a question
one division can't answer is answered, with consent, by another. When an owner **approves**, the
**answer must reach the original requester's account even if that person was offline** at the
moment of approval; when an owner **denies**, the requester must receive a clear "declined"
message.

Three capabilities the goal names are **not actually present today** — they are the heart of this
spec and are written as gap-driven requirements, not enhancements:

1. **"Answer delivered even if offline" does not work today.** The approval outcome is stored in
   Redis with a **1-hour TTL**, the answer is only pulled while the browser tab is open and
   polling (`tasks` is in-memory React state with no persistence), and the user-notification
   activity is a **stub that only logs**. If the requester closes the tab, nothing reaches them.
2. **Cross-division agent "conversation" does not exist.** Delegation targets a single **hardcoded
   `peer_agent_url`** chosen by an intent classifier. There is no discovery, no capability
   advertisement, no negotiation — agents cannot "find who can help."
3. **There is no division / tenant concept at all.** One Keycloak realm, one shared OpenFGA store,
   no division attribute on users or data, hardcoded to exactly 4 clusters. The entire
   multi-division premise is greenfield against the current state.

### Stated assumptions (correct any that are wrong at review)

- **A-1 — One product, one governance model — DECIDED (AGT).** Two implementations (A2A / AGT)
  existed; the product **converges on AGT — the cryptographic-DID + per-action-policy governance
  model** (the Microsoft Agent Governance Toolkit / AgentMesh direction). The A2A (OAuth RFC 8693)
  variant is **retired as the base**; its federated-user-identity technique is re-used at the *user*
  layer only (FR-3.6). This is a settled decision, no longer an open assumption.
- **A-2 — A division is an isolation boundary.** Each division is a self-contained governed
  deployment (its own data, identity, authorization, approvals). Cross-division access happens
  **only** through the federated agent + approval path, never by shared storage. Whether isolation
  is physical (separate stacks) or logical (scoped tenancy) is downstream; the **requirement is
  hard isolation**.
- **A-3 — Identity is per-division, federated for collaboration — TWO layers.** Users authenticate
  to their own division's identity provider. Cross-division trust has two distinct layers: (1) a
  **DID-authenticated, mutually-verified agent channel** between divisions, and (2) the requesting
  **user's identity**, propagated as a **cryptographically verifiable assertion** and authorized by
  the *receiving* division against its own store (FR-3.6). Neither layer puts all users in one
  realm, and the receiving division never takes the peer agent's *word* for who the user is.
- **A-4 — "Account" means a durable, server-side, per-user destination.** "Deliver to the
  requester's account even if offline" is satisfied by durable server-side storage bound to the
  user identity, surfaced on next login, **plus** an out-of-band notification — not by any
  browser/session state.
- **A-5 — Self-hosted / data-residency-respecting inference is in scope.** Division data must not
  be required to leave the division's trust boundary to be answered (today chunks are sent to
  `api.nvidia.com`).

---

## Functional Requirements

### FR-1 — Multi-division deployment & tenancy
- **FR-1.1** The system SHALL be deployable as **N independent divisions** (N ≥ 2, not fixed),
  each in its own cloud/account/region, from the same codebase + parameterized configuration.
  *(Today: hardcoded to 4 clusters across docker-compose, setup scripts, `.env` files, and
  `clusters.ps1`.)*
- **FR-1.2** Each division SHALL have an isolated data plane — its own knowledge base
  (vectors/graph), its own task/approval state, its own authorization store — such that no
  division can read another division's data except via the governed cross-division path (FR-3).
  *(Today: shared Qdrant / Neo4j / Redis / OpenFGA store; partitioned only by collection name and
  Redis DB number.)*
- **FR-1.3** Onboarding a new division SHALL be a **repeatable, parameterized operation** (a named
  division, its endpoints, its secrets, its trust relationships) without editing source.
- **FR-1.4** A division SHALL be identifiable by a stable **division/tenant identifier** carried
  through identity tokens, authorization tuples, audit records, and inter-agent messages.
  *(Today: no division/tenant id exists anywhere.)*

### FR-2 — Per-division identity & user login
- **FR-2.1** A user SHALL authenticate against **their own division's identity provider** and
  receive a token scoped to that division's services only.
  *(Today: single `rag` realm; one `rag-ui` token carries audience for all backends — finding
  AUD-1.)*
- **FR-2.2** Division administrators SHALL be able to **provision, disable, and assign roles to**
  users within their division (data owner, requester/member, division admin) without affecting
  other divisions.
- **FR-2.3** A user's authorization to data SHALL be evaluated per-resource (ReBAC) within their
  division, **deny-by-default**, and SHALL distinguish three outcomes: allowed / needs-approval /
  denied. *(Today: present via OpenFGA, but in one shared store.)*
- **FR-2.4** The login experience SHALL make the user's division explicit and prevent a token from
  one division being silently accepted by another division's services.

### FR-3 — Cross-division agent communication & delegation by discovery
- **FR-3.1** When a division's agent cannot answer from local data, it SHALL be able to **discover
  which other division(s) can help** rather than calling a single hardcoded peer. Discovery MAY be
  via a registry / capability advertisement, but MUST NOT require the requesting agent to know the
  answer-holder in advance. *(Today: single hardcoded `peer_agent_url`.)*
- **FR-3.2** Delegation SHALL be a **negotiated exchange** — the requesting agent asks whether a
  peer can help and the peer responds — not a blind forward. The exchange SHALL be driven by the
  agents' reasoning, not hardcoded strings.
- **FR-3.3** Every cross-division message SHALL carry **verifiable agent identity** (cryptographic
  signature, e.g. Ed25519/DID), be replay-protected, and be rejected if the signer is not a
  trusted, sufficiently-scored peer. *(Today: present in the AGT implementation; this is a product
  requirement for all cross-division traffic.)*
- **FR-3.4** Cross-division collaboration SHALL be **observable**: the requesting user's monitor
  view SHALL show the inter-agent / cross-division conversation, not only the user's own request
  lifecycle.
- **FR-3.5** The system SHOULD support more than two divisions participating (no assumption of a
  single fixed peer); multi-party / multi-hop discovery is a forward requirement.
- **FR-3.6** Every cross-division request SHALL carry the **requesting user's verifiable identity** —
  a cryptographically validatable assertion federated from the user's home division (e.g. OAuth2
  Token Exchange / RFC 8693, or OIDC federation) — **not** a bare claim the receiver must take on the
  peer agent's word. The **receiving division SHALL authorize that user identity against its OWN
  authorization store** (ReBAC, deny-by-default), independent of its trust in the requesting agent
  beyond channel authentication, yielding one of **allowed / needs-approval / denied**. *(Today: the
  AGT path forwards `user_id` as a DID-signed claim the peer vouches for — agent-vouched, not
  user-verifiable; this requirement raises it to a federated, far-side-validated user identity. It is
  distinct from and does not weaken FR-2.1 — the home-division login token still never leaves its
  division.)*
- **FR-3.7** When the propagated user is **already authorized** in the receiving division, the answer
  SHALL be returned **immediately through the governed pipeline with no approval step**; an approval
  is required only when the data needs its owner's consent (FR-5). The two cross-division outcomes —
  directly-authorized vs needs-approval — are **distinct paths**, not one flow.

### FR-4 — Governance enforcement (the active governance toolkit)
- **FR-4.1** Every agent action (retrieve, authorize, generate, delegate, send-to-peer,
  receive-callback, format/output) SHALL pass a **per-action policy evaluation** before executing;
  denials SHALL fail closed and surface as a safe user-facing message. *(Today: present in AGT via
  per-node `_enforce` + policy YAML.)*
- **FR-4.2** Agent-to-agent trust SHALL be **scored and gated** — low-trust or unverified peers
  SHALL be refused; repeated violations SHALL decay trust.
- **FR-4.3** An **operator kill-switch** SHALL be able to halt an agent/division's governed
  request path. *(Today: present, deploy-time engaged.)*
- **FR-4.4** Outbound answers SHALL pass an **output safety check** (e.g. credential/secret
  leakage DLP) before release; a positive match SHALL withhold the answer.
- **FR-4.5** The requirement that a query **needs approval** SHALL be a governed authorization
  decision (data has an owner / pending state), not a hardcoded branch.

### FR-5 — Approval workflow
- **FR-5.1** When data needs consent, the system SHALL open a **durable approval request**
  addressed to the correct **data owner**, surviving process restarts, valid for a configurable
  window (default 24h). *(Today: present via Temporal.)*
- **FR-5.2** The data owner SHALL see pending requests in an **authenticated inbox** (who is
  asking, for what) and approve/deny as the verified owner — not via an unauthenticated deep-link
  alone.
- **FR-5.3** Approving SHALL grant access through the authorization store and (where applicable)
  signal the originating division; denying SHALL record the refusal. Both outcomes SHALL be
  durably recorded against the **requester's identity and original request**.

### FR-6 — Offline, account-bound delivery of the outcome  *(core gap)*
- **FR-6.1** When an approval **resolves** (approve or deny), the outcome SHALL be delivered to the
  **requester's account**, durably, **independent of whether the requester is online** at that
  moment. The mechanism MUST NOT depend on a browser tab being open or on any client-side polling
  loop. *(Today: 1h Redis TTL + in-memory React polling + stubbed notifier ⇒ fails when offline.)*
- **FR-6.2** On **approval**, the requester SHALL receive the **actual answer to their original
  question**, (re)generated **server-side through the full governance pipeline** at delivery time
  (so a changed authorization state cannot leak stale data). *(Today: server-side re-run exists,
  but only reachable via live polling within the TTL.)*
- **FR-6.3** On **denial**, the requester SHALL receive a clear **"declined"** message (and reason
  where policy permits).
- **FR-6.4** The outcome SHALL be **retrievable on the requester's next login** to their division,
  presented against the original question, with no time cap shorter than the approval window — and
  ideally retained until acknowledged. *(Today: 1h TTL is far too short and tab-bound.)*
- **FR-6.5** The system SHALL additionally send an **out-of-band notification** (channel is an open
  sub-option: in-app inbox badge on next login, and/or email, and/or push) so the requester learns
  an answer is waiting without re-asking. *(Today: `notify_user_of_decision` is a logging stub.)*
- **FR-6.6** Offline delivery SHALL work for **cross-division** approvals (requester in division X,
  owner in division Y) the same as for same-division approvals. *(Today: the AGT path has no
  requester-side outcome retrieval at all.)*

### FR-7 — Access lifecycle (grant, expiry, revocation)
- **FR-7.1** An approval-granted access SHALL support being **time-bound** (configurable
  expiry / re-consent) rather than permanent. *(Today: grants are written with no TTL — permanent.)*
- **FR-7.2** A data owner or division admin SHALL be able to **revoke** a previously granted access,
  after which the requester loses access on the next authorization check.
- **FR-7.3** Re-asking an expired/revoked question SHALL re-enter the approval flow, not silently
  reuse a stale grant.

### FR-8 — Audit & accountability
- **FR-8.1** The system SHALL record an **audit trail** of: who asked what, what was retrieved/
  released, who approved/denied (and when), and every cross-division delegation — scoped per
  division and queryable by division admins.
- **FR-8.2** Audit records SHALL be **tamper-evident** and retained per the division's policy.
- **FR-8.3** Governance denials (policy, trust, kill-switch, DLP) SHALL be audited with the reason.

---

## Non-Functional Requirements

- **NFR-1 — Data residency / sovereignty.** A division's data (documents, chunks, embeddings,
  queries) SHALL be processable **within the division's trust boundary**, including inference.
  Sending division content to an external third-party API SHALL be configurable off and SHALL NOT
  be required. *(Today: chunks are sent to `api.nvidia.com`.)*
- **NFR-2 — Isolation / blast radius.** A failure, compromise, or noisy-neighbor load in one
  division SHALL NOT degrade or expose another division. No shared single point whose loss crosses
  a division boundary. *(Today: shared datastores violate this.)*
- **NFR-3 — Security posture (zero-trust).** All service-to-service and cross-division traffic SHALL
  be encrypted (TLS/mTLS); every request re-authorized at the resource; no auth-bypass modes in any
  build. Because cross-division **agent endpoints are internet-facing**, they SHALL use **mutual TLS
  with certificate-identity validation and revocation (CRL/OCSP)** and SHALL support **periodic
  DID/credential rotation** — a private-LAN posture is insufficient. *(Today: localhost plaintext;
  mock-auth already removed.)*
- **NFR-4 — Secrets management.** No secrets in source or tracked config; secrets centrally managed,
  rotatable, per-division. *(Today: `ui/.env.prod` is gitignored but contains a real NVIDIA key that
  must be rotated; `bootstrap_keycloak.py` carries default credentials.)*
- **NFR-5 — Durability & availability.** Approval state, outcome delivery, authorization grants, and
  audit SHALL survive process/host restarts and be backed up; the approval/outcome path SHALL meet a
  stated availability target.
- **NFR-6 — Scalability.** Adding divisions and users SHALL scale horizontally; the data-owner
  pending-inbox and discovery/registry lookups SHALL not degrade super-linearly with request volume
  or division count. *(Today: pending-inbox does O(open requests) point queries.)*
- **NFR-7 — Performance.** Interactive latency budgets for local answers, and a stated budget for the
  added cross-division hop; intent/classification SHALL not block the common local path.
- **NFR-8 — Operability / IaC.** A division SHALL be stood up and configured via
  infrastructure-as-code (no manual multi-file edits); health, metrics, and tracing SHALL cross the
  inter-division hop. *(Today: k8s manifests are placeholder stubs; no Helm/IaC.)*
- **NFR-9 — Compliance & governance evidence.** The product SHALL be able to demonstrate, per
  division, who could access what and why a given release was or wasn't permitted (ties to FR-8).
- **NFR-10 — Portability across clouds.** The deployment SHALL not hard-depend on one cloud's managed
  services; division endpoints/DNS SHALL be configurable, not localhost-bound. *(Today: hostnames/
  ports hardcoded to localhost.)*

---

## Scenarios the product must cover

> These are **product capability scenarios** — the acceptance narratives — not the existing internal
> flow re-documented. Each names the actors, the trigger, and the expected governed outcome.

- **SC-1 — Onboard a new division.** An operator stands up "Division C" (own identity, data store,
  authorization store, agent identity, trust relationships) via parameterized config, with no source
  edits. *Expected:* Division C is live, isolated, and discoverable by peers it's allowed to talk to.
- **SC-2 — Provision a user within a division.** A division admin creates user *carol* (role:
  member) and *dave* (role: data owner). *Expected:* carol can log in to her division and query;
  dave receives approval requests for data he owns; neither can authenticate to another division.
- **SC-3 — Local authorized answer.** alice asks a question whose data she's authorized to see in
  her own division. *Expected:* immediate governed answer; no approval; audit recorded.
- **SC-4 — Local needs approval → granted → delivered offline.** alice asks for data owned by bob in
  the same division; the agent opens an approval; **alice closes her browser**; bob approves an hour
  later. *Expected:* on alice's **next login**, the actual answer (re-generated server-side under
  current authorization) is waiting in her account, with an out-of-band notification — no tab needed.
- **SC-5 — Denied → declined message delivered.** Same as SC-4 but bob **denies**. *Expected:* alice
  receives a clear "declined" message (with reason where allowed) in her account, online or offline.
- **SC-6 — Cross-division delegation by discovery, user authorized in B.** alice (Division A) asks
  something only Division B can answer; A's agent **does not know B in advance** — it discovers a
  capable peer and negotiates. alice's **verifiable identity is propagated** and **validated by B**
  (not vouched for by A's agent); B finds alice **is authorized** for the data. *Expected:* answer
  returned **immediately, no approval**; both agent identities verified; the inter-agent conversation
  is visible in alice's monitor.
- **SC-7 — Cross-division needs approval → offline delivery.** Like SC-6's discovery + identity
  validation, but alice is **not** pre-authorized — B's data needs its owner's consent; alice goes
  offline. *Expected:* B's owner approves/denies; the outcome reaches alice's **account in Division
  A** on next login (FR-6.6), cross-machine, no shared client state.
- **SC-8 — Time-bound access & revocation.** A previously approved access expires (or B's owner
  revokes it); alice re-asks. *Expected:* access is re-evaluated and re-enters approval — no stale
  reuse.
- **SC-9 — Governance stop.** An operator engages the kill-switch / a policy or trust gate trips
  during a cross-division request. *Expected:* the request fails closed with a safe message; the
  denial and reason are audited.
- **SC-10 — Out-of-scope / general query.** alice asks a non-company/chit-chat question.
  *Expected:* answered locally without wasting a cross-division call; no data exposure.
- **SC-11 — Audit review.** A division admin asks "who accessed bob's salary data last month, and who
  approved it?" *Expected:* a complete, division-scoped, tamper-evident answer (FR-8).
- **SC-12 — Isolation under failure.** Division B's datastore is down or compromised. *Expected:*
  Division A keeps serving local queries; only B-dependent cross-division requests degrade, with a
  clear message; no A data is exposed (NFR-2).

---

## How each requirement is validated (acceptance posture)

- **Multi-division / isolation (FR-1, NFR-2, SC-1, SC-12):** stand up ≥3 divisions from config;
  prove division A cannot read division B's store directly; kill B and show A unaffected.
- **Per-division login (FR-2, SC-2):** a Division-A token is rejected by Division-B services; role
  changes take effect; deny-by-default holds.
- **Discovery + conversation (FR-3, SC-6):** remove all hardcoded peer URLs; A still finds and
  negotiates with a capable peer; agent signatures verified; the **requesting user's identity is
  validated by the receiver** (not agent-vouched) and authorized against B's own ReBAC; the
  directly-authorized path returns with **no approval**; monitor shows the exchange.
- **Offline delivery (FR-6, SC-4/SC-5/SC-7) — the headline:** approve/deny **with the requester's
  browser fully closed**; the answer/declined message is present on next login with **no 1-hour
  cap** and an out-of-band notification fired; verified cross-division and cross-machine.
- **Access lifecycle (FR-7, SC-8):** grant expires/revokes; re-ask re-enters approval.
- **Governance + audit (FR-4, FR-8, SC-9, SC-11):** denials fail closed and are audited; admin can
  reconstruct access history per division.

---

## Out of scope for this document
- Implementation design, technology selection between the two existing codebases, schemas, file
  changes, sequencing, or estimates. Those follow **after** these requirements are agreed.
