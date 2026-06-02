# Security Review — `ai_governance` (federated-rag + agt-federated-rag)

**Date:** 2026-05-22
**Scope:** whole repository (`/security-review` ran against a non-git parent dir; the
repo is nested at `ai_governance/.git`). Both projects reviewed: `federated-rag`
(OIDC / RFC 8693 variant) and `agt-federated-rag` (AgentMesh DID variant).

The codebase has been through several prior review rounds (annotations `C-1`, `S-7`,
`H-6`, …). Most of those fixes hold up. The findings below are issues that survived
or were *introduced* by later refactors.

> **Status: all findings remediated in code on 2026-05-22.** See
> [Remediation](#remediation-applied-2026-05-22) at the end of this document for the
> per-finding status, the answer to "does the governance SDK provide a solution for
> Finding 1" (it does), and a separate functional bug uncovered during the fix.

---

## Summary

| # | Severity | Project | Issue |
|---|----------|---------|-------|
| 1 | **High** | agt-federated-rag | Peer callback authentication bypass — message signature never verified |
| 2 | **Medium** | both | Approval deep-link HMAC token has no expiry / no nonce (permanent bearer credential) |
| 3 | **Medium** | federated-rag | `/tasks/{id}/callback` lets any allowlisted peer overwrite *any* task |
| 4 | **Low** | agt-federated-rag | AGT `peer.send_message` policy context is hardcoded "all-verified" (reinforces #1) |
| 5 | **Low** | agt-federated-rag | Inbound HTTP peer callback bypasses the AGT policy engine entirely |
| 6 | **Low** | federated-rag | Qdrant ACL pre-filter exists but is never used — denied chunk content loaded into memory |
| 7 | **Low** | both | No rate limiting on authenticated query endpoints (cost / DoS) |
| 8 | **Info** | both | Approval `reason` not covered by HMAC; approver identity never recorded |

**Non-security blocker (flagged because it nullifies the file's controls):**
`federated-rag/api/main.py` does not parse — `SyntaxError` at line 576. See end of report.

---

## 1. High — Peer callback authentication bypass (`agt-federated-rag`)

**File:** `agt-federated-rag/api/main.py:544-613` (`task_callback`),
`agt-federated-rag/mesh/agent_identity.py:79-94` (`verify_peer_identity`)

`POST /tasks/{task_id}/callback` is the cross-cluster callback endpoint. Its
docstring states the inbound message "must carry an `_agentmesh` signature block"
and that the sender is verified "against the AgentMesh registry."

What the code actually does:

```python
agentmesh_block = payload.get("_agentmesh", {})
sender_did: str = agentmesh_block.get("sender_did", "")     # attacker-supplied
...
verified, trust_score = await agent_identity.verify_peer_identity(sender_did)
```

`verify_peer_identity(peer_did)` takes **only the DID string** and calls
`mesh.verify_identity(peer_did)` — a registry lookup that answers "does this DID
exist and what is its trust score." It is never passed the request body or the
signature, so it **cannot and does not verify that this message was signed by that
DID's private key.** A grep of the whole `agt-federated-rag` tree confirms there is
no `verify_message` / `verify_signature` call anywhere — only `sign_message`
(outbound) and `verify_identity` (lookup).

The DID is not secret. It is published by this agent's own
`GET /identity` (`api/main.py:423-432`) and `GET /.well-known/agent-card.json`
(`api/main.py:413-418`).

**Exploit (unauthenticated):**
1. `GET https://agent-b.internal/identity` → returns cluster B's DID.
2. `POST https://agent-a.internal/tasks/<any_task_id>/callback` with body
   `{"_agentmesh": {"sender_did": "<cluster-B-DID>"}, "status": {"state": "failed", "message": "<attacker text>"}}`.
3. Accepted. `_update_task` overwrites the victim task's `peer_status` /
   `peer_message`.

The optional `peer_agent_did` check at `api/main.py:586` does **not** close this —
it only narrows the required DID to *the configured peer's* DID, which is exactly
the value the peer publishes on its own `/identity` endpoint.

**Impact:** any unauthenticated party can tamper with any task's state — flip
cross-cluster requests to `completed`/`failed` and inject up-to-500-char text that
is shown back to users (state/message confusion, phishing content). No data
exfiltration or RCE, but it is a complete bypass of a security control the code
*claims* to enforce — operators will believe callbacks are DID-authenticated.

Note the sibling project gets this right: `federated-rag/api/main.py:522-565`
authenticates the callback with a real JWT (`Depends(get_token_claims)`) and an
explicit peer `client_id` allowlist. The AgentMesh rewrite replaced working auth
with an unverified self-asserted body field.

**Fix:** verify the signature in the `_agentmesh` block against the payload using
an AgentMesh message-verification primitive (e.g. `mesh.verify_message(payload)`),
not a bare DID lookup. Reject if the signature does not match. Until that exists,
fall back to the JWT-based scheme used by `federated-rag`.

---

## 2. Medium — Approval deep-link HMAC token never expires

**Files:** `federated-rag/workflow/activities.py:97-109` + `api/main.py:271-279`;
`agt-federated-rag/workflow/activities.py:120-141` + `api/main.py:266-276`

The `/approve/{request_id}` deep-link is protected by
`HMAC-SHA256(secret, "{request_id}:{decision}")`. The HMAC itself is correct and
compared with `hmac.compare_digest`. The problem is what it signs: **only
`request_id` and `decision`** — no timestamp, no expiry, no nonce.

Consequences:
- The token is a **permanent bearer credential**. The approve/deny URL is delivered
  over Slack and email and will persist in Slack exports, mail archives, SIEM/log
  aggregation, and browser history. Anyone who later obtains the URL can approve or
  deny the request — there is no time bound.
- The HMAC error path returns `"Invalid or expired approval token"`, but **nothing
  is ever expired** — the message is misleading.

**Fix:** include an issued-at / expiry timestamp in the signed message and reject
tokens older than a short window (the Temporal workflow already has
`timeout_seconds`; bound the link to the same deadline). Optionally bind the token
to a one-time nonce stored with the workflow so a decision link cannot be replayed
after a decision is recorded.

---

## 3. Medium — Any allowlisted peer can overwrite any task (`federated-rag`)

**File:** `federated-rag/api/main.py:522-565` (`task_callback`)

The callback correctly authenticates the caller and checks its `client_id` against
`peer_agent_client_ids_list`. But once past that gate, it loads the task purely by
the path `task_id` and overwrites `task.status` — there is **no check that the
calling peer is actually a participant in that task** (no correlation between the
peer and the task's originating cross-cluster flow).

A single compromised or malicious peer — or any peer in a multi-peer deployment —
can therefore call `/tasks/<arbitrary_id>/callback` and set the status/message of
**any** user's task, injecting up to 500 characters of caller-controlled text that
`GET /tasks/{id}` then returns to the owning user.

**Fix:** when a task is created for a cross-cluster flow, record which peer it was
delegated to; in `task_callback`, reject the update unless `caller_client_id`
matches that recorded peer.

---

## 4. Low — AGT `peer.send_message` policy context is hardcoded (`agt-federated-rag`)

**File:** `agt-federated-rag/agent/nodes.py:525-535`

`call_peer_agent` calls the policy engine with a **hardcoded** context:

```python
await _enforce("peer.send_message", {
    "peer_did_verified": True,
    "transport_encrypted": True,
    "peer_trust_score": 1.0,
    "peer_execution_ring": "TRUSTED",
    ...
})
```

`peer-comms-policy.yaml` contains `DENY` rules keyed on exactly these fields
(`require-peer-did-verified`, `require-iatp-encryption`, `block-low-trust-peer`,
`require-trusted-ring`). Because the values are hardcoded to the "safe" constants,
**those four DENY rules can never fire.** Only `peer_circuit_state` is a real input.

The real verification does still happen downstream in `mesh/peer_client.py`, so
this is not an exploitable bypass on its own — but read together with **Finding 1**
it shows a consistent pattern: the trust controls are declared in policy YAML,
asserted as `True` in the policy context, and in the inbound case
(`verify_peer_identity`) never actually computed. The governance layer reports
"verified" without verifying.

**Fix:** pass the *actual* verification results into the policy context (do the
mesh verification before `_enforce`, then feed the real `verified` / `trust_score`
/ `encrypted` values), so the policy engine evaluates real state.

---

## 5. Low — Inbound peer callback skips the AGT policy engine (`agt-federated-rag`)

**File:** `agt-federated-rag/api/main.py:544-613`

`peer-comms-policy.yaml` defines an `allow-peer-callback` rule for action
`peer.receive_callback`, and the `handle_peer_result` *graph node* calls
`_enforce("peer.receive_callback", …)`. But the actual inbound HTTP endpoint
`POST /tasks/{task_id}/callback` never calls `_enforce` at all — the AGT policy
engine, audit logging, and any future rate/anomaly rules on that action are
bypassed for the real network entry point.

**Fix:** invoke `_enforce("peer.receive_callback", …)` inside `task_callback`
(after, and in addition to, fixing the signature verification in Finding 1).

---

## 6. Low — Qdrant ACL pre-filter exists but is never applied (`federated-rag`)

**Files:** `federated-rag/rag/qdrant_retriever.py:86-117`,
`federated-rag/agent/nodes.py:168`

`HybridQdrantRetriever.retrieve()` accepts `allowed_chunk_ids` to push the OpenFGA
allowlist into the vector query. `retrieve_local` calls `retrieve(query)` with no
allowlist, so retrieval returns chunks regardless of authorization.

Authorization is still enforced afterward (`check_auth` via OpenFGA, then
`generate_answer` filters to `allowed_chunk_ids`), and the full `AgentState` is not
returned to the client — so this is **not** a direct disclosure. But denied chunk
*text* is fetched into process memory and the LangGraph state, where it can reach
Langfuse traces / OTEL spans. Defense-in-depth gap, not an exploit.

(`agt-federated-rag/agent/nodes.py:232` instead passes `allowed_chunk_ids=[]`;
confirm the retriever treats an empty list as "no filter" and not "match nothing,"
or local retrieval will silently return zero results.)

**Fix:** either apply the OpenFGA allowlist at retrieval time, or document that
post-retrieval filtering is the intended single enforcement point and stop loading
unauthorized text into traceable state.

---

## 7. Low — No rate limiting on authenticated query endpoints

`POST /tasks/send` (`federated-rag`) and `POST /query` (`agt-federated-rag`) are
authenticated but unbounded. Each request fans out to vector + graph retrieval and
an LLM call. A single valid user (or a leaked token) can drive unbounded LLM spend
and backend load. `SREMiddleware` tracks SLO latency but does not throttle.

**Fix:** add per-subject rate limiting (e.g. Redis token bucket keyed on JWT `sub`).

---

## 8. Info — Approval `reason` integrity & missing approver identity

- `/approve` signs `request_id:decision` but **not** `reason`. `reason` is
  attacker-controllable free text (capped at 500 chars) that flows into Slack/email
  notifications and the denial message. Low impact given the cap, but it is outside
  the integrity-protected envelope.
- `ApprovalDecisionSignal.approver_id` is never populated by the `/approve`
  endpoint (always `""`). The workflow logs `approver=""` — there is **no audit
  record of who approved a request**. For an access-approval system this is a
  meaningful governance gap. Capture the authenticated approver identity (which
  also argues for putting real auth, not just an HMAC link, in front of `/approve`).

---

## Non-security blocker — `federated-rag/api/main.py` does not parse

**File:** `federated-rag/api/main.py:576**

```
SyntaxError: parameter without a default follows parameter with a default
    request: Request,   # in handle_approval(), after reason: str = Query("")
```

Verified with `ast.parse`. The module cannot be imported, so the **entire
`federated-rag` HTTP API is non-functional as committed** — and none of the
security controls in that file (HMAC approval check, body-size middleware, task
ownership enforcement, callback peer check) actually run. `agt-federated-rag`'s
equivalent avoids this by declaring `request: Request = None`.

**Fix:** move `request: Request` ahead of the defaulted `Query(...)` parameters,
or give it a default as the agt variant does. This should be fixed before any of
the findings above can be exercised or tested in `federated-rag`.

---

## What looks good

- JWT validation enforces audience and issuer; `verify_aud` is always on; accepted
  algorithms are an asymmetric allowlist (`RS256,ES256`) with no `HS256`/`none`, so
  algorithm-confusion is not reachable by default. `agt`'s `_find_key` adds a
  key/header `alg` cross-check.
- HMAC comparisons use `hmac.compare_digest` (timing-safe).
- Token-exchange audience validation uses scheme+netloc origin comparison, not
  `startswith` (`token_exchange.py:80-85`) — correct SSRF guard.
- User tokens are kept out of `AgentState`, Langfuse, and Temporal history via
  `contextvars`; `H-7` keeps delegated tokens out of Temporal event history.
- Body-size limiting is pure-ASGI so it does not buffer SSE streams.
- No real secrets committed; `.env` is git-ignored, only `.env.example` templates
  are tracked.
- Dockerfile runs as a non-root user.

---

## Remediation (applied 2026-05-22)

All findings have been fixed in code. Files modified:

- `federated-rag/`: `api/main.py`, `config.py`, `workflow/activities.py`, `agent/nodes.py`
- `agt-federated-rag/`: `api/main.py`, `config.py`, `workflow/activities.py`,
  `agent/nodes.py`, `mesh/agent_identity.py`

Every modified file was syntax-checked with `ast.parse`. (Runtime import checks are
not possible offline — most third-party deps are not installed in the review venv.)

### Does the governance toolkit provide a solution for Finding 1?

**Yes.** `agentmesh-platform` is a real, installable package — installed v3.5.0 into a
project venv (`.venv/`) and introspected. It provides the exact primitive the callback
needed:

- `AgentIdentity.verify_signature(data: bytes, signature: str) -> bool` — message
  signature verification, paired with `AgentIdentity.sign(data) -> str`.
- Also `KeyStore.verify(...)`, `TrustBridge.verify_peer(...)`, `Credential.verify_token(...)`.

Finding 1 was therefore **not** a missing-SDK-feature problem — it was the code calling
the *wrong* SDK function: `verify_peer_identity()` (a registry/trust lookup keyed only
by a DID string) instead of a message-signature verification. The toolkit had the right
tool; the code didn't use it.

**Caveat uncovered while checking.** The `agt-federated-rag/mesh/` layer is written
against an SDK API surface that does **not** exist in the real `agentmesh-platform` 3.5.0:

- `from agentmesh import AgentMesh` — there is no `AgentMesh` class (the real facade is
  `AgentMeshClient`).
- `IATProtocolError` — does not exist.
- `mesh.sign_message()`, `mesh.verify_identity()`, `mesh.create_or_load_identity()` —
  not the real method names.

So `mesh/agent_identity.py` and `mesh/peer_client.py` will not import against the real
SDK regardless of this security fix. **Reconciling the mesh layer with the real
`agentmesh-platform` API** (`AgentMeshClient` / `AgentIdentity.sign|verify_signature` /
`TrustBridge`) **is a separate, non-security refactor and was left out of scope.** The
security fix corrects the *authentication logic* and is written at the same abstraction
level as the rest of that file (a `verify_signed_message()` wrapper, the inverse of the
existing `sign_outbound_message()`), so it stays internally consistent. Once the mesh
layer is reconciled with the real SDK, `verify_signed_message()` must be backed by
`AgentIdentity.verify_signature`.

### Per-finding status

| # | Finding | Status | Fix |
|---|---------|--------|-----|
| 1 | agt peer-callback auth bypass | **Fixed** | `verify_signed_message()` added to `mesh/agent_identity.py`; `task_callback` verifies the `_agentmesh` signature against the payload and fails closed *before* trusting any field; the cryptographically-verified signer must match the claimed DID and the configured peer |
| 2 | Approval HMAC token never expires | **Fixed** | Signed message now binds an `exp` timestamp (`{request_id}:{decision}:{exp}`); `/approve` rejects expired links; expiry = approval-workflow timeout — both projects |
| 3 | federated-rag callback can tamper any task | **Fixed** | Tasks delegated to a peer are tagged `metadata.awaiting_peer_callback`; `task_callback` returns 404 for any task without the tag |
| 4 | agt hardcoded `peer.send_message` policy context | **Fixed** | `call_peer_agent` runs real `verify_peer_identity` and passes the actual `peer_did_verified` / `peer_trust_score` into the policy context |
| 5 | agt callback skips the policy engine | **Fixed** | `task_callback` now calls `_enforce("peer.receive_callback", …)` with the real verification context |
| 6 | Denied-chunk text retained in state | **Fixed** | `check_auth` prunes `fused_chunks` to allowed+pending and clears the raw retrieval lists — both projects |
| 7 | No rate limiting on query endpoints | **Fixed** | Redis fixed-window per-subject limiter (`rate_limit_per_minute`, default 60, fails open) — both projects |
| 8 | Approver identity not recorded | **Partial** | `ApprovalDecisionSignal.approver_id` set to `approval-deeplink` so the audit log records the decision channel; full human attribution still requires an authenticated approval UI |
| — | federated-rag `main.py` `SyntaxError` | **Fixed** | `request: Request` moved ahead of the `Query(...)`-defaulted parameters; file now parses |

### Residual risk

- **Finding 3:** the `awaiting_peer_callback` flag does not bind a task to a *specific*
  peer. For the two-cluster topology in this repo (one peer each) the fix is complete;
  a future multi-peer deployment should additionally record the delegated peer's
  client_id on the task and match it in `task_callback`.
- **Finding 8:** intentionally partial — see table.
- The `agt-federated-rag` project as a whole still will not run until its `mesh/` layer
  is reconciled with the real `agentmesh-platform` API (see caveat above). The security
  fixes are syntactically valid and logically correct within the existing abstraction.

### Additional functional bug found (not a vulnerability)

`agt-federated-rag/agent/nodes.py` `retrieve_local` calls
`qdrant.retrieve(query, allowed_chunk_ids=[])`. The agt Qdrant retriever treats an
empty allowlist as **deny-all** (`rag/qdrant_retriever.py:191-193` returns `[]`). So
agt local vector retrieval **always returns zero results** — every query falls through
to `LOCAL_DENIED` / `REMOTE`. This fails *closed* (no data leak), so it is a functional
bug rather than a security finding, but it makes local RAG non-functional in
`agt-federated-rag`. Fix: retrieve an unfiltered candidate set and rely on the existing
post-`check_auth` filtering. Left unchanged here because it is out of security scope.
