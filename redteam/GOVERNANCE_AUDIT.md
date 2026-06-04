# Agent-Governance Correctness Audit (both solutions)

Auditor: gov-auditor · Task #6 · Top priority: agent-governance correctness, FAIL-CLOSED.

Scope: both solutions, both clusters.
- **A2A** `federated-rag/` (cluster-a :8000, cluster-b :8002) — LangGraph + OpenFGA + RFC 8693 token exchange + Temporal approval + A2A peer client/callback.
- **AGT** `agt-federated-rag/` (cluster-a :8010, cluster-b :8012) — same shape PLUS `mesh/` (Ed25519 DID identity, signed peer client, real HTTP `/a2a/query`), the Agent OS `PolicyEvaluator` policy engine (`_enforce`), and a graph-level `govern_action` gate.

Method: read the source for every checklist item; for the load-bearing fail-closed claims I ran the real engines empirically (`agent_os.policies.PolicyEvaluator` and `agentmesh.AgentMeshClient`) rather than trusting comments.

**Result: 8/8 checklist items audited. 6 OK, 2 GAP (1 minor, 1 medium). Both GAPs fixed at the root (minimal, fail-closed-preserving). No data-path fail-open found in either solution.**

---

## Summary table

| # | Item | A2A | AGT | Verdict |
|---|------|-----|-----|---------|
| 1 | Every node gates before acting, fails closed on error | OK | OK | OK |
| 2 | AGT middleware/graph gate DENIES on policy-deny (not advisory) | n/a | **GAP (medium)** | graph-level kill-switch is decorative; per-node `_enforce` is the real, fail-closed control |
| 3 | Policy default-deny + covers every action/collection | OK | **GAP (minor)** | latent fail-open in `data-access-policy.yaml` default (FIXED); + 4 decorative DENY rules via field-name mismatch, none a data-path fail-open (see 3a) |
| 4 | Trust gate fails closed | OK | OK | OK |
| 5 | Approval integrity (viewer only after approval; pending revoked on deny+timeout) | OK | OK | OK |
| 6 | Token isolation (user JWT never in state/history/logs) | OK | OK | OK |
| 7 | Cross-cluster delegation re-checks OpenFGA on receiver | OK | OK | OK |
| 8 | Peer callback hardening | OK | OK | OK |

Fixes applied (both minimal, root-cause, fail-closed-preserving):
1. `agt-federated-rag/agent/policies/data-access-policy.yaml` — `defaults.action: allow` → `deny`.
2. `agt-federated-rag/agent/graph.py` — corrected the module docstring that falsely claimed a functional `GovernanceMiddleware` kill-switch.

---

## Item 1 — Every node gates the action before acting and fails closed — OK (both)

**A2A.** Graph wiring (`federated-rag/agent/graph.py:88-116`): `retrieve_local → check_auth → {generate_answer | start_approval | call_peer_agent} → … → format_response`. `check_auth` (`agent/nodes.py:185-261`) runs OpenFGA `batch_decide` per chunk and is the gate before any answer is generated. The routers fail closed on an unexpected flow: `route_after_auth` (`graph.py:62`) **raises ValueError** rather than silently allowing.
- Fail-closed on authz error: A2A `auth/openfga.py:94-103` `check()` does **not** swallow exceptions — an OpenFGA `ApiException` propagates up through `decide`→`batch_decide`→`check_auth`→graph and is caught only by the SSE handler (`api/main.py:524-532`) which sets the task FAILED. No implicit allow on error.

**AGT.** Every node calls `_enforce(action, ctx)` before work: `retrieve_local`→`rag.retrieve` (`nodes.py:227`), `check_auth`→`auth.check_permission` (`nodes.py:275`), `generate_answer`→`llm.generate` (`nodes.py:384`), `start_approval`→`approval.start_workflow` (`nodes.py:430`), `call_peer_agent`→`peer.send_message` (`nodes.py:559`), `handle_peer_result`→`peer.receive_callback` (`nodes.py:622`), `format_response`→`agent.format_response` (`nodes.py:672`). `_enforce` (`nodes.py:116-133`) raises `PermissionError` on `not result.allowed`. The router `_route` (`graph.py`) also **raises** on an unexpected flow value. AGT `auth/openfga.py:143-153` `check()` catches `ApiException` and sets `allowed = False` (explicit fail-closed).

---

## Item 2 — AGT graph-level governance gate DENIES on policy-deny (not advisory-only) — GAP (medium) → RESOLVED (operator kill-switch now enforcing)

**What the code does.** There is no `GovernanceMiddleware` in the codebase — it appears only in the old `graph.py` docstring. The actual graph-level gate is in `run_query` (`agt-federated-rag/agent/graph.py`):

```python
gov = await govern_action("agent.graph.invoke", {"user_id": ..., "task_id": ...})
if not gov.allowed:
    raise PermissionError(...)        # the deny PATH is correct and fails closed
```

So the *path* is wired correctly: a deny would raise and abort before any node runs.

**Why it's a GAP.** The gate can never deny. `govern_action` → `mesh.execute_with_governance` (`agentmesh/client.py:132`). The mesh client is built in `mesh/agent_identity.py:get_mesh()` with **no `policy_yaml`**, so `AgentMeshClient.__init__` loads its built-in `_DEFAULT_ALLOW_POLICY` (`agentmesh/client.py:24-31, 75-79`): `rules: []`, `default_action: allow`. Empirically confirmed by constructing the client exactly as `get_mesh()` does and feeding hostile contexts:

```
ctx={'agent_trust_score':0.0}                 -> allowed=True  decision=allow  trust=510
ctx={'goal':'system_prompt.override'}         -> allowed=True  decision=allow  trust=520
ctx={'agent_trust_score':-999}                -> allowed=True  decision=allow  trust=530
```

The client's own trust score only ever **rises** (`+success_delta` on allow; there is no path in this codebase that decreases self-trust — `report_trust_event`/`verify_peer_identity` move the *peer's* score, not the client's). So the trust-based "kill-switch" the docstring advertised does not exist.

**Severity = MEDIUM, with an important caveat:** this is a decorative **defense-in-depth / audit** hook, **not a data-path fail-open**. The real, fail-closed access controls are untouched and verified elsewhere in this report: per-node `_enforce` against the Agent OS engine (Item 1, default-deny per Item 3) and OpenFGA per-chunk ReBAC (Item 7). An attacker cannot read unauthorized data through this gap — they only fail to be stopped by a decorative trust gate that never functioned.

**Fix applied (minimal, honest).** Corrected the `graph.py` module docstring: removed the false "wraps the compiled graph with AGT GovernanceMiddleware … kill-switch" claim and replaced it with an accurate description of the two real enforcing layers plus an explicit note that the `govern_action("agent.graph.invoke")` gate is currently a decorative audit hook (allow-all baseline policy, monotonically-rising self-trust) and that a working kill-switch is a design change, not a code tweak.

**Deliberately NOT done (would be theater):** wiring `agent_trust_score` into `_enforce` to fire the `base-policy.yaml:block-low-trust-agents` rule. The mesh self-trust starts at 500/1000 = 0.5, which is *below* the 0.6 threshold, and only rises — so such a rule would either deny everything at startup or never fire. A genuine kill-switch needs (a) an agentmesh-format policy with a real threshold passed to `AgentMeshClient(policy_yaml=...)`, and (b) a downward trust signal on anomalous behaviour. That is a design item, surfaced here rather than faked.

> **UPDATE (task #4 — operator kill-switch now ENFORCING):** The decorative gate is now a working **operator off-switch**, implemented via part (a) above (a real `AgentMeshClient(policy_yaml=...)`) plus an explicit operator flag — deliberately **not** keyed on self-trust, which (per the paragraph above) can never function as a kill-switch.
> - **What changed (4 AGT-only edits):**
>   1. `mesh/agent_identity.py` — `get_mesh()` now builds the client with `_GRAPH_GOVERNANCE_POLICY`: `default_action: allow` + one priority-1000 deny rule `condition: kill_switch_engaged`. Default-allow means wiring the policy in cannot regress any working flow.
>   2. `config.py` — new `agent_kill_switch_engaged: bool = False` (env `AGENT_KILL_SWITCH_ENGAGED`), the same static-flag idiom as `policy_audit_only`/`sre_enabled`.
>   3. `agent/graph.py` — `run_query` injects `settings.agent_kill_switch_engaged` into the existing `govern_action("agent.graph.invoke", …)` context, and the docstring is corrected to describe the gate accurately.
>   4. `api/main.py` — `/query` refuses with **HTTP 503** at the top of the endpoint when the flag is engaged (before auth/streaming); `/a2a/query` is left on the signed-`status="failed"` path (see HTTP-surface note below for why a raw 503 there would break the DID-signed peer contract).
> - **It genuinely DENIES (verified in-process, real edited code, no backends touched):** flag `True` → `govern_action` returns `allowed=False` → `run_query` raises `PermissionError` **before `_get_compiled_graph()`** (no node runs; graph never compiled; no retrieval/LLM). Flag `False` (default) → allowed, normal operation. The second `govern_action` call site (`peer_client.call_peer_agent` → `peer.send_message`) does not set the flag, so it stays `allowed=True` — **no regression**. (`run_query` is the single entry point for BOTH `/query` and `/a2a/query`, and `call_peer_agent` only runs after `run_query` already passed, so the internal `govern_action` deny alone already covers the kill-switch intent at the graph layer; the 4th edit below additionally shapes the `/query` HTTP surface.)
>   - **HTTP surface (4th edit — `api/main.py`, Option B):** the internal `govern_action` deny raises `PermissionError`, but that is caught *inside* the request handlers (it does NOT reach the global `permission_error_handler→403`). So the operator-facing HTTP surface is shaped deliberately at the endpoints:
>     - **`/query` → HTTP 503** *before* the SSE stream opens. A guard at the top of the endpoint (`if settings.agent_kill_switch_engaged: raise HTTPException(503, "Agent administratively disabled (kill-switch engaged)")`) refuses before any auth/retrieval/LLM work. **503 (Service Unavailable = administrative disable), not 403** — a monitor / load balancer hitting a disabled agent should see "unavailable", not a per-request authz denial, and the two are distinguishable in logs (`kill_switch_refused_query`). This avoids the misleading "200 OK SSE stream that immediately errors" that the 3-edit-only version produced.
>     - **`/a2a/query` → signed `status="failed"` (HTTP 200), deliberately NOT a raw 503.** This is the DID-signed peer contract: a raw `HTTPException` would return an UNSIGNED error body, which the peer cannot cryptographically verify. The existing internal-deny path (`run_query` `PermissionError` caught locally → `sign_outbound_message({"status":"failed", …})`) yields a verifiable refusal, which is the correct behaviour for the peer protocol. So `/a2a/query` relies on edit #3's internal `govern_action` deny, unchanged.
>     - **`/health` stays 200** — process liveness is genuinely up; the kill-switch disables the query path, not the process.
>   - **Defense-in-depth, not replacement:** the 4th edit ADDS the `/query` endpoint check; it does NOT remove the internal `govern_action` deny (edit #3), which still fires for any other `run_query` caller and keeps the AgentMesh audit entry when reached. Verified in-process: `/query` handler with flag `True` → `HTTPException(503)` before auth; flag `False` → passes the gate into auth (401 on missing token), confirming the guard only fires when engaged.
> - **HONESTY / scope (do not overclaim — this is exactly the line the original GAP narrative drew):** this is a **DEPLOY-TIME** operator disable lever — `settings` is read once at startup, so engaging it means setting the env var and **RESTARTING** the agent; it is **not** an instant runtime lever, and it is **not** the automatic, trust-degradation-based self-trust trip (that downward-trust signal, part (b) above, remains a tracked design item). The fail-closed **data-path** controls (per-node `_enforce` default-deny + OpenFGA per-chunk ReBAC) are unchanged and remain the real access-control boundary; this gate is defense-in-depth / an emergency off-switch on top of them. The decorative-rule findings in Item 3a (e.g. `block-low-trust-agents` on `agent_trust_score`) are unaffected by this change and stay as documented.

---

## Item 3 — Policy engine default-deny; covers every action + every collection — GAP (minor), FIXED

**Engine semantics (verified by reading + running `agent_os/policies/evaluator.py`).** `load_policies` loads `*.yaml` **alphabetically** (`evaluator.py:55`). All rules from all docs are flattened and sorted by `priority` desc; the first rule whose `condition` matches wins (`_evaluate_flat`, `evaluator.py:171-197`). When no rule matches, the default is taken from **`self.policies[0].defaults.action`** (`evaluator.py:220-222`). The three files sort `base-policy` < `data-access-policy` < `peer-comms-policy`, so `policies[0]` = `base-policy`, whose `defaults.action: deny`. Empirically:

```
order: ['base-policy','data-access-policy','peer-comms-policy'] | policies[0].default = deny
UNKNOWN action (no rule matches)        -> allowed=False (deny)
empty context (no action key)           -> allowed=False (deny)
all 7 governed actions                  -> allowed=True via explicit allow-* rules
untrusted collection / oversize ctx /
  unverified DID / low trust            -> allowed=False via DENY guard rules
```

The engine also fail-closes on its own internal exception (`evaluator.py:236-253`: any exception → `allowed=False`).

**Action coverage:** every governed action has an explicit `allow-*` rule in `base-policy.yaml` (priority 100), and every action with no matching rule is denied by default. OK.

**Collection coverage:** `data-access-policy.yaml:block-untrusted-collection` allow-lists `[knowledge_base, knowledge_base_agt_a, knowledge_base_agt_b]`. The two AGT clusters configure `QDRANT_COLLECTION=knowledge_base_agt_a` (`.env`) and `knowledge_base_agt_b` (`.env.cluster-b`) — both covered. The checklist's `knowledge_base_a` / `knowledge_base_b` are the **A2A** solution's collections; A2A does not use this policy engine, so their absence from the AGT allow-list is correct, not a gap.

**The GAP (minor / latent fail-open):** `data-access-policy.yaml` declared `defaults: action: allow`. Today this is harmless because `base-policy` sorts first and supplies the effective global default. But it is a latent fail-open: rename a file, or add a policy file that sorts before `base-`, and `policies[0]` flips to a document whose default is `allow` → the whole engine defaults to allow. Given the fail-closed mandate, every policy document must agree on deny-by-default.

**Fix applied:** `data-access-policy.yaml` `defaults.action: allow` → `deny`, with a comment explaining the load-order dependency. Re-ran the full matrix above after the change: no regression (all governed actions still allowed via their explicit rules; all guard denials and unknown-action denials unchanged).

### Item 3a — Decorative / non-functional DENY rules (field-name mismatch)

Systematic check (the same method used for Item 2's kill-switch): for every `deny`/`block` rule across the three YAMLs, I confirmed whether its `condition.field` is ever populated by the matching `_enforce(...)` context. A rule whose field is never supplied can never fire. Result — **the action allow-list and the live guard rules are real, but 4 DENY rules are decorative because their field name does not match what the node passes:**

| Rule (file) | `condition.field` | Node passes | Status | Exploitable? |
|---|---|---|---|---|
| `block-untrusted-collection` (data-access) | `qdrant_collection` | `qdrant_collection` | **LIVE** | — |
| `cap-llm-context` (data-access) | `context_char_count` | `context_char_count` | **LIVE** | — |
| `reject-oversized-query`/`reject-empty-query` (data-access) | `query_length` | `query_length` | **LIVE** | — |
| `require-*` / `block-*` peer rules (peer-comms) | `peer_did_verified`, `transport_encrypted`, `peer_circuit_state`, `peer_trust_score`, `peer_execution_ring` | all supplied (`nodes.py:559-571`) | **LIVE** | — |
| `cap-chunk-retrieval` (data-access) | `requested_chunk_count` | `chunk_count` (not this) | **DECORATIVE** | No — `retrieve_local` caps fused chunks at `qdrant_final_k`=10 < 50, so redundant-with-config even if wired |
| `block-credential-leak-in-output` (data-access, ASI-05) | `llm_output` | now passed by `format_response` (task #10) | **RESOLVED → LIVE** | Was decorative; now an enforcing hard-deny control. `format_response` passes `llm_output` to the policy gate, so the rule fires; see note below |
| `block-low-trust-agents` (base) | `agent_trust_score` | never passed | **DECORATIVE** | See Item 2 — also non-functional via the mesh gate |
| `block-code-execution`/`block-filesystem-writes` (base) | `tool_category` | never passed | **DECORATIVE / N/A** | This RAG agent issues no tool calls, so the category never exists to gate |

**Severity:** none of these is a data-path fail-open (OpenFGA per-chunk ReBAC + the LIVE guard rules remain the enforcing controls). `cap-chunk-retrieval` and the `tool_category` rules are redundant/N/A. `block-credential-leak-in-output` was the only one worth wiring as a genuine added control — **now done (task #10):**

> **UPDATE (task #10 — Output-DLP, HARD-DENY):** The credential-leak control is now an ENFORCING control in BOTH solutions. It runs at `format_response` — the single universal output choke point that every terminal route passes through, covering **both** locally-generated and cross-cluster **peer** answers (the peer path is the higher-risk source and would not have been covered by an "after generate_answer" hook, since `generate_answer` never sees peer answers — those arrive via `handle_peer_result → format_response`). Posture is **hard-deny** (team-lead's call): on a credential match the ENTIRE answer is withheld and replaced with a generic safe message — never returned partially redacted, which could leak a regex-evaded fragment. Fail-safe is preserved by TIGHT patterns: structured secret formats + explicit `key/secret/password = value` assignments, so a legitimate answer that merely discusses infra/auth/retention topics — even using the words "secret"/"token"/"password" in prose — is NOT blocked.
> - **AGT** (`agt-federated-rag`): the formerly-decorative `block-credential-leak-in-output` rule is now **LIVE** — `format_response` calls `_enforce("agent.output_check", {"llm_output": answer})`; the rule (priority 950, tightened regex) denies on a match and a new `allow-output-check` rule (priority 100, base-policy) lets clean answers pass. `PermissionError` is caught locally and returns the safe message. So this row moves decorative → **live policy rule** (a cleaner honesty outcome than removing it).
> - **A2A** (`federated-rag`): no policy engine — a self-contained `detect_credentials()` scanner in `format_response` using the **byte-identical** tight pattern set; on a hit it returns the same safe message. (A2A intentionally has no `agent_os`/`agentmesh` dependency; keep the two pattern sets in sync.)
> - Verified: planted AWS `AKIA…`, PEM PRIVATE KEY, OpenAI `sk-…`, Slack `xox…`, JWT `eyJ…`, and `password=`/`api_key:`/`client_secret=` assignments all BLOCKED on both the local-answer and peer-answer paths in both solutions (secret never appears in the returned message); realistic demo-like answers (retention-policy prose, Cilium/ALB topology, financials, "provide your password to the IdP") all pass UNBLOCKED; the error path still returns its generic message; deny-by-default and all other governed actions unaffected.

**Not "fixed" by renaming:** I deliberately did NOT rename `chunk_count`→`requested_chunk_count` to make `cap-chunk-retrieval` "fire" — that would add a redundant gate (retrieve already caps at `qdrant_final_k`=10 < 50). Making a rule appear live without it doing useful work is theater. The remaining decorative rules (`cap-chunk-retrieval`, `agent_trust_score`, `tool_category`) are documented as known-decorative/redundant/N/A, consistent with the Item 2 treatment. (`llm_output` was the one with real value, so it was genuinely wired — see the task #10 update above — rather than left decorative.)

---

## Item 4 — Trust gate fails closed — OK (both, AGT in depth)

**AGT** `mesh/agent_identity.py:verify_peer_identity` (299-359): unknown peer → `(False, 0.0)`; inactive peer → `(False, 0.0)`; any exception → `(False, 0.0)`. Callers enforce the threshold, not the function:
- `mesh/peer_client.py:124-138` — rejects on `not verified` and on `trust_score < settings.agent_trust_threshold`.
- `api/main.py` `/a2a/query` (652-668) and `/tasks/{id}/callback` (808-826) — re-verify the signer, reject below threshold, and reject `signer_did != settings.peer_agent_did`.
- The node also feeds the **real** verification result into the policy context (`nodes.py:553-557`): `peer_did = settings.peer_agent_did or ""`; if empty → `peer_verified, peer_trust = False, 0.0`. So the `peer-comms-policy` DENY rules act on real data, not optimistic constants (Finding #4 in-repo).

**A2A** has no DID layer; its peer trust boundary is the OAuth audience allowlist on token exchange (`auth/token_exchange.py:74-82`, exact-match, fails closed when unconfigured) plus the callback `client_id` allowlist (Item 8). OK for its design.

---

## Item 5 — Approval integrity — OK (both)

Verified end-to-end in `workflow/approval.py` + `workflow/activities.py` + `auth/openfga.py` for **both** solutions:
- **Viewer tuple written ONLY after approval.** `grant_viewer`/`grant_access_in_openfga` (AGT `activities.py:251-266`, A2A `activities.py:198`) is called from exactly one place: `_handle_approved` (`approval.py:163`/`198`). Grepped all call sites — no other writer of the viewer relation; the deny and timeout paths never call it.
- **Pending revoked on BOTH deny AND timeout.** `revoke_pending_in_openfga` (`activities.py`) deletes the `pending_approval` tuple and is invoked by `_handle_denied` (`approval.py:203`/`...`) and `_handle_timeout` (`approval.py:240`/`...`). `grant_access_in_openfga` also revokes pending on approval (`activities.py:264-266`).
- **Pending alone never grants reads.** `decide()` returns `ALLOWED` only on the viewer/editor/owner relation; `pending_approval` maps to `NEEDS_APPROVAL` (AGT `openfga.py:168-185`, A2A `openfga.py:105-116`). `check_auth` routes `NEEDS_APPROVAL` to `start_approval`, never to `generate_answer`.
- `start_approval` writes pending only for `pending_chunk_ids`, never for `denied_chunk_ids` (AGT `nodes.py:443-467`; A2A `nodes.py:334-356`, H3-6). Approval deep-links are HMAC-signed with a bound expiry (`activities.py:_approval_url`); `/approve` verifies the HMAC timing-safely and rejects expired links.

---

## Item 6 — Token isolation — OK (both)

- **User JWT never in LangGraph state.** Both solutions inject the raw token via a module ContextVar (`_user_token_ctx`) in `run_query` before `graph.ainvoke`, and `AgentState` has no token field (A2A `graph.py:157`, `nodes.py:60-71`; AGT `graph.py:196`, `nodes.py:85-92`). The delegated (exchanged) token in A2A is likewise stashed in a ContextVar, not state (`nodes.py:439`, with the explicit "NOT stored in state (C-5)" comment at the return).
- **Never in Temporal history.** A2A `ApprovalInput` carries no token; the H-7 comment (`approval.py:67-72`) documents that `send_a2a_callback` mints a fresh client-credentials/DID-signed token instead of persisting a user-delegated one. AGT's `A2ACallbackInput` carries no token either (`activities.py:106-117`); the callback is DID-signed by the agent.
- **Never in logs.** `user_id` (an OIDC sub) is logged at DEBUG, not INFO (e.g. A2A `nodes.py:196`); token-validation failures log a static string, never `str(e)` (which would contain the JWT) — A2A `api/main.py:395-399`, AGT `api/main.py:368-370`. The cross-cluster transport forwards **no** user JWT at all (Item 7).

---

## Item 7 — Cross-cluster delegation re-checks OpenFGA on the receiving cluster — OK (both)

**AGT** `/a2a/query` (`api/main.py:611-748`): authenticates by Ed25519 signature (no user JWT on this path), then runs the **same governed pipeline** as `/query` with `user_token=""` (`api/main.py:699-705`) and the `user_id` taken from the **signed** payload. That pipeline includes `check_auth` → OpenFGA `batch_decide`, so the delegated user's access to *this* cluster's data is re-decided locally. The peer vouches for identity only; it does not bypass authorization. Outbound side (`mesh/peer_client.py:160-167`) carries `user_id` inside the signed payload and forwards no raw JWT.

**A2A** uses RFC 8693 token exchange (`auth/token_exchange.py`): the peer receives a delegated token scoped to the peer audience (allowlist-validated), and the peer's own `/tasks/send` → `check_auth` → OpenFGA re-decides access on the receiving cluster. The user's original JWT is not forwarded; the exchanged token's `sub` is the user and `act` is the agent.

---

## Item 8 — Peer callback hardening — OK (both)

**A2A** `/tasks/{id}/callback` (`api/main.py:594-652`): caller's JWT `client_id` must be in `peer_agent_client_ids_list` (C-4); an **empty** allowlist rejects ALL callbacks (Q-4, `main.py:615`). The task must carry `metadata.awaiting_peer_callback`, set only when this agent actually delegated to a peer (Finding #3, `main.py:554-555`, `630-636`) — returns 404 (not 403) so it doesn't confirm task existence. Payload is Pydantic-validated → 422 on bad shape.

**AGT** `/tasks/{id}/callback` (`api/main.py:753-866`): cryptographically verifies the `_agentmesh` Ed25519 signature via `verify_signed_message` (against the configured peer public JWK, never the body) — fails closed on missing/invalid signature (401). The DID asserted in the block must equal the cryptographically-verified signer (403 on mismatch). Then registry trust-score gate (403 below threshold), then `signer_did == settings.peer_agent_did` (403 on mismatch), then the AGT policy engine `peer.receive_callback` gate with the **real** verification values (Finding #5, `main.py:835-846`). `/a2a/query` applies the same signature → trust → configured-peer → governed-pipeline chain.

`verify_signed_message` (`mesh/agent_identity.py:239-294`) is the crux and is sound: signature verified against the **trusted-config** peer key (not the message-supplied key), signer DID must match the configured-key DID and the configured peer DID, and any verify error → `(False, None)`. SSRF guard on outbound callbacks restricts the target to the configured peer origin (`activities.py:337-352`).

---

## Files changed (for team-lead to restart + verify)

Both changes are in the **AGT** solution only; both `py_compile` / YAML-parse clean. No backend restarted by me.

1. `agt-federated-rag/agent/policies/data-access-policy.yaml`
   - `defaults.action: allow` → `deny` (+ explanatory comment). Removes the latent fail-open in policy load-order. Re-verified: no behavioral regression for any governed action.
2. `agt-federated-rag/agent/graph.py`
   - Module docstring corrected: removed the false `GovernanceMiddleware` / functional-kill-switch claim; documented the two real fail-closed enforcing layers and the decorative nature of the `agent.graph.invoke` mesh gate. (Docstring-only; no behavior change.)

**Restart note:** the policy YAML is read at worker/API startup (`PolicyEvaluator.load_policies` is cached behind a singleton in `nodes._get_evaluator`), so the cluster-a/b API + worker processes must be restarted to pick up the `data-access-policy.yaml` change. The `graph.py` change is documentation only but will be reloaded on the same restart.

## Open design item (not a code fix — flagged for prioritisation)

An **operator kill-switch** (Item 2) is now implemented and enforcing — a real agentmesh-format policy in `get_mesh()` plus an operator flag (see the Item 2 task #4 UPDATE). What remains a design item is the **automatic** half: a downward self-trust signal that trips the switch on anomalous behaviour without an operator manually setting the flag + restarting. The current lever is deploy-time (env + restart), deliberately keyed on an explicit operator flag rather than self-trust (which starts at 0.5 and only rises, so it can never function as an automatic kill-switch). Tracked here rather than faked with a trust rule that can never correctly fire.
