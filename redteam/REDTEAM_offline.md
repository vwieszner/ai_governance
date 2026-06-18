# Red-team — FR-6 offline delivery / inbox

**Target:** `outcome_store.py`, `api/main.py` (`GET /inbox`, `POST /inbox/{id}/ack`,
`POST /tasks/{id}/callback`, `GET /tasks/{id}/result`), `workflow/activities.py`
(`notify_user_of_decision`, `send_a2a_callback`).
**Method:** runnable probes against the REAL functions/endpoints with a stubbed async Redis
(same harness as `tests/test_offline.py`). Probe file: `redteam/probe_offline.py`
(11 probes, all green — attack probes assert SUCCESS, control probes assert DEFENDED).
**Run:** `cd agt-federated-rag && ../.venv/Scripts/python.exe -m pytest ../redteam/probe_offline.py -v`

| # | Attack | Verdict | Severity |
|---|--------|---------|----------|
| 1 | IDOR — read/ack another user's inbox | **DEFENDED** | — |
| 2 | Stale-data leak (answer served without fresh authz) | **DEFENDED** | — |
| 3 | Cross-division callback abuse (no task↔peer binding) | **VULNERABLE** | Medium (insider/peer) |
| 3b | Denial confusion (`decision` vs `state`) | **NEEDS-HARDENING** | Low–Medium |
| 3c | Callback replay overwrites a terminal/acked outcome | **NEEDS-HARDENING** | Low |
| 4 | Badge / ack abuse | **NEEDS-HARDENING** (cosmetic) | Low |
| 4 | Denial surfacing as completed | **DEFENDED** | — |

---

## TOP FINDING — Attack 3: `task_callback` has no task↔delegate binding (VULNERABLE, Medium)

`api/main.py::task_callback` (lines 1240–1393) authenticates the *signature* of a peer
(`verify_signed_message` → trusted DID, trust-gated — that gate is real, see control probe
`test_A3a_unauth_caller_cannot_seed`), **but never checks that the `task_id` in the URL was
actually delegated to *that* signing peer** (or delegated at all). It loads the local task by
`task_id`, reads `_owner_id` from that record, and writes the outcome to that principal's store:

```
rec = await _load_task(task_id)            # any task in THIS division's Redis
requester = rec.get("_owner_id", "")       # victim chosen by the task record, not the attacker
... outcome_store.put(principal_id=requester, task_id=task_id, ...)   # lands
```

Contrast with `/a2a/query` (FR-3.6), which binds the user assertion to a recipient DID and
re-authorizes per signer. The **delivery/callback path applies none of that binding.**

**Consequence (insider / lateral, NOT unauthenticated):** any ONE trusted federation peer (a
compromised or over-scoped peer) can drive an outcome write into *any* requester's store for
*any* `task_id` it can guess/enumerate — including:

- **DoS on delivery (demonstrated, `test_A3a_dos_overwrite_suppresses_victims_pending_outcome`):**
  a signed *denial* callback for a victim's legitimately-parked task OVERWRITES the victim's
  `pending` (regenerate-and-deliver) record with a terminal `denied`. The victim never receives
  their real answer at next login — silently suppressed by a peer with no claim to that task.
  `outcome_store.put` overwrites by `task_id` with no guard.
- **Inbox injection / spam (demonstrated, `test_A3a_trusted_peer_injects_outcome_into_unfederated_task`):**
  the same peer can inject a `pending` record + badge bump onto a *purely-local* task that was
  never federated. No data leak (the answer still regenerates under the OWNER's own authz at
  `/inbox`, so the owner only ever sees their own re-authorized answer) — but it is unsolicited
  inbox/badge noise the requester cannot attribute.

**Why not High:** the attacker cannot choose an arbitrary victim principal (it's whatever
`_owner_id` the local record holds) and cannot exfiltrate data (regenerate-at-delivery re-auths
under the owner). The break is **integrity/availability of the delivery channel by a trusted
peer**, not confidentiality and not an external attacker.

**One-line fix:** on the callback path, bind the task to its delegate — record the target peer
DID at delegation time and reject the callback unless `sender_did` equals the task's recorded
`peer_did` (and the task is actually a federated/outbound task), before writing any outcome.

---

## Attack 3b — denial confusion: `decision="denied"` + `state="completed"` → deliverable (NEEDS-HARDENING)

`task_callback` line 1362: `if decision == "approved" or state == "completed":` → writes a
**deliverable** `pending` (regenerate) record; else a `denied` record. The **OR** means a peer
whose `decision` field says *denied* but whose `status.state` says *completed* lands in the
deliver branch. Demonstrated: `test_A3b_denied_decision_with_completed_state_becomes_deliverable`
— a `denied` decision produced a `pending` (deliverable) record and the denial message was
dropped (`answer_or_message == ""`).

Self-limiting because delivery still re-auths at `/inbox` (so it won't leak data the owner can't
see), but it is a contradictory-signal handling bug: the two fields can disagree and the more
permissive one wins. **Fix:** treat the outcome as deliverable only when BOTH agree
(`decision == "approved" and state == "completed"`), else record denied.

## Attack 3c — callback replay resurrects an acknowledged outcome (NEEDS-HARDENING, Low)

No nonce/idempotency guard on the callback and `outcome_store.put` always resets
`acknowledged=False`. A replayed (or peer-retried) signed callback for an already-acked task
overwrites the record back into the unacknowledged view and re-bumps the unseen badge.
Demonstrated: `test_A3c_callback_replay_resurrects_acknowledged_outcome`. Annoyance-grade
(re-notification), not a data break. **Fix:** make the callback idempotent — skip the store
write if a terminal/acked record already exists for that `task_id`, or carry a callback nonce.

## Attack 4 — badge accounting (NEEDS-HARDENING, cosmetic)

`bump_badge` increments unconditionally and is fired on park, on resolution (same-division
`notify_user_of_decision`), and on every cross-division callback — but a single outcome can be
bumped multiple times while `acknowledge` decrements once. Result: a phantom positive badge
count with an empty inbox view (`test_A4_badge_underflow_via_double_ack_or_stray_ack`: badge=1,
view empty). No security impact (the durable records are the source of truth; the decr is
floored at 0 so no underflow). **Fix:** derive the badge from the unacknowledged record count
rather than maintaining a separate counter, or only bump on first write per `task_id`.

---

## DEFENDED (verified, not assumed)

- **Attack 1 — IDOR.** `GET /inbox` and `POST /inbox/{id}/ack` key strictly on the caller's
  namespaced principal (`principal(claims)` = `email|issuer-ns`, never raw `sub`). Bob cannot
  read or ack Alice's outcomes even sharing a division/store
  (`test_A1_inbox_idor_blocked`, `test_A1b_ack_idor_is_scoped_to_caller`). The division-namespaced
  key (`outcome_store._key`) plus per-issuer namespace also blocks cross-division principal
  confusion. `GET /tasks/{id}/result` enforces `rec["_owner_id"] == user_id` (line 844).
- **Attack 2 — stale-data leak.** No answer is ever persisted for a `completed` record
  (`put` forces `stored_message=""`, verified `test_A2b_stored_record_never_holds_a_completed_answer`);
  `GET /inbox` re-runs the governed pipeline `check_only` at delivery, so a grant revoked between
  decision and login flips the SAME record to `denied` with no answer field
  (`test_A2_inbox_regenerate_and_revoke_flips_to_denied`). Regenerate-at-delivery is genuinely
  re-authorizing every time. **No stale leak found.**
- **Retention.** `OUTCOME_RETENTION_SECONDS = 30 days`, re-set on every write/ack, and strictly
  greater than `task_ttl_seconds` — there is no short TTL that would drop the outcome while the
  user is offline. (Covered by the suite's `test_retrievable_next_login_no_ttl_cap`.)
- **Denied-as-completed (terminal records).** A terminal `denied` record (no question) surfaces
  as `denied` with no `answer` and does NOT re-run the pipeline
  (`test_A4b_denied_record_never_surfaces_as_completed`).
- **Unsigned callback cannot seed an inbox.** An unverified signature is rejected 401 before any
  store write (`test_A3a_unauth_caller_cannot_seed`) — the inbox cannot be seeded by an
  unauthenticated caller; Attack 3 strictly requires *trusted-peer* status.

---

## Skeptic's note

The one true VULNERABLE (Attack 3) is gated behind trusted-peer status, so it is an
insider/lateral-movement finding, not a remote/unauthenticated one — sevity Medium, not High.
Its confidentiality impact is null (regenerate-at-delivery saves it); the real damage is
**integrity/availability of a victim's delivery** (suppress/forge outcomes) by a peer that
should have no authority over that task. 3b/3c/4 are hardening items that the regenerate-at-
delivery design already neutralizes for data exposure. Attacks 1, 2, and retention are solidly
DEFENDED and I could not break them.
