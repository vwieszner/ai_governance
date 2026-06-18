# Red-Team — Governance-Edge Controls

**Scope:** the four new governance-edge controls — runtime kill-switch (FR-4.3),
`GET /audit` admin export (FR-8.1/NFR-9), CRL revocation at the mTLS handshake
(NFR-3), and grant expiry (FR-7.1).
**Method:** adversarial probes that drive the **real code** (`redteam/probe_govedge.py`),
plus the existing suite (`test_killswitch`, `test_audit_endpoint`, `test_transport`,
`test_lifecycle`). Verdict discipline: VULNERABLE only when a probe actually drove the
code into the unsafe state; otherwise DEFENDED. Defaults to DEFENDED, no speculation.

**Run:**
```
cd agt-federated-rag
PYTHONIOENCODING=utf-8 ../.venv/Scripts/python.exe ../redteam/probe_govedge.py
```
**Result:** 17 probes — **15 DEFENDED, 2 NEEDS-HARDENING, 0 VULNERABLE.**
Existing suite for the four files: **38 passed.**

---

## Verdicts by attack goal

| # | Attack goal | Verdict | Notes |
|---|---|---|---|
| 1 | Kill-switch bypass | **DEFENDED** | Fail-closed on Redis error; both entrypoints guarded; settings-override always-on; per-division key. |
| 2 | `/audit` authz bypass | **DEFENDED** (+1 documented residual) | Non-admin 403; division-scoped; tamper (field-edit + tail-truncation) flagged `verified=false`. Residual: keyless chain + local-only anchor → host-level lock-step rewrite. |
| 3 | CRL bypass | **DEFENDED** (+1 deployment caveat) | Revoked cert rejected at the real handshake (helper + production serving path); refresh works; missing-CRL fails loud; cafile association correct. Caveat: `require_mtls` with no CRL has no revocation gate (by design). |
| 4 | Expiry bypass (FR-7.1) | **DEFENDED** | `ttl>0` → time-bound `grant_viewer_until` only; expiry basis identical to `check()`'s `current_time` (tz-aware UTC ISO-8601); `current_time` injected per request; post-expiry re-ask → `NEEDS_APPROVAL`. |

---

## GOAL 1 — Kill-switch bypass → DEFENDED

Attacked the classic fail-open windows. All held:

- **Redis fail-OPEN on the engaged-check (1a) — DEFENDED.** Stubbed `_get_redis` to a
  client whose `GET` raises (store outage). `_runtime_kill_switch_engaged()` returns
  **True** (engaged) — `api/main.py:301-305` catches the exception and fails **closed**.
  A degraded store cannot silently lift a halt.
- **Single-entrypoint gap (1b) — DEFENDED.** Drove the real `query()` and `a2a_query()`
  handlers with the flag engaged. Both raise **503 before any work** — `/query` at
  `main.py:655` (before auth/rate-limit/body-parse/`run_query`), `/a2a/query` at
  `main.py:1060` (before signature verification: with verify stubbed to fail, an engaged
  switch still yields 503, not 401, proving the kill-check fires first).
- **Settings-vs-runtime confusion (1c) — DEFENDED.** With the runtime Redis flag clear but
  `settings.agent_kill_switch_engaged=True`, the check returns True (`main.py:296`). The
  deploy-time override is always-on; the admin endpoint reports `effective_engaged`
  combining both.
- **Division-scope confusion (1d) — DEFENDED.** A flag under `agt:killswitch:beta` does
  **not** halt division `alpha`; engage/disengage and the engaged-check all read
  `settings.division_id` at call time and only touch this division's key. An attacker
  cannot set another division's key without that division's Redis/admin token.

No race exploitable: the check runs once at handler entry, before work; there is no
window where an engaged switch is observed as disengaged for the same request.

## GOAL 2 — `/audit` authz bypass → DEFENDED (one documented residual)

- **Role-claim confusion (2a) — DEFENDED.** `_is_division_admin` (`main.py:446`) returns
  **False** for all six non-admin shapes probed: `realm_access.roles` without the role;
  the role hiding under `resource_access` (not consulted, correctly); a bare top-level
  `roles`; no role claims; `realm_access` not a dict; a substring near-match
  (`division-admin-readonly`). Legit `realm_access.roles=[division-admin]` and
  `groups=[division-admin]` both pass. Fail-closed.
- **Non-admin reach (2b) — DEFENDED.** A valid member token through the real
  `get_audit → _require_admin` path is refused **403**.
- **Cross-division read (2c) — DEFENDED.** An `alpha` admin export returns only
  `alpha_*.jsonl`; `beta`'s seeded `peer_secret` entries are absent.
  `read_division_chain` globs `{division}_*.jsonl` scoped to `settings.division_id`
  (`audit_log.py:348`) — NFR-2 isolation holds.
- **Tampered chain reported verified=true (2d) — DEFENDED.** A field edit
  (`alice|ns`→`mallory|ns`) is caught by hash recompute; a tail-truncation is caught by
  the anchor cross-check. Both → `verified:false`, still HTTP 200 (the admin SEES the
  break, no 500).

### NEEDS-HARDENING (documented residual) — host-level lock-step rewrite (2e)

The hash chain is a **keyless** SHA256 (`audit_log.py:47`, no HMAC secret), and the
default anchor sink is a **local** sibling file (`*.anchor.jsonl`; `AUDIT_ANCHOR_URL`
empty by default). I forged a *fully valid* replacement chain from genesis — substituting
`alice|ns`→`mallory|ns` and inserting a fabricated `audit_clean` entry — and rewrote the
local anchor to match the new head. `GET /audit` reports **`verified: true`** and serves
the forged entries as authentic.

- **Severity:** Medium. Requires **host/filesystem compromise of the division's audit
  volume** (write access to both the chain and the local anchor). It does **not** break
  the chain's intended threat model (it detects *accidental* corruption, single-file
  tamper, internal deletion/reorder, and tail truncation) — but it is worth stating
  plainly that local-anchor tamper-evidence is not tamper-*proof* against root.
- **Not a new bug:** `audit_log.py:55-62` itself states a local chain "cannot detect …
  an attacker who owns the file" and that the real defense is a remote sink.
- **Fix:** set `AUDIT_ANCHOR_URL` to a remote append-only collector so the head the
  attacker cannot reach diverges from a rewritten local chain (`_anchor_head`,
  `audit_log.py:112-117` already POSTs there when set). Optionally key the chain with an
  HMAC whose secret is not co-located with the log. **Repro:** probe 2e.

*(Minor robustness note, not a vuln: if an operator sets `recognized_groups` to an
allowlist that omits `division-admin`, an admin presenting the role via the **groups**
claim is filtered out by `extract_groups` and denied — fail-closed. The `realm_access`
path is unaffected, so admins keep working; just don't rely solely on the groups path
when an allowlist is configured.)*

## GOAL 3 — CRL bypass → DEFENDED (one deployment caveat)

All proven via **real MemoryBIO TLS handshakes** (the technique CPython's own ssl tests use):

- **Revoked cert at the handshake (3a) — DEFENDED.** A CA-signed-but-revoked client cert
  **fails the handshake** against a CRL-configured `server_context`
  (`VERIFY_CRL_CHECK_LEAF`, `mtls.py:223-224`).
- **Stale cache / no refresh (3b) — DEFENDED.** The same cert handshakes before its serial
  is on the CRL and is **rejected after** the CRL is republished at the same path — the
  mtime-keyed bundle cache (`load_crl_bundle`, `mtls.py:190-204`) refreshes without a
  restart.
- **Missing-CRL fail-open (3c) — DEFENDED.** A configured-but-absent CRL path raises
  `FileNotFoundError` (fail **loud**, `mtls.py:190`) rather than silently building a
  no-revocation context.
- **cadata-vs-cafile gotcha (3d) — DEFENDED.** With CRL checking on, an **unrevoked** cert
  still handshakes — proving the CRL is associated to its issuer via `cafile` (the
  documented gotcha — loading via `cadata` would make OpenSSL reject *every* cert — is
  avoided).
- **Production serving path (3e) — DEFENDED.** Bypassed the unit helper: built the real
  `tls_serving_kwargs` for `require_mtls + TLS_CRL_FILE`, invoked the returned
  `ssl_context_factory`, and confirmed **that** served context rejects the revoked cert at
  the handshake. The wiring an operator actually gets is CRL-enforcing.

### NEEDS-HARDENING (deployment caveat, documented) — mTLS without a CRL (3f)

When `require_mtls=true` but **no** `TLS_CRL_FILE` is configured, `tls_serving_kwargs`
returns plain `ssl_cert_reqs=CERT_REQUIRED` with **no revocation gate**
(`mtls.py:282-287`). A revoked-yet-CA-signed cert would be **accepted** — mTLS and CA
trust still enforced, but revocation is not.

- **Severity:** Low. This is the documented backward-compatible posture
  (`mtls.py:36-37`, PROJECT_STATUS M7 row). It is not a silent downgrade *of CRL* — it is
  the absence of CRL when revocation was never wired.
- **Operational requirement for NFR-3:** operators MUST set `TLS_CRL_FILE` to get
  revocation; the **nginx-edge** production mode additionally needs `ssl_crl` wired at the
  proxy (PROJECT_STATUS already flags this). OCSP remains deferred (needs a responder).
- **Repro:** probe 3f.

## GOAL 4 — Expiry bypass (FR-7.1) → DEFENDED

- **TTL wiring + basis (4a) — DEFENDED.** With `approval_grant_ttl_seconds=3600`,
  `grant_access_in_openfga` calls **only** `grant_viewer_until` (never the permanent
  `grant_viewer`); the expiry is a tz-aware **UTC ISO-8601** timestamp ~`now+ttl`, in the
  future. Critically it uses `datetime.now(timezone.utc).isoformat()`
  (`activities.py:281`) — **the same basis** `check()` supplies as `current_time`
  (`openfga.py:168`), so the OpenFGA condition `current_time < expiry` compares
  like-for-like. **No naive-vs-aware mismatch.** (The host's local TZ is UTC+2; I verified
  `now(timezone.utc)` returns true UTC, so the expiry that looked "in the past" against the
  local-time log line is correct in UTC.)
- **Stale reuse / re-ask (4b) — DEFENDED.** `check()` injects `current_time` into the
  request context on **every** call (confirmed by capturing the `ClientCheckRequest`:
  `context` keys = `['current_time']`), so expiry is evaluated live per request — not from
  a snapshot. A post-expiry state (viewer no longer allowed, `pending_approval` remains)
  drives `decide()` to **NEEDS_APPROVAL**, so re-asking a lapsed grant re-enters approval
  rather than reusing stale access. No timestamp-basis trick, no stale-grant replay.

---

## Top finding

The four controls are **genuinely fail-closed** on the error paths that usually break them
(Redis outage, missing CRL, tampered/truncated chain, expired grant) — 0 VULNERABLE across
17 adversarial probes. The single security-relevant residual is the **audit chain's
keyless SHA256 + local-only anchor**: a host-level attacker who rewrites the chain and the
local anchor in lock-step gets `verified:true`. This is a known, code-documented limit, not
a regression — close it by pointing `AUDIT_ANCHOR_URL` at a remote append-only collector
(and consider HMAC-keying the chain with an off-host secret). The CRL "no-revocation when
unconfigured" item is a deployment requirement (set `TLS_CRL_FILE`; wire `ssl_crl` at the
nginx edge), not a flaw in the gate itself.
```
Probes: redteam/probe_govedge.py   |   17 probes: 15 DEFENDED, 2 NEEDS-HARDENING, 0 VULNERABLE
Existing suite (4 files): 38 passed
```
