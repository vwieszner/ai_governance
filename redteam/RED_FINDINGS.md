# RED_FINDINGS.md — Red-team adversarial probe results

_Generated: 2026-06-04 14:40:45 by redteam/run_probes.py_

Targets: A2A (federated-rag) :8000/:8002, AGT (agt-federated-rag) :8010/:8012, OpenFGA :8089, Keycloak :8087.

Verdicts: **DEFENDED** = control rejected the attack as designed; **VULNERABLE** = real bypass/leak (fix at root); **EXPECTED** = correct authorization (not a vuln); **BLOCKED** = could not run (re-run).

## Summary

| Verdict | Count |
|---------|-------|
| DEFENDED | 43 |
| VULNERABLE | 0 |
| EXPECTED | 4 |
| BLOCKED | 0 |

**Real vulnerabilities found: 0**

## All probe results

| Probe | Target | Verdict | Observed | Expected |
|-------|--------|---------|----------|----------|
| P1 no-auth submit | A2A cluster-a | DEFENDED | HTTP 401 '{"detail":"Missing Authorization header"}' | 401/403 (authentication required) |
| P2 alg:none JWT forgery | A2A cluster-a | DEFENDED | HTTP 401 | 401 (algorithm pinned; unsigned token rejected) |
| P3 tampered signature | A2A cluster-a | DEFENDED | HTTP 401 | 401 (signature verification fails) |
| P4 malformed bearer | A2A cluster-a | DEFENDED | HTTP 401 | 401 (reject malformed token) |
| P5 IDOR cross-user task read | A2A cluster-a | DEFENDED | HTTP 404 '{"detail":"Task not found"}' | 404 (deny-by-default ownership; do not confirm existence) |
| P6 unauth task read | A2A cluster-a | DEFENDED | HTTP 401 | 401 |
| P7 ReBAC pending-not-read leakage | A2A cluster-a | EXPECTED | HTTP 200; answer='Processing your query...' | pending-approval message, NO salary data (pending != read) |
| P8 approval HMAC forgery | A2A cluster-a | DEFENDED | HTTP 401 '{"detail":"Invalid or expired approval token"}' | 401 (HMAC verification fails) |
| P9 approval link replay (expired) | A2A cluster-a | DEFENDED | HTTP 401 '{"detail":"Approval link has expired"}' | 401 (expired link rejected before HMAC) |
| P10 A2A callback forgery | A2A cluster-a | DEFENDED | HTTP 403 '{"detail":"Caller is not a recognised peer agent"}' | 403 (caller client_id not in peer allowlist) |
| P14 oversized query DoS | A2A cluster-a | DEFENDED | HTTP 400 | 400/413 (max_query_length enforced before work) |
| P17 secret leakage in public responses | A2A cluster-a | DEFENDED | /health:200; /.well-known/agent-card.json:200 | no private keys / secrets / passwords in responses |
| P1 no-auth submit | A2A cluster-b | DEFENDED | HTTP 401 '{"detail":"Missing Authorization header"}' | 401/403 (authentication required) |
| P2 alg:none JWT forgery | A2A cluster-b | DEFENDED | HTTP 401 | 401 (algorithm pinned; unsigned token rejected) |
| P3 tampered signature | A2A cluster-b | DEFENDED | HTTP 401 | 401 (signature verification fails) |
| P4 malformed bearer | A2A cluster-b | DEFENDED | HTTP 401 | 401 (reject malformed token) |
| P5 IDOR cross-user task read | A2A cluster-b | DEFENDED | HTTP 404 '{"detail":"Task not found"}' | 404 (deny-by-default ownership; do not confirm existence) |
| P6 unauth task read | A2A cluster-b | DEFENDED | HTTP 401 | 401 |
| P7 ReBAC pending-not-read leakage | A2A cluster-b | EXPECTED | HTTP 200; answer='Processing your query...' | pending-approval message, NO salary data (pending != read) |
| P8 approval HMAC forgery | A2A cluster-b | DEFENDED | HTTP 401 '{"detail":"Invalid or expired approval token"}' | 401 (HMAC verification fails) |
| P9 approval link replay (expired) | A2A cluster-b | DEFENDED | HTTP 401 '{"detail":"Approval link has expired"}' | 401 (expired link rejected before HMAC) |
| P10 A2A callback forgery | A2A cluster-b | DEFENDED | HTTP 403 '{"detail":"Caller is not a recognised peer agent"}' | 403 (caller client_id not in peer allowlist) |
| P14 oversized query DoS | A2A cluster-b | DEFENDED | HTTP 400 | 400/413 (max_query_length enforced before work) |
| P17 secret leakage in public responses | A2A cluster-b | DEFENDED | /health:200; /.well-known/agent-card.json:200 | no private keys / secrets / passwords in responses |
| P1 no-auth submit | AGT cluster-a | DEFENDED | HTTP 401 '{"detail":"Missing Authorization header"}' | 401/403 (authentication required) |
| P2 alg:none JWT forgery | AGT cluster-a | DEFENDED | HTTP 401 | 401 (algorithm pinned; unsigned token rejected) |
| P3 tampered signature | AGT cluster-a | DEFENDED | HTTP 401 | 401 (signature verification fails) |
| P4 malformed bearer | AGT cluster-a | DEFENDED | HTTP 401 | 401 (reject malformed token) |
| P7 ReBAC pending-not-read leakage | AGT cluster-a | EXPECTED | HTTP 200; answer='Your request is pending approval. The data owner has been notified and w | pending-approval message, NO salary data (pending != read) |
| P11 AGT /a2a/query unsigned | AGT cluster-a | DEFENDED | HTTP 401 '{"detail":"Invalid or missing AgentMesh message signature"}' | 401 (DID signature required) |
| P12 AGT /a2a/query forged signature | AGT cluster-a | DEFENDED | HTTP 401 '{"detail":"Invalid or missing AgentMesh message signature"}' | 401/403 (signature invalid OR signer != configured peer) |
| P13 AGT callback unsigned | AGT cluster-a | DEFENDED | HTTP 401 '{"detail":"Invalid or missing AgentMesh message signature"}' | 401 (DID signature required) |
| P14 oversized query DoS | AGT cluster-a | DEFENDED | HTTP 400 | 400/413 (max_query_length enforced before work) |
| P17 secret leakage in public responses | AGT cluster-a | DEFENDED | /health:200; /.well-known/agent-card.json:200; /identity:200 | no private keys / secrets / passwords in responses |
| P1 no-auth submit | AGT cluster-b | DEFENDED | HTTP 401 '{"detail":"Missing Authorization header"}' | 401/403 (authentication required) |
| P2 alg:none JWT forgery | AGT cluster-b | DEFENDED | HTTP 401 | 401 (algorithm pinned; unsigned token rejected) |
| P3 tampered signature | AGT cluster-b | DEFENDED | HTTP 401 | 401 (signature verification fails) |
| P4 malformed bearer | AGT cluster-b | DEFENDED | HTTP 401 | 401 (reject malformed token) |
| P7 ReBAC pending-not-read leakage | AGT cluster-b | EXPECTED | HTTP 200; answer='The requested information is on the remote cluster and requires approval | pending-approval message, NO salary data (pending != read) |
| P11 AGT /a2a/query unsigned | AGT cluster-b | DEFENDED | HTTP 401 '{"detail":"Invalid or missing AgentMesh message signature"}' | 401 (DID signature required) |
| P12 AGT /a2a/query forged signature | AGT cluster-b | DEFENDED | HTTP 401 '{"detail":"Invalid or missing AgentMesh message signature"}' | 401/403 (signature invalid OR signer != configured peer) |
| P13 AGT callback unsigned | AGT cluster-b | DEFENDED | HTTP 401 '{"detail":"Invalid or missing AgentMesh message signature"}' | 401 (DID signature required) |
| P14 oversized query DoS | AGT cluster-b | DEFENDED | HTTP 400 | 400/413 (max_query_length enforced before work) |
| P17 secret leakage in public responses | AGT cluster-b | DEFENDED | /health:200; /.well-known/agent-card.json:200; /identity:200 | no private keys / secrets / passwords in responses |
| P15 direct OpenFGA (no key) | OpenFGA :8089 | DEFENDED | HTTP 401 '{"code":"bearer_token_missing","message":"missing bearer token"}\n' | 401 (preshared-key auth) |
| P16 client_credentials secret guess | Keycloak agent-cluster-a | DEFENDED | HTTP 401 | 400/401 (bad client credentials) |
| P16 client_credentials secret guess | Keycloak agent-agt-a | DEFENDED | HTTP 401 | 400/401 (bad client credentials) |

## Round 2 — deeper vectors

_Generated: 2026-06-04 14:42:35 by redteam/run_probes_r2.py_

Round 1 was clean (43 DEFENDED / 0 VULNERABLE / 4 EXPECTED). Round 2 goes deeper: SSRF, JWT audience confusion + cross-cluster/cross-solution token reuse, kid/alg confusion, signed-message replay, direct OpenFGA tuple writes, rate-limit subject bypass, AGT governance-gate coverage, and prompt injection.

Extra verdict buckets this round: **FINDING** = a real weakness that is bounded / config-rooted / not directly exploitable over HTTP from outside — a blue-team note, NOT an open bypass. **EVIDENCE** = a supporting observation for a FINDING (counted separately so the FINDING count reflects DISTINCT findings, not double-counted rows).

### Round 2 summary

| Verdict | Count |
|---------|-------|
| DEFENDED | 25 |
| VULNERABLE | 0 |
| EXPECTED | 0 |
| FINDING | 2 |
| EVIDENCE | 1 |
| BLOCKED | 0 |

**Open bypasses (VULNERABLE): 0** · **Bounded findings (FINDING): 2**

### FINDING — real but bounded (2 distinct, blue-team notes)
- **R2-2a audience confusion (THE finding)** (Keycloak rag-ui): ONE finding: rag-ui mints a single token whose aud lists all 4 backend client_ids (test-enablement audience mappers), so one token authenticates to every cluster of BOTH solutions (confirmed by R2-2b). Per-cluster audience isolation is not enforced at the IdP. App-layer aud checks are CORRECT (token_validator/token_exchange); A2A even ships exchange_token() with an audience allowlist — which only makes sense if direct cross-cluster reuse is meant to be impossible. BOUNDED: no privilege gain (see R2-2b note). Fix is IdP audience hygiene, not app code.
  - observed: `aud=['agent-cluster-b', 'agent-cluster-a', 'agent-agt-b', 'agent-agt-a', 'account']`
  - repro: `.venv\Scripts\python.exe -c "import sys;sys.path.insert(0,'redteam');import probe_lib as pl;print(pl.decode_claims(pl.get_token('alice'))['aud'])"`
- **R2-8 prompt injection in authorized chunk** (both solutions): LOW severity / defence-in-depth: bounded by per-chunk ReBAC (can't exfiltrate unauthorized chunks). Hardening: delimiter/escape context, output scanning. Not HTTP-exploitable externally (no user-facing ingest).
  - observed: `no ingestion path is user-reachable in this deployment; LLM sees only OpenFGA-authorized chunks; prompt uses a fixed 'use ONLY context' system msg`

- _(evidence)_ **R2-2b cross-target reuse (aggregate)** (cross-solution): EVIDENCE for the one audience finding (R2-2a). BOUNDED: no privilege gain — auth acceptance alone grants nothing; every path re-enforces authz on sub (OpenFGA), azp (A2A callback allowlist), or DID signature (AGT peer endpoints). Fix is IdP audience hygiene (scope rag-ui tokens per cluster / use RFC8693 token-exchange), not an app-code bypass.
  - observed: `authenticated to ['A2A cluster-a', 'A2A cluster-b', 'AGT cluster-a', 'AGT cluster-b']; per-target: A2A cluster-a=HTTP 404(auth-PASS); A2A cluster-b=HTTP 404(auth-PASS); AGT cluster-a=HTTP 400(auth-PASS); AGT cluster-b=HTTP 400(auth-PASS)`

### Round 2 — all probe results

| Probe | Target | Verdict | Observed | Expected |
|-------|--------|---------|----------|----------|
| R2-2a audience confusion (THE finding) | Keycloak rag-ui | FINDING | aud=['agent-cluster-b', 'agent-cluster-a', 'agent-agt-b', 'agent-agt-a', 'account'] | aud scoped to ONE cluster the user is talking to |
| R2-2b cross-target reuse (aggregate) | cross-solution | EVIDENCE | authenticated to ['A2A cluster-a', 'A2A cluster-b', 'AGT cluster-a', 'AGT cluster-b']; per-target: A | a token should authenticate only to its intended audience |
| R2-3 RS256->HS256 alg sub | A2A cluster-a | DEFENDED | HTTP 401 | 401 (algorithm pinned / kid must exist with matching alg) |
| R2-3 RS256->HS256 alg sub | A2A cluster-b | DEFENDED | HTTP 401 | 401 (algorithm pinned / kid must exist with matching alg) |
| R2-3 RS256->HS256 alg sub | AGT cluster-a | DEFENDED | HTTP 401 | 401 (algorithm pinned / kid must exist with matching alg) |
| R2-3 RS256->HS256 alg sub | AGT cluster-b | DEFENDED | HTTP 401 | 401 (algorithm pinned / kid must exist with matching alg) |
| R2-3 unknown kid | A2A cluster-a | DEFENDED | HTTP 401 | 401 (algorithm pinned / kid must exist with matching alg) |
| R2-3 unknown kid | A2A cluster-b | DEFENDED | HTTP 401 | 401 (algorithm pinned / kid must exist with matching alg) |
| R2-3 unknown kid | AGT cluster-a | DEFENDED | HTTP 401 | 401 (algorithm pinned / kid must exist with matching alg) |
| R2-3 unknown kid | AGT cluster-b | DEFENDED | HTTP 401 | 401 (algorithm pinned / kid must exist with matching alg) |
| R2-1 SSRF A2A push url | A2A cluster-a | DEFENDED | submit status TIMEOUT; url is stored but never fetched | backend must not dereference a user-supplied callback URL |
| R2-1 SSRF A2A push url | A2A cluster-b | DEFENDED | submit status TIMEOUT; url is stored but never fetched | backend must not dereference a user-supplied callback URL |
| R2-1 SSRF AGT callback url | AGT (both) | DEFENDED | callback_url is server-built from settings.agent_url; /a2a/query requires a peer DID signature to ev | no user-controllable outbound URL |
| R2-4 signed /a2a/query replay (forged) | AGT cluster-a | DEFENDED | 1st=401 2nd=401 (forged sig rejected pre-freshness) | signature rejected (401) before the freshness/nonce check |
| R2-4 signed /a2a/query replay (forged) | AGT cluster-b | DEFENDED | 1st=401 2nd=401 (forged sig rejected pre-freshness) | signature rejected (401) before the freshness/nonce check |
| R2-4 signed message anti-replay (remediated by #8) | AGT (both) | DEFENDED | ts+nonce are now signed (sign_outbound_message); verify_signed_message -> _check_freshness_and_nonce | signed inter-agent messages should be single-use (nonce/timestamp + cache) |
| R2-5 OpenFGA tuple WRITE (no key) | OpenFGA A2A store | DEFENDED | HTTP 401 '{"code":"bearer_token_missing","message":"missing bearer tok' | 401 (preshared-key auth) |
| R2-5 OpenFGA tuple WRITE (wrong key) | OpenFGA A2A store | DEFENDED | HTTP 401 '{"code":"unauthenticated","message":"unauthenticated"}\n' | 401/403 (bad preshared key) |
| R2-5 OpenFGA tuple WRITE (no key) | OpenFGA AGT store | DEFENDED | HTTP 401 '{"code":"bearer_token_missing","message":"missing bearer tok' | 401 (preshared-key auth) |
| R2-5 OpenFGA tuple WRITE (wrong key) | OpenFGA AGT store | DEFENDED | HTTP 401 '{"code":"unauthenticated","message":"unauthenticated"}\n' | 401/403 (bad preshared key) |
| R2-5 user-facing tuple-write path | both solutions | DEFENDED | none — writes occur only server-side in start_approval (set_pending_approval) and seed scripts | no user-reachable tuple-write |
| R2-6 rate-limit subject spoof (no sub) | A2A cluster-a | DEFENDED | HTTP 401 | 401 before any rate-limit keying (sub is signed, immutable) |
| R2-6 rate-limit subject spoof (no sub) | A2A cluster-b | DEFENDED | HTTP 401 | 401 before any rate-limit keying (sub is signed, immutable) |
| R2-6 rate-limit subject spoof (no sub) | AGT cluster-a | DEFENDED | HTTP 401 | 401 before any rate-limit keying (sub is signed, immutable) |
| R2-6 rate-limit subject spoof (no sub) | AGT cluster-b | DEFENDED | HTTP 401 | 401 before any rate-limit keying (sub is signed, immutable) |
| R2-7 AGT governance gate coverage | AGT (both) | DEFENDED | every LangGraph node calls _enforce before work; /a2a/query and /callback also _enforce after DID au | all data/action paths pass the AGT policy gate |
| R2-9 approval tuple-write race | both solutions | DEFENDED | pending-tuple write is idempotent (400 'already exists' swallowed); workflow start catches WorkflowA | no authorization race; concurrent writes converge safely |
| R2-8 prompt injection in authorized chunk | both solutions | FINDING | no ingestion path is user-reachable in this deployment; LLM sees only OpenFGA-authorized chunks; pro | injection cannot widen data access beyond user's authz |
