# RED_FINDINGS.md — Red-team adversarial probe results

_Generated: 2026-06-04 00:12:39 by redteam/run_probes.py_

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
