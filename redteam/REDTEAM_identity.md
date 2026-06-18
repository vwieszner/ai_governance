# Red-team: FR-3.6 cross-division user identity

**Scope:** `mesh/peer_client.py` (`_bind_user_assertion`, `call_peer_agent`),
`auth/token_validator.py` (`validate_cross_division_assertion`, `assertion_principal`,
`principal`), `api/main.py` `a2a_query`, `mesh/agent_identity.py` (envelope
signing/verify, trust map), `tests/test_assertion.py`.

**Method:** probe `redteam/probe_identity.py` exercises the REAL functions with real
Ed25519 identities (`AgentIdentity.create`), monkeypatching only the module-global
`settings` (the trust map) exactly as `tests/test_mesh.py` does — no source edits, no
network. A finding is VULNERABLE only where the probe demonstrably gets a forged/invalid
input ACCEPTED.

**Threat actor for assertion-content attacks:** a *compromised-but-trusted peer* (or
anyone who has compromised one). This is the actor the assertion validation exists to
constrain — the envelope is validly DID-signed, so signature/replay controls do not help;
the only thing standing between the attacker and impersonation is
`validate_cross_division_assertion`. The assertion is attacker-controlled JSON.

---

## Verdict summary

| # | Attack | Verdict |
|---|--------|---------|
| 1 | Assertion forgery (within signer's own issuer namespace) | DEFENDED (by design) |
| 2 | Audience confusion / recipient-binding bypass | DEFENDED |
| 3 | Replay (envelope) | DEFENDED |
| 4 | **Expiry bypass (`exp = Infinity` / `1e400` / `NaN`)** | **VULNERABLE (High)** |
| 5 | Cross-issuer spoof | DEFENDED |
| 6 | Signer-binding bypass | DEFENDED |
| 7 | Envelope-signature bypass (tamper after signing) | DEFENDED |
| — | Untrusted-signer envelope (bonus) | DEFENDED |

---

## 4. Expiry bypass — VULNERABLE (High) — DEMONSTRATED

**The break.** `validate_cross_division_assertion` (token_validator.py:362-370) guards
`exp` like this:

```python
raw_exp = assertion.get("exp")
if not isinstance(raw_exp, (int, float)) or isinstance(raw_exp, bool) or raw_exp <= 0:
    raise ValueError("assertion is missing a valid 'exp' ...")
current = time.time() if now is None else now
if current > float(raw_exp) + _ASSERTION_EXP_SKEW_SECONDS:   # 60s skew
    raise ValueError("assertion expired ...")
```

`float('inf')` and `float('nan')` are `float`, are not `bool`, and `inf <= 0` /
`nan <= 0` are both `False` → they pass the type guard. Then the expiry comparison
`current > inf + 60` is `current > inf` → always `False`; `current > nan` → always
`False`. **Both checks pass, so the assertion never expires.** This directly violates the
function's own contract ("A missing/0/non-numeric `exp` is rejected (no unbounded-lifetime
assertions)") and the module docstring ("EXPIRY — short `exp` ... a passed/missing exp is
rejected").

**Reachability is real, not theoretical.** The `/a2a/query` handler parses the body with
`payload = await request.json()` (api/main.py:1069). Starlette's `Request.json()` is
`json.loads(body)` with **default** settings, and Python's `json.loads` accepts the
non-standard tokens `Infinity`, `-Infinity`, `NaN`, **and** a finite-looking number that
overflows, e.g. `1e400`, which it returns as `float('inf')`. So a compromised peer simply
puts a valid-looking JSON number in the assertion:

```json
{ "iss":"<peer's bound issuer>", "email":"ceo@example.com", "email_verified":true,
  "sub":"x", "aud":"<this division's DID>", "exp": 1e400 }
```

signs the envelope (it is a trusted peer — it can), and the receiver accepts a
**never-expiring** cross-division assertion.

**Demonstrated repro** (exact path `/a2a/query` takes: wire JSON → `json.loads` →
`validate_cross_division_assertion`):

```
wire bytes the peer sends inside the signed envelope:
   {"iss": "http://alpha/realms/rag", "email": "ceo@example.com", ... , "exp": 1e400}
parsed exp = inf (type float)
ACCEPTED even 1000 years in the future -> ceo@example.com|972bab68c05d8e69
```

Run: `PYTHONPATH=.../agt-federated-rag .venv/Scripts/python.exe redteam/probe_identity.py`
(see attack-4 block — `exp=Infinity` and `exp=NaN` both print `!!! ACCEPTED`, while the
legitimate guards for `0`/`True`/`"string"`/missing/past all correctly reject).

**Severity: High.** Defeats one of the three named FR-3.6 bindings entirely. The short
`exp` is the control that bounds how long a captured/forwarded assertion stays usable
("bounded acceptance even inside the envelope window"). With `exp=inf` an assertion
captured by a downstream component, leaked in a log, or stockpiled by the compromised peer
is usable indefinitely — the expiry layer collapses to "forever." The envelope's ±5-min
ts/nonce window still bounds *envelope* replay, but the assertion's own lifetime bound —
the second, independent layer the design advertises — is gone.

**One-line fix direction.** Require the value to be *finite*: add `math.isfinite(raw_exp)`
to the guard, e.g.
`if not isinstance(raw_exp,(int,float)) or isinstance(raw_exp,bool) or not math.isfinite(raw_exp) or raw_exp <= 0:`.
Verified: this keeps `300.0` (accepted) and rejects `inf`/`nan`/`0`/`True`. Belt-and-braces
hardening also worth doing: parse the request body with a JSON loader that rejects
`Infinity`/`NaN`/non-finite (e.g. `json.loads(..., parse_constant=...)` or a strict
parser) so the malformed value never enters the system at the edge.

---

## Attacks that held (DEFENDED)

**2. Audience confusion / recipient-binding bypass — DEFENDED.** An assertion minted with
`aud = OTHER_DID` and presented to a division whose DID is `SELF_DID` is refused
("recipient-binding / cross-recipient replay guard"). Missing `aud` and empty-string `aud`
also fail closed (compared against the receiver's own non-empty DID). No bypass found.

**3. Replay (envelope) — DEFENDED.** A byte-identical re-send of a signed envelope (reused
`(sender_did, nonce)`) is rejected by the post-signature nonce cache within the ±5-min
window; a stale `ts` is rejected by the freshness check. The nonce cache is only written
*after* signature verification, so an unauthenticated caller can't poison it.
*Caveat (not a vuln, by design):* assertion-level anti-replay rides entirely on the
envelope nonce+ts; the assertion's `jti` is **audit-only**, not enforced as single-use at
`validate_cross_division_assertion` (the probe shows the same `jti` validating twice). Within
the freshness window a *re-signed fresh envelope* carrying the same still-valid assertion
re-validates. This is the documented layering and is bounded by the short `exp` — **which
is exactly why finding #4 matters**: with `exp=inf` that bound is removed, so the
"jti is audit-only" posture stops being safe.

**5/6. Cross-issuer spoof & signer-binding bypass — DEFENDED.** `assertion_principal`
enforces `assertion['iss'] == expected_issuer`, where `expected_issuer` is the issuer bound
to *this specific signing peer's DID* (`api/main.py:1096`,
`settings.peer_trust[signer_did]["issuer"]`). An alpha-signed envelope asserting a beta- or
gamma-issuer user is refused. It fails closed when no issuer is bound (`expected_issuer == ""`).
This is the control that confines a compromised peer's blast radius to its own namespace.

**1. Assertion forgery (same namespace) — DEFENDED by design.** A peer bound to alpha can
assert any *alpha-namespace* email (e.g. `ceo@example.com|<alpha-ns>`) because the receiver
does not — and architecturally cannot — re-verify the email against the home Keycloak (no
receiver-audience home token can be minted). This is the standard *vouched delegation* model
and is explicitly documented in `assertion_principal`'s trust-model note. The forgery is
confined to the signer's own issuer namespace by #5/#6, so it never reaches another division
and is strictly safer than forwarding a replayable raw token. Not a vuln — but worth a line
in the threat model so reviewers don't mistake the vouched model for verified identity.

**7. Envelope-signature bypass — DEFENDED.** Mutating any signed field after signing — the
assertion's `email` (identity escalation) or `aud` (retargeting a captured envelope) — breaks
the Ed25519 signature over the canonical bytes; `verify_signed_message` fails closed.
`_canonical_bytes` excludes only the `_agentmesh` envelope, so the entire payload including
`user_assertion` is covered. The verification key is resolved from `peer_trust` by claimed
DID, never from the message body, and the key must derive the claimed DID.

**Bonus — DEFENDED.** A validly self-signed envelope from a DID *absent* from `peer_trust`
is refused (`verify_signed_message_untrusted_peer`) — trust-map membership is the data-path
trust decision.
