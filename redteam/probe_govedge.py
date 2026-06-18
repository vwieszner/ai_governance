"""Adversarial probes against the governance-edge controls (red-team).

Run from the backend package dir so `import api.main` etc. resolve:

    cd agt-federated-rag
    ../.venv/Scripts/python.exe ../redteam/probe_govedge.py

Each probe targets one attack goal and PRINTS a verdict line. A probe is only
allowed to claim VULNERABLE if it actually drove the REAL code into the unsafe
state; otherwise it prints DEFENDED with the observed safe behaviour. No probe
mutates source; everything is in-memory / tmp files.

Attack goals:
  1. Kill-switch bypass (race / Redis fail-open / single-entrypoint / settings-vs-runtime)
  2. /audit authz bypass (cross-division read, non-admin reach, tampered-but-verified)
  3. CRL bypass (revoked cert accepted at handshake; missing-CRL fail-open semantics)
  4. Expiry bypass (FR-7.1 grant TTL basis mismatch / stale reuse)
"""
from __future__ import annotations

import asyncio
import json
import ssl
import sys
import time
from pathlib import Path

# Make the backend package importable regardless of CWD.
_HERE = Path(__file__).resolve().parent
_BACKEND = _HERE.parent / "agt-federated-rag"
for p in (_BACKEND, _BACKEND.parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import api.main as main          # noqa: E402
import audit_log                 # noqa: E402
from transport import mtls       # noqa: E402

RESULTS: list[tuple[str, str, str]] = []   # (goal, verdict, note)


def record(goal: str, verdict: str, note: str) -> None:
    RESULTS.append((goal, verdict, note))
    print(f"[{verdict:14}] {goal}: {note}")


# ── Fakes / helpers ────────────────────────────────────────────────────────────

class FakeRedis:
    def __init__(self):
        self.kv: dict = {}

    async def get(self, k):
        return self.kv.get(k)

    async def set(self, k, v):
        self.kv[k] = v

    async def delete(self, k):
        self.kv.pop(k, None)

    async def setex(self, k, ttl, v):
        self.kv[k] = v

    async def expire(self, k, ttl):
        return True

    async def incr(self, k):
        self.kv[k] = int(self.kv.get(k, 0)) + 1
        return self.kv[k]


class BoomRedis(FakeRedis):
    """A Redis whose GET fails (store degraded) -- tests fail-open on the error path."""
    async def get(self, k):
        raise RuntimeError("redis read failed (simulated outage)")


def _set(mp_attr, value):
    setattr(main.settings, mp_attr, value)


# ══════════════════════════════════════════════════════════════════════════════
# GOAL 1 -- KILL-SWITCH BYPASS
# ══════════════════════════════════════════════════════════════════════════════

def probe_killswitch():
    goal = "GOAL1 kill-switch"

    # --- 1a. Redis fail-OPEN on the engaged-check error path? -------------------
    main.settings.agent_kill_switch_engaged = False
    main.settings.division_id = "alpha"
    boom = BoomRedis()

    async def get_boom():
        return boom
    orig_get_redis = main._get_redis
    main._get_redis = get_boom
    try:
        engaged = asyncio.run(main._runtime_kill_switch_engaged())
    finally:
        main._get_redis = orig_get_redis
    if engaged is True:
        record(goal, "DEFENDED",
               "Redis GET error during engaged-check fails CLOSED (engaged=True) -- "
               "a degraded store cannot silently lift a halt.")
    else:
        record(goal, "VULNERABLE",
               f"Redis error fails OPEN (engaged={engaged}!) -- a halt is lifted by a store outage.")

    # --- 1b. Both entrypoints (/query AND /a2a/query) guarded? ------------------
    # Drive the real handlers with a fake Redis carrying the engaged flag.
    fake = FakeRedis()
    fake.kv[main._killswitch_key("alpha")] = "1"

    async def get_fake():
        return fake
    main._get_redis = get_fake

    # /query: stub auth/rl/run_query so a SERVED path wouldn't need infra; if the
    # kill check fires, none of that is reached.
    async def fake_bearer(auth):
        return ("tok", {"sub": "x", "email": "a@e.com", "email_verified": True,
                        "iss": "http://localhost:9002/realms/rag"})
    orig_bearer = main._get_bearer_token
    main._get_bearer_token = fake_bearer
    orig_principal = main.principal
    main.principal = lambda c: "a@e.com|ns"

    async def no_rl(s):
        return None
    orig_rl = main._check_rate_limit
    main._check_rate_limit = no_rl

    async def fake_run_query(**kw):
        return {"task_id": kw.get("task_id"), "answer": "LEAK", "status_message": "completed",
                "flow": "LOCAL_ALLOWED"}
    orig_rq = main.agent_graph.run_query
    main.agent_graph.run_query = fake_run_query

    class _Req:
        async def json(self):
            return {"query": "hi"}

    q_status = None
    try:
        try:
            asyncio.run(main.query(_Req(), authorization="Bearer tok"))
            q_status = "SERVED"
        except main.HTTPException as e:
            q_status = e.status_code
    finally:
        pass

    # /a2a/query: DID-authenticated. Stub verify so we can tell whether the kill
    # check (which should fire FIRST, before signature verification) blocks it.
    async def fake_verify(payload):
        return (False, None)
    orig_verify = main.agent_identity.verify_signed_message
    main.agent_identity.verify_signed_message = fake_verify

    a2a_status = None
    try:
        try:
            asyncio.run(main.a2a_query(_Req()))
            a2a_status = "RETURNED"
        except main.HTTPException as e:
            a2a_status = e.status_code
    finally:
        main._get_bearer_token = orig_bearer
        main.principal = orig_principal
        main._check_rate_limit = orig_rl
        main.agent_graph.run_query = orig_rq
        main.agent_identity.verify_signed_message = orig_verify
        main._get_redis = orig_get_redis

    if q_status == 503 and a2a_status == 503:
        record(goal, "DEFENDED",
               "Both entrypoints refuse with 503 when engaged (/query=503, /a2a/query=503) "
               "BEFORE any auth/retrieval/LLM/signature work.")
    else:
        record(goal, "VULNERABLE",
               f"Entrypoint NOT halted: /query={q_status}, /a2a/query={a2a_status}.")

    # --- 1c. settings-vs-runtime confusion / disengage TOCTOU ------------------
    # If the deploy-time settings flag is set, disengaging the runtime flag must
    # NOT serve. And a runtime engage must not require the settings flag.
    main.settings.agent_kill_switch_engaged = True
    fake2 = FakeRedis()  # no runtime flag at all

    async def get_fake2():
        return fake2
    main._get_redis = get_fake2
    try:
        eng = asyncio.run(main._runtime_kill_switch_engaged())
    finally:
        main._get_redis = orig_get_redis
        main.settings.agent_kill_switch_engaged = False
    if eng is True:
        record(goal, "DEFENDED",
               "Settings override is always-on: with runtime flag CLEAR but settings flag set, "
               "engaged=True (no settings-vs-runtime confusion).")
    else:
        record(goal, "VULNERABLE",
               "Settings override ignored when runtime flag is clear -- confusion bypass.")

    # --- 1d. division-scope confusion: does engaging halt THIS division's key,
    # and could a flag set under a DIFFERENT division id leave this one serving?
    # The engaged-check reads settings.division_id at call time; an attacker cannot
    # set a key for a division they don't control, and the per-division key means
    # halting alpha must not require/affect beta. Verify the key is division-scoped
    # AND that a flag under the WRONG division id does NOT engage this one.
    main.settings.agent_kill_switch_engaged = False
    fake3 = FakeRedis()
    fake3.kv[main._killswitch_key("beta")] = "1"     # a DIFFERENT division is halted

    async def get_fake3():
        return fake3
    main.settings.division_id = "alpha"
    main._get_redis = get_fake3
    try:
        eng_alpha = asyncio.run(main._runtime_kill_switch_engaged())   # alpha not halted
        asyncio.run(main._set_runtime_kill_switch(True))               # engage alpha
        eng_alpha2 = asyncio.run(main._runtime_kill_switch_engaged())  # now halted
        key_used = main._killswitch_key("alpha")
        scoped = (key_used in fake3.kv) and (eng_alpha is False) and (eng_alpha2 is True)
    finally:
        main._get_redis = orig_get_redis
    if scoped:
        record(goal, "DEFENDED",
               "Kill-switch is correctly per-division: a flag under another division's key does "
               "NOT halt this one; engaging writes/reads agt:killswitch:<this-division> only "
               "(no cross-division engage confusion, and an attacker cannot reach another "
               "division's key without that division's Redis/admin token).")
    else:
        record(goal, "VULNERABLE",
               "Division-scope confusion in the kill-switch key handling.")


# ══════════════════════════════════════════════════════════════════════════════
# GOAL 2 -- /audit AUTHZ BYPASS
# ══════════════════════════════════════════════════════════════════════════════

def _seed_chain(base: Path, division: str, role: str, events):
    chain = audit_log.AuditChain(base / f"{division}_{role}.jsonl")
    for ev, data in events:
        chain.append(ev, data)
    return chain


def probe_audit(tmp: Path):
    goal = "GOAL2 /audit authz"

    # --- 2a. role-claim confusion: non-admin reach via groups vs realm_access ---
    # Probe several token shapes that should NOT be treated as admin.
    not_admin_shapes = [
        ("realm_access.roles=member only",
         {"realm_access": {"roles": ["member", "data-owner"]}}),
        ("resource_access carries division-admin (NOT realm_access)",
         {"resource_access": {"some-client": {"roles": ["division-admin"]}}}),
        ("role nested under a different key",
         {"roles": ["division-admin"]}),  # top-level 'roles', not realm_access/groups
        ("missing role claims entirely", {}),
        ("realm_access not a dict",
         {"realm_access": "division-admin"}),
        ("groups claim present but role only as substring",
         {"groups": ["division-admin-readonly"]}),  # not exact
    ]
    base_claims = {"sub": "x", "email": "m@e.com", "email_verified": True,
                   "iss": "http://localhost:9002/realms/rag"}
    main.settings.recognized_groups = ""  # accept any group name (most permissive)
    leaks = []
    for label, extra in not_admin_shapes:
        claims = {**base_claims, **extra}
        if main._is_division_admin(claims):
            leaks.append(label)
    # And the legitimate admin shapes that SHOULD pass (sanity, not a vuln either way):
    admin_realm = main._is_division_admin({**base_claims, "realm_access": {"roles": ["division-admin"]}})
    admin_groups = main._is_division_admin({**base_claims, "groups": ["division-admin"]})
    if leaks:
        record(goal, "VULNERABLE",
               f"_is_division_admin returns True for non-admin shapes: {leaks}")
    else:
        record(goal, "DEFENDED",
               f"_is_division_admin fail-closed: none of {len(not_admin_shapes)} non-admin shapes "
               f"granted admin; legit realm_access={admin_realm}, groups={admin_groups}.")

    # --- 2b. non-admin reaches GET /audit? (end-to-end through _require_admin) --
    main.settings.division_id = "alpha"
    main.settings.audit_log_dir = str(tmp)
    _seed_chain(tmp, "alpha", "agent", [("auth_decision", {"allowed": True, "user_id": "alice|ns"})])

    async def bearer_member(auth):
        return ("tok", {**base_claims, "realm_access": {"roles": ["member"]}})
    orig_bearer = main._get_bearer_token
    main._get_bearer_token = bearer_member

    async def no_rl(s):
        return None
    orig_rl = main._check_rate_limit
    main._check_rate_limit = no_rl
    status = None
    try:
        try:
            asyncio.run(main.get_audit(authorization="Bearer tok", event=None, limit=500))
            status = "SERVED"
        except main.HTTPException as e:
            status = e.status_code
    finally:
        main._get_bearer_token = orig_bearer
        main._check_rate_limit = orig_rl
    if status == 403:
        record(goal, "DEFENDED", "Non-admin (member) GET /audit refused with 403.")
    else:
        record(goal, "VULNERABLE", f"Non-admin reached GET /audit (status={status}).")

    # --- 2c. cross-division read: can an alpha admin export beta's chain? -------
    main.settings.division_id = "alpha"
    main.settings.audit_log_dir = str(tmp)
    _seed_chain(tmp, "beta", "agent",
                [("peer_secret", {"user_id": "carol|beta"}),
                 ("peer_secret2", {"user_id": "dave|beta"})])

    async def bearer_admin(auth):
        return ("tok", {**base_claims, "realm_access": {"roles": ["division-admin"]}})
    main._get_bearer_token = bearer_admin
    main._check_rate_limit = no_rl
    try:
        resp = asyncio.run(main.get_audit(authorization="Bearer tok", event=None, limit=500))
        body = json.loads(bytes(resp.body).decode())
    finally:
        main._get_bearer_token = orig_bearer
        main._check_rate_limit = orig_rl
    events = [e["event"] for e in body["entries"]]
    files = [c["file"] for c in body["chains"]]
    if any(e.startswith("peer_secret") for e in events) or any(f.startswith("beta_") for f in files):
        record(goal, "VULNERABLE",
               f"alpha admin exported beta's chain! events={events}, files={files}")
    else:
        record(goal, "DEFENDED",
               f"Cross-division export blocked: alpha admin sees only alpha chains ({files}); "
               f"beta's peer_secret entries absent.")

    # --- 2d. tampered chain reported verified=TRUE? ----------------------------
    # (i) field tamper.
    tdir = tmp / "tamper"
    tdir.mkdir()
    main.settings.audit_log_dir = str(tdir)
    _seed_chain(tdir, "alpha", "agent",
                [("auth_decision", {"user_id": "alice|ns"}), ("access_revoked", {"chunk_id": "c-1"})])
    f = tdir / "alpha_agent.jsonl"
    lines = f.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("alice|ns", "mallory|ns")
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    main._get_bearer_token = bearer_admin
    main._check_rate_limit = no_rl
    try:
        body = json.loads(bytes(asyncio.run(
            main.get_audit(authorization="Bearer tok", event=None, limit=500)).body).decode())
    finally:
        main._get_bearer_token = orig_bearer
        main._check_rate_limit = orig_rl
    field_ok = body["verified"] is False

    # (ii) tail truncation with the anchor present (whole-file-tail drop).
    tdir2 = tmp / "trunc"
    tdir2.mkdir()
    main.settings.audit_log_dir = str(tdir2)
    ch = _seed_chain(tdir2, "alpha", "agent",
                     [("e0", {"count": 0}), ("e1", {"count": 1}), ("e2", {"count": 2})])
    cf = tdir2 / "alpha_agent.jsonl"
    cl = cf.read_text(encoding="utf-8").splitlines()
    cf.write_text("\n".join(cl[:-1]) + "\n", encoding="utf-8")   # drop the tail entry
    main._get_bearer_token = bearer_admin
    main._check_rate_limit = no_rl
    try:
        body2 = json.loads(bytes(asyncio.run(
            main.get_audit(authorization="Bearer tok", event=None, limit=500)).body).decode())
    finally:
        main._get_bearer_token = orig_bearer
        main._check_rate_limit = orig_rl
    trunc_ok = body2["verified"] is False

    if field_ok and trunc_ok:
        record(goal, "DEFENDED",
               "Tampered chain reported verified=False (field-edit detected via hash recompute; "
               "tail truncation detected via the anchor cross-check) -- still returns 200 so the "
               "admin SEES the break.")
    else:
        record(goal, "VULNERABLE",
               f"Tamper reported as verified=True (field_detected={field_ok}, "
               f"truncation_detected={trunc_ok}).")

    # --- 2e. CONSISTENT local rewrite: attacker owns the host, rewrites BOTH the
    # chain AND the local anchor file in lock-step. The chain hash is a keyless
    # SHA256 (no HMAC secret), so a host-level attacker can recompute a fully valid
    # chain; the LOCAL anchor offers no independent secret either. Does verify
    # still report verified=TRUE? (This is the documented limit of a local anchor.)
    rdir = tmp / "rewrite"
    rdir.mkdir()
    main.settings.audit_log_dir = str(rdir)
    _seed_chain(rdir, "alpha", "agent",
                [("auth_decision", {"user_id": "alice|ns", "allowed": True}),
                 ("access_revoked", {"chunk_id": "c-1", "decision": "revoked"})])
    # Forge a REPLACEMENT chain (genesis-based, valid hashes) that erases the real
    # history and substitutes attacker-chosen entries, then rebuild the local anchor
    # to match its new head. No secret is needed -- _entry_hash is public SHA256.
    cf = rdir / "alpha_agent.jsonl"
    af = rdir / "alpha_agent.anchor.jsonl"
    prev = audit_log.GENESIS
    forged_lines = []
    forged_head = None
    for seq, (ev, data) in enumerate([
            ("auth_decision", {"user_id": "mallory|ns", "allowed": True}),  # rewritten actor
            ("audit_clean", {"reason": "nothing to see here"})]):           # fabricated entry
        norm = json.loads(json.dumps(data))
        ts = "2026-01-01T00:00:0%dZ" % seq
        h = audit_log._entry_hash(seq, ts, ev, norm, prev)
        forged_lines.append(json.dumps(
            {"seq": seq, "ts": ts, "event": ev, "data": norm, "prev_hash": prev, "hash": h}))
        prev = h
        forged_head = {"seq": seq, "hash": h, "ts": ts}
    cf.write_text("\n".join(forged_lines) + "\n", encoding="utf-8")
    af.write_text(json.dumps(forged_head) + "\n", encoding="utf-8")   # anchor rewritten to match
    main._get_bearer_token = bearer_admin
    main._check_rate_limit = no_rl
    try:
        body3 = json.loads(bytes(asyncio.run(
            main.get_audit(authorization="Bearer tok", event=None, limit=500)).body).decode())
    finally:
        main._get_bearer_token = orig_bearer
        main._check_rate_limit = orig_rl
    rewrite_events = [e["event"] for e in body3["entries"]]
    if body3["verified"] is True:
        record(goal, "NEEDS-HARDENING",
               "DOCUMENTED RESIDUAL: a host-level attacker who rewrites the chain AND the LOCAL "
               "anchor in lock-step is reported verified=True (keyless SHA256 + local-only anchor). "
               f"Forged entries shown as authentic: {rewrite_events}. Mitigation EXISTS but is "
               "OFF by default: set AUDIT_ANCHOR_URL to a remote append-only collector "
               "(audit_log.AuditChain.anchor_url) so the head the attacker can't reach diverges. "
               "Not a NEW bug -- the code's own docstring calls the local anchor insufficient.")
    else:
        record(goal, "DEFENDED",
               "Even a lock-step chain+anchor rewrite is flagged verified=False.")


# ══════════════════════════════════════════════════════════════════════════════
# GOAL 3 -- CRL BYPASS
# ══════════════════════════════════════════════════════════════════════════════

def _handshake_ok(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext,
                  server_hostname: str = "localhost") -> bool:
    c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname=server_hostname)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    c_done = s_done = False
    try:
        for _ in range(40):
            if not c_done:
                try:
                    client.do_handshake()
                    c_done = True
                except ssl.SSLWantReadError:
                    pass
            s_in.write(c_out.read())
            if not s_done:
                try:
                    server.do_handshake()
                    s_done = True
                except ssl.SSLWantReadError:
                    pass
            c_in.write(s_out.read())
            if c_done and s_done:
                return True
        return False
    except ssl.SSLError:
        return False


def probe_crl(tmp: Path):
    goal = "GOAL3 CRL"
    ca_key, ca_cert = mtls.generate_ca()
    ca_path = tmp / "ca.crt"
    ca_path.write_bytes(ca_cert.public_bytes(mtls.serialization.Encoding.PEM))
    server = mtls.issue_division_cert(ca_key, ca_cert, "alpha")
    client = mtls.issue_division_cert(ca_key, ca_cert, "beta")
    s_crt, s_key = server.write(tmp, "server")
    c_crt, c_key = client.write(tmp, "client")

    # --- 3a. revoked cert REJECTED at the real handshake? -----------------------
    crl_path = mtls.write_crl(
        mtls.build_crl(ca_key, ca_cert, [client.cert.serial_number]), tmp / "fed.crl")
    sctx = mtls.server_context(s_crt, s_key, ca_path, crl_path=crl_path)
    revoked_client = mtls.client_context(ca_path, c_crt, c_key)
    accepted = _handshake_ok(sctx, revoked_client)
    if accepted:
        record(goal, "VULNERABLE",
               "A CA-signed but REVOKED client cert COMPLETED the mTLS handshake (CRL not enforced).")
    else:
        record(goal, "DEFENDED",
               "Revoked client cert rejected at the real (MemoryBIO) handshake -- CRL enforced fail-closed.")

    # --- 3b. stale cache: republished CRL picked up without restart? -----------
    refresh = tmp / "refresh.crl"
    mtls.write_crl(mtls.build_crl(ca_key, ca_cert, []), refresh)        # empty
    s1 = mtls.server_context(s_crt, s_key, ca_path, crl_path=str(refresh))
    before = _handshake_ok(s1, mtls.client_context(ca_path, c_crt, c_key))
    time.sleep(0.02)
    mtls.write_crl(mtls.build_crl(ca_key, ca_cert, [client.cert.serial_number]), refresh)  # revoke
    s2 = mtls.server_context(s_crt, s_key, ca_path, crl_path=str(refresh))
    after = _handshake_ok(s2, mtls.client_context(ca_path, c_crt, c_key))
    if before is True and after is False:
        record(goal, "DEFENDED",
               "Republished CRL is picked up on next context build (mtime cache) -- "
               "accepted before revocation, rejected after, no restart.")
    elif after is True:
        record(goal, "VULNERABLE",
               "Stale CRL cache: a serial added to the republished CRL is still accepted "
               "(revocation not refreshed).")
    else:
        record(goal, "NEEDS-HARDENING",
               f"Unexpected refresh behaviour (before={before}, after={after}).")

    # --- 3c. configured-but-missing CRL fail-OPEN? ------------------------------
    # A configured CRL path that does not exist must fail LOUD, not silently
    # build a no-revocation context (which would fail OPEN).
    missing = str(tmp / "no-such.crl")
    failed_loud = False
    try:
        mtls.server_context(s_crt, s_key, ca_path, crl_path=missing)
    except FileNotFoundError:
        failed_loud = True
    except Exception as e:  # any raise is "loud"; note the type
        failed_loud = True
    if failed_loud:
        record(goal, "DEFENDED",
               "A configured-but-absent CRL raises (fail loud) instead of silently building a "
               "no-revocation context -- no missing-CRL fail-open.")
    else:
        record(goal, "VULNERABLE",
               "Configured CRL path missing yet server_context built a context -- fail-open.")

    # --- 3d. cadata-vs-cafile gotcha: is CRL actually associated with issuer? ---
    # If load_crl_bundle had loaded the CRL via cadata, OpenSSL would reject EVERY
    # cert ("unable to get certificate CRL"); 3a's positive control (unrevoked
    # accepted) below proves the CRL is correctly associated via cafile.
    empty_crl = mtls.write_crl(mtls.build_crl(ca_key, ca_cert, []), tmp / "empty.crl")
    sctx_e = mtls.server_context(s_crt, s_key, ca_path, crl_path=empty_crl)
    unrevoked_ok = _handshake_ok(sctx_e, mtls.client_context(ca_path, c_crt, c_key))
    if unrevoked_ok:
        record(goal, "DEFENDED",
               "With CRL checking ON, an UNREVOKED cert still handshakes -- CRL is associated to "
               "its issuer via cafile (no cadata gotcha that would reject all certs).")
    else:
        record(goal, "NEEDS-HARDENING",
               "Unrevoked cert rejected under an empty CRL -- CRL may be mis-associated (cadata gotcha).")

    # --- 3e. real run() wiring: does tls_serving_kwargs build a CRL-ENFORCING
    # factory, and is the resulting served context one that rejects a revoked cert?
    # (Bypasses the unit helper and exercises the production serving path.)
    class _S:
        require_mtls = True
        tls_cert_file = s_crt
        tls_key_file = s_key
        tls_ca_file = str(ca_path)
        tls_crl_file = crl_path           # the CRL revoking `client`
    kwargs = mtls.tls_serving_kwargs(_S())
    factory = kwargs.get("ssl_context_factory")
    if factory is None:
        record(goal, "VULNERABLE",
               f"require_mtls + CRL configured but tls_serving_kwargs produced NO CRL factory "
               f"(keys={list(kwargs)}) -- revocation silently skipped on the served path.")
    else:
        served_ctx = factory(None, None)
        served_rejects_revoked = _handshake_ok(served_ctx, mtls.client_context(ca_path, c_crt, c_key))
        if served_rejects_revoked is False:
            record(goal, "DEFENDED",
                   "Production serving path (tls_serving_kwargs->ssl_context_factory) builds a "
                   "CRL-enforcing context that rejects the revoked cert at the handshake.")
        else:
            record(goal, "VULNERABLE",
                   "Production serving context ACCEPTED a revoked cert (factory built a "
                   "non-enforcing context).")

    # --- 3f. require_mtls WITHOUT a CRL: documented fail-open semantics ----------
    # No CRL configured => CERT_REQUIRED but NO revocation gate. This is the
    # documented backward-compatible posture. Flag it as a deployment caveat, not a
    # silent downgrade: a revoked cert WOULD be accepted because revocation was never
    # configured (mTLS still required; trust-CA still enforced).
    class _SNoCrl(_S):
        tls_crl_file = ""
    nocrl_kwargs = mtls.tls_serving_kwargs(_SNoCrl())
    if "ssl_context_factory" in nocrl_kwargs:
        record(goal, "DEFENDED", "Unexpectedly built a CRL factory even with no CRL configured.")
    elif nocrl_kwargs.get("ssl_cert_reqs") == ssl.CERT_REQUIRED:
        record(goal, "NEEDS-HARDENING",
               "DEPLOYMENT CAVEAT (documented): require_mtls with NO CRL configured serves "
               "CERT_REQUIRED but with NO revocation gate -- a revoked-yet-CA-signed cert would "
               "be accepted. mTLS + CA-trust still enforced; revocation requires setting "
               "TLS_CRL_FILE. Operators MUST configure a CRL to get NFR-3; nginx-edge mode also "
               "needs ssl_crl wired (PROJECT_STATUS M7 notes this).")
    else:
        record(goal, "VULNERABLE",
               f"require_mtls without CRL did not even demand a client cert: {nocrl_kwargs}")


# ══════════════════════════════════════════════════════════════════════════════
# GOAL 4 -- EXPIRY BYPASS (FR-7.1)
# ══════════════════════════════════════════════════════════════════════════════

class RecordingFGA:
    def __init__(self):
        self.viewer = []
        self.viewer_until = []
        self.pending_revoked = []

    async def grant_viewer(self, user_id, chunk_id):
        self.viewer.append((user_id, chunk_id))

    async def grant_viewer_until(self, user_id, chunk_id, expiry_iso):
        self.viewer_until.append((user_id, chunk_id, expiry_iso))

    async def revoke_pending_approval(self, user_id, chunk_id):
        self.pending_revoked.append((user_id, chunk_id))


def probe_expiry():
    goal = "GOAL4 expiry"
    from datetime import datetime, timezone

    from config import settings as cfg
    from workflow import activities
    from workflow.activities import GrantAccessInput, grant_access_in_openfga

    # --- 4a. ttl>0 => time-bound grant, and the expiry basis matches check() ----
    fga = RecordingFGA()

    async def fake_get():
        return fga
    orig = activities._get_openfga
    activities._get_openfga = fake_get
    orig_ttl = cfg.approval_grant_ttl_seconds
    cfg.approval_grant_ttl_seconds = 3600
    before = datetime.now(timezone.utc)
    try:
        asyncio.run(grant_access_in_openfga(
            GrantAccessInput(user_id="user:alice", chunk_ids=["c1"])))
    finally:
        cfg.approval_grant_ttl_seconds = orig_ttl
        activities._get_openfga = orig
    permanent_used = bool(fga.viewer)
    if permanent_used or not fga.viewer_until:
        record(goal, "VULNERABLE",
               f"ttl>0 but permanent grant used (viewer={fga.viewer}, until={fga.viewer_until}) -- "
               "approved access is forever, expiry never enforced.")
    else:
        # Verify the expiry basis matches what check() supplies (datetime.now(utc).isoformat()).
        _, _, exp_iso = fga.viewer_until[0]
        exp = datetime.fromisoformat(exp_iso)
        check_basis = datetime.now(timezone.utc)  # the exact value check() builds
        comparable = exp.tzinfo is not None and check_basis.tzinfo is not None
        future = exp > before
        # Is the expiry parseable by the SAME comparison the OpenFGA condition does
        # (current_time < expiry, both TIMESTAMP)? A naive-vs-aware mismatch would make
        # the comparison wrong. Confirm both are tz-aware UTC ISO-8601.
        if comparable and future and (3600 - 5) <= (exp - before).total_seconds() <= (3600 + 60):
            record(goal, "DEFENDED",
                   f"ttl>0 -> grant_viewer_until only; expiry={exp_iso} is tz-aware UTC ISO-8601 "
                   "(same basis as check()'s current_time), ~now+ttl, in the future -- comparable, "
                   "no naive-vs-aware basis mismatch.")
        else:
            record(goal, "VULNERABLE",
                   f"Expiry basis mismatch/unsound: comparable={comparable}, future={future}, "
                   f"exp={exp_iso}.")

    # --- 4b. decide() re-checks live; an expired/revoked grant => NEEDS_APPROVAL?
    # The grant tuple carries the non_expired condition; check() ALWAYS passes
    # current_time, so once expiry lapses OpenFGA stops returning allowed=viewer.
    # Demonstrate the consequence the wiring relies on with a stubbed check that
    # mimics the post-expiry state (viewer no longer allowed, pending remains).
    from auth import openfga as ofga
    auth = ofga.OpenFGAAuth()

    async def _expired_check(user_id, chunk_id, relation, groups=None):
        # Post-expiry: the non_expired viewer tuple no longer grants viewer; only
        # the pending_approval relation remains -> a re-ask must re-enter approval.
        return relation == ofga.Relation.PENDING_APPROVAL
    auth.check = _expired_check  # type: ignore[method-assign]
    decision = asyncio.run(auth.decide("user:alice", "chunk:q4"))

    # Also confirm check() actually injects current_time (so OpenFGA evaluates the
    # condition every request -- not a stale snapshot). Inspect the request body it builds.
    captured = {}

    class _CapClient:
        async def check(self, body):
            captured["context"] = getattr(body, "context", None)

            class R:
                allowed = False
            return R()
    auth2 = ofga.OpenFGAAuth()
    auth2._client = _CapClient()
    asyncio.run(auth2.check("user:alice", "q4", ofga.Relation.VIEWER))
    ctx = captured.get("context") or {}
    injects_current_time = "current_time" in ctx

    if decision == ofga.AuthzDecision.NEEDS_APPROVAL and injects_current_time:
        record(goal, "DEFENDED",
               "Post-expiry re-ask routes to NEEDS_APPROVAL (no stale viewer reuse); check() "
               f"injects current_time per request (ctx keys={list(ctx)}), so OpenFGA evaluates "
               "current_time<expiry live -- re-asking a stale grant cannot reuse it.")
    else:
        record(goal, "VULNERABLE",
               f"Stale grant reuse possible: decision={decision}, current_time injected={injects_current_time}.")


# ── main ────────────────────────────────────────────────────────────────────────

def main_run():
    import tempfile
    print("=" * 90)
    print("RED-TEAM PROBE -- governance-edge controls (kill-switch / audit / CRL / expiry)")
    print("=" * 90)
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        audit_dir = tmp / "audit"
        crl_dir = tmp / "crl"
        audit_dir.mkdir(parents=True, exist_ok=True)
        crl_dir.mkdir(parents=True, exist_ok=True)
        probe_killswitch()
        probe_audit(audit_dir)
        probe_crl(crl_dir)
        probe_expiry()
    print("=" * 90)
    vulns = [r for r in RESULTS if r[1] == "VULNERABLE"]
    needs = [r for r in RESULTS if r[1] == "NEEDS-HARDENING"]
    print(f"SUMMARY: {len(RESULTS)} probes -- "
          f"{sum(1 for r in RESULTS if r[1]=='DEFENDED')} DEFENDED, "
          f"{len(needs)} NEEDS-HARDENING, {len(vulns)} VULNERABLE")
    for g, v, n in vulns + needs:
        print(f"  !! {v}: {g} -- {n}")
    return 0 if not vulns else 1


if __name__ == "__main__":
    # tmp dirs created on demand
    import tempfile

    def _ensure(p: Path):
        p.mkdir(parents=True, exist_ok=True)
        return p
    # patch probe_* tmp subdirs to exist
    sys.exit(main_run())
