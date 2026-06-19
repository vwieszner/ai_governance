"""Cross-agent GOVERNED TOOL DELEGATION — /a2a/tool RECEIVE endpoint security tests.

The /a2a/tool endpoint is the receiving side of the DID-signed tool channel: a peer that
lacks a tool capability delegates the tool CALL here, this agent runs ITS OWN governed tool
(authorizing the delegated user so the peer can't bypass authz) and returns a DID-SIGNED
result. These tests pin that the endpoint replicates the /a2a/query security envelope
EXACTLY, in order, and fails CLOSED on every tampered/forged input:

  * kill-switch engaged                  → 503 (before any signature work)
  * non-finite JSON number               → 422
  * unsigned / forged signature          → 401
  * low-trust signer                     → 403
  * wrong-audience user assertion        → 401 (aud != self DID)
  * unconfigured capability              → SIGNED status="failed" (never a 500)
  * policy-denied delegated user         → SIGNED status="failed" (never a 500)
  * correctly-signed + authorized call   → runs the tool, returns a SIGNED result

These drive the endpoint coroutine directly with a fake request + monkeypatched gate
functions (the SAME pattern tests/test_killswitch.py / tests/test_offline.py use for
/a2a/query) — no live mesh, no real crypto, no broker.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from api import main

_SELF_DID = "did:mesh:self"
_PEER_DID = "did:mesh:peer-b"
_PEER_ISSUER = "http://peer-b/realms/rag"
_USER_ID = "alice@example.com|deadbeefdeadbeef"


@pytest.fixture(autouse=True)
def _clean_mcp_cache():
    """Reset the governed MCP executor's gateway cache around each test so the happy-path
    (which runs the real local calc tool via run_local_tool) is order-independent — other
    suites monkeypatch settings.mcp_servers and pytest's revert can leave a stale gateway."""
    from tools import mcp as mcp_tools
    mcp_tools.reset_cache()
    yield
    mcp_tools.reset_cache()


class _FakeRedis:
    def __init__(self): self.kv: dict = {}
    async def get(self, k): return self.kv.get(k)
    async def set(self, k, v): self.kv[k] = v
    async def setex(self, k, ttl, v): self.kv[k] = v


def _patch_redis(monkeypatch):
    fake = _FakeRedis()
    async def get_redis(): return fake
    monkeypatch.setattr(main, "_get_redis", get_redis)
    return fake


def _req(body: dict):
    class _Req:
        async def json(self): return body
    return _Req()


def _tool_body(capability="tool.calc", arguments=None, with_assertion=True):
    """A well-formed /a2a/tool request body (the signed envelope fields are simulated by
    monkeypatching verify_signed_message, so we only need the application fields here)."""
    body: dict = {
        "capability": capability,
        "arguments": {"expression": "2+3*4"} if arguments is None else arguments,
        "source_division": "division-b",
        # An opaque _agentmesh block; the real signature is simulated by the monkeypatch.
        "_agentmesh": {"sender_did": _PEER_DID, "signature": "sig", "alg": "EdDSA"},
    }
    if with_assertion:
        # The recipient-bound assertion. Its VALIDATION is monkeypatched per-test; the
        # important invariant is that user_id is derived from THIS dict, never a body field.
        body["user_assertion"] = {"sub": "x", "email": "alice@example.com",
                                  "email_verified": True, "iss": _PEER_ISSUER,
                                  "aud": _SELF_DID, "exp": 9999999999}
    return body


def _pass_signature_and_trust(monkeypatch, *, signer=_PEER_DID, trust=0.99):
    """Make the signature + registry-trust gates pass for a single trusted peer."""
    async def fake_verify_signed(payload):
        return (True, signer)
    monkeypatch.setattr(main.agent_identity, "verify_signed_message", fake_verify_signed)

    async def fake_verify_peer(did):
        return (True, trust)
    monkeypatch.setattr(main.agent_identity, "verify_peer_identity", fake_verify_peer)
    monkeypatch.setattr(main.settings, "agent_trust_threshold", 0.5)

    async def fake_get_did():
        return _SELF_DID
    monkeypatch.setattr(main.agent_identity, "get_did", fake_get_did)

    # Per-DID issuer binding resolved from the trust map (signer -> issuer). peer_trust is a
    # read-only property derived from peer_trust_map, so we set the underlying JSON setting.
    monkeypatch.setattr(main.settings, "peer_trust_map", json.dumps(
        {_PEER_DID: {"issuer": _PEER_ISSUER, "public_jwk": "", "agent_url": "http://peer-b",
                     "division_id": "division-b"}}))


def _pass_assertion(monkeypatch, user_id=_USER_ID):
    """validate_cross_division_assertion → user_id (the signed, recipient-bound identity)."""
    def fake_validate(assertion, *, expected_issuer, expected_audience, **kw):
        # Pin the recipient binding the endpoint must pass through: aud == self DID.
        assert expected_audience == _SELF_DID
        assert expected_issuer == _PEER_ISSUER
        if assertion.get("aud") != expected_audience:
            raise ValueError("aud mismatch")
        return user_id
    monkeypatch.setattr(main, "validate_cross_division_assertion", fake_validate)


def _capture_signed_response(monkeypatch):
    """Capture what sign_outbound_message signs (the endpoint's response object)."""
    captured: dict = {}
    async def fake_sign(obj):
        captured.clear()
        captured.update(obj)
        return {**obj, "_agentmesh": {"sender_did": _SELF_DID, "signature": "s", "alg": "EdDSA"}}
    monkeypatch.setattr(main.agent_identity, "sign_outbound_message", fake_sign)
    return captured


def _allow_policy(monkeypatch, captured_ctx=None):
    # The endpoint authorizes the DELEGATED user with _enforce("mcp.call", {..., user_id})
    # BEFORE running the tool; run_local_tool then re-runs the executor's own gate-1
    # _enforce("mcp.call", {server, tool}) WITHOUT a user_id. We capture the FIRST call that
    # carries a user_id (the endpoint's delegated-authz call — the one under test) so the
    # inner executor gate can't clobber it.
    async def fake_enforce(action, ctx):
        if captured_ctx is not None and "user_id" in ctx and "user_id" not in captured_ctx:
            captured_ctx.update({"action": action, **ctx})
        return None
    monkeypatch.setattr(main.agent_nodes, "_enforce", fake_enforce)


def _run(body):
    return asyncio.run(main.a2a_tool(_req(body)))


# ── kill-switch (FR-4.3): halts before any signature work ──────────────────────

def test_kill_switch_engaged_returns_503(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    fake = _patch_redis(monkeypatch)
    fake.kv[main._killswitch_key("alpha")] = "1"
    with pytest.raises(main.HTTPException) as ei:
        _run(_tool_body())
    assert ei.value.status_code == 503


# ── non-finite number (never-expiring-assertion guard) → 422 ───────────────────

def test_non_finite_number_returns_422(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    body = _tool_body(arguments={"expression": "1", "x": float("inf")})
    with pytest.raises(main.HTTPException) as ei:
        _run(body)
    assert ei.value.status_code == 422


# ── unsigned / forged signature → 401 ──────────────────────────────────────────

def test_unsigned_request_returns_401(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    async def fake_verify_signed(payload):
        return (False, None)          # signature does not verify
    monkeypatch.setattr(main.agent_identity, "verify_signed_message", fake_verify_signed)
    with pytest.raises(main.HTTPException) as ei:
        _run(_tool_body())
    assert ei.value.status_code == 401


# ── low-trust signer → 403 ─────────────────────────────────────────────────────

def test_low_trust_signer_returns_403(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch, trust=0.1)   # below the 0.5 threshold
    with pytest.raises(main.HTTPException) as ei:
        _run(_tool_body())
    assert ei.value.status_code == 403


# ── wrong-audience assertion (aud != self DID) → 401 ───────────────────────────

def test_wrong_audience_assertion_returns_401(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch)
    _pass_assertion(monkeypatch)        # the real validate raises on aud mismatch
    body = _tool_body()
    body["user_assertion"]["aud"] = "did:mesh:some-other-division"   # not self DID
    with pytest.raises(main.HTTPException) as ei:
        _run(body)
    assert ei.value.status_code == 401


def test_missing_assertion_returns_401(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch)
    body = _tool_body(with_assertion=False)   # no user_assertion at all
    with pytest.raises(main.HTTPException) as ei:
        _run(body)
    assert ei.value.status_code == 401


# ── unconfigured capability → SIGNED status="failed", not a 500 ────────────────

def test_unconfigured_capability_returns_signed_failure(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch)
    captured = _capture_signed_response(monkeypatch)
    # An unconfigured capability is resolved BEFORE the assertion (it's request validation),
    # so this returns a signed failure with no further gates needed.
    resp = _run(_tool_body(capability="tool.does-not-exist"))
    body = json.loads(bytes(resp.body).decode())
    assert body["status"] == "failed"
    assert body["result"] is None
    assert "_agentmesh" in body            # the failure result is DID-SIGNED
    assert captured["status"] == "failed"  # what we signed


# ── policy-denied delegated user → SIGNED status="failed", not a 500 ───────────

def test_policy_denied_returns_signed_failure(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch)
    _pass_assertion(monkeypatch)
    _capture_signed_response(monkeypatch)

    async def deny(action, ctx):
        raise PermissionError(f"policy denied {action}")
    monkeypatch.setattr(main.agent_nodes, "_enforce", deny)

    # run_local_tool must NEVER be reached when policy denies.
    async def boom(*a, **k):
        raise AssertionError("tool ran despite policy denial")
    monkeypatch.setattr("tools.local_tools.run_local_tool", boom)

    resp = _run(_tool_body())
    body = json.loads(bytes(resp.body).decode())
    assert body["status"] == "failed"
    assert "_agentmesh" in body            # signed, not a raw 500


# ── happy path: correctly-signed + authorized → runs the tool, signed result ───

def test_authorized_call_runs_tool_and_signs_result(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch)
    _pass_assertion(monkeypatch)
    captured_resp = _capture_signed_response(monkeypatch)
    policy_ctx: dict = {}
    _allow_policy(monkeypatch, policy_ctx)

    resp = _run(_tool_body())   # tool.calc, expression "2+3*4"
    body = json.loads(bytes(resp.body).decode())
    assert body["status"] == "completed"
    assert body["capability"] == "tool.calc"
    assert body["result"]["result"] == 14          # the real local calc tool ran
    assert "_agentmesh" in body                     # DID-SIGNED result

    # The DELEGATED user is what the policy engine saw — the peer did NOT bypass authz.
    assert policy_ctx["action"] == "mcp.call"
    assert policy_ctx["user_id"] == _USER_ID
    assert policy_ctx["server"] == "local-calc"
    assert policy_ctx["source_division"] == "division-b"
    assert captured_resp["status"] == "completed"


def test_oversized_arguments_rejected(monkeypatch):
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch)
    big = {"expression": "1+" * 5000}     # well over _MAX_TOOL_ARGS_BYTES
    with pytest.raises(main.HTTPException) as ei:
        _run(_tool_body(arguments=big))
    assert ei.value.status_code == 400


def test_user_id_is_never_taken_from_an_unsigned_body_field(monkeypatch):
    """Defence: even if the caller plants a `user_id` in the body, the endpoint derives the
    principal ONLY from the validated, recipient-bound assertion (never the body field)."""
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch)
    _pass_assertion(monkeypatch, user_id=_USER_ID)
    _capture_signed_response(monkeypatch)
    policy_ctx: dict = {}
    _allow_policy(monkeypatch, policy_ctx)

    body = _tool_body()
    body["user_id"] = "attacker@evil.example|0000000000000000"   # planted, must be ignored
    _run(body)
    assert policy_ctx["user_id"] == _USER_ID    # from the assertion, NOT the body field


# ── F2 (HIGH availability): an unserializable tool RESULT → signed failure, not a 500 ──
# JSONResponse.render() does json.dumps(..., allow_nan=False) and CPython refuses ints past
# the str-digit limit — both raise AFTER the handler returns, so a result the inbound
# non-finite guard never saw would surface as an uncaught HTTP 500 instead of the contract's
# signed status="failed". The endpoint now validates the result before signing AND wraps the
# sign+serialize, so every one of these returns 200 + a SIGNED failure the caller can verify.

def _setup_authorized(monkeypatch):
    """All gates pass + sign captured + policy allowed — so only the RESULT path is exercised."""
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch)
    _pass_assertion(monkeypatch)
    captured = _capture_signed_response(monkeypatch)
    _allow_policy(monkeypatch)
    return captured


@pytest.mark.parametrize("bad_result", [
    {"result": float("inf"), "expression": "1e1000"},      # inf → allow_nan=False rejects
    {"result": float("-inf"), "expression": "-1e1000"},
    {"result": float("nan"), "expression": "1e1000-1e1000"},  # nan
    {"result": 2 ** 50000, "expression": "pow(2, 50000)"},  # oversized int → str-digit limit
    {"nested": [1, {"deep": float("inf")}]},               # non-finite buried in structure
])
def test_unserializable_tool_result_returns_signed_failure_not_500(monkeypatch, bad_result):
    captured = _setup_authorized(monkeypatch)

    # Force the governed tool to RETURN a value JSONResponse cannot serialize (the sandbox
    # may also bound this upstream — this pins the endpoint's own defence-in-depth guard).
    async def bad_tool(server, tool, arguments):
        return bad_result
    monkeypatch.setattr("tools.local_tools.run_local_tool", bad_tool)

    # The key property: NO exception escapes (no 500). We get a real Response back.
    resp = _run(_tool_body())
    assert resp.status_code == 200

    # And it is a SIGNED status="failed" the caller can verify.
    body = json.loads(bytes(resp.body).decode())
    assert body["status"] == "failed"
    assert body["result"] is None
    assert "_agentmesh" in body                  # DID-signed failure
    assert captured["status"] == "failed"        # what we actually signed
    # The bad value never reached the signed payload (so render() can't choke on it).
    assert captured.get("result") is None


def test_real_calc_oversized_int_result_returns_signed_failure(monkeypatch):
    """End-to-end via the REAL calc tool (no monkeypatched result): pow(2, 50000) — whatever
    the sandbox does, IF a giant int reaches the endpoint it must degrade to a signed failure,
    never a 500. (If the sandbox rejects it first, that's ALSO a signed failure — either way,
    the contract holds and no 500 escapes.)"""
    captured = _setup_authorized(monkeypatch)
    resp = _run(_tool_body(arguments={"expression": "pow(2, 50000)"}))
    assert resp.status_code == 200
    body = json.loads(bytes(resp.body).decode())
    assert body["status"] == "failed"
    assert "_agentmesh" in body
    assert captured["status"] == "failed"


def test_response_build_error_degrades_to_signed_failure(monkeypatch):
    """Belt-and-suspenders: if signing the SUCCESS result raises, the endpoint still returns a
    signed status="failed" (via _signed_tool_failure), never an uncaught 500."""
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    _patch_redis(monkeypatch)
    _pass_signature_and_trust(monkeypatch)
    _pass_assertion(monkeypatch)
    _allow_policy(monkeypatch)

    # First sign_outbound_message call (the success result) blows up; the second (inside
    # _signed_tool_failure) must still produce a verifiable signed failure.
    calls = {"n": 0}
    async def flaky_sign(obj):
        calls["n"] += 1
        if calls["n"] == 1 and obj.get("status") == "completed":
            raise RuntimeError("signing backend unavailable")
        return {**obj, "_agentmesh": {"sender_did": _SELF_DID, "signature": "s", "alg": "EdDSA"}}
    monkeypatch.setattr(main.agent_identity, "sign_outbound_message", flaky_sign)

    resp = _run(_tool_body())          # tool.calc 2+3*4 — a perfectly serializable result
    assert resp.status_code == 200
    body = json.loads(bytes(resp.body).decode())
    assert body["status"] == "failed"
    assert "_agentmesh" in body        # the FAILURE response is still signed


def test_valid_result_still_succeeds_after_fix(monkeypatch):
    """Regression guard: the result-validation must NOT reject a normal, serializable result —
    the happy path (calc 2+3*4 → 14) still returns a signed status='completed'."""
    captured = _setup_authorized(monkeypatch)
    resp = _run(_tool_body())          # tool.calc, "2+3*4"
    assert resp.status_code == 200
    body = json.loads(bytes(resp.body).decode())
    assert body["status"] == "completed"
    assert body["result"]["result"] == 14
    assert captured["status"] == "completed"
