"""Cross-agent tool ORCHESTRATION tests — solve_with_tools + call_peer_tool send path.

solve_with_tools is the governed entry point that solves a sub-problem with a tool: run it
LOCALLY when we serve the capability, else DISCOVER a peer that advertises it and DELEGATE
the tool call over the DID-signed /a2a/tool channel. These hermetic tests pin:

  * a LOCAL capability runs locally — NO discovery, NO delegation;
  * a missing-LOCAL capability triggers find_peer_for_capability + call_peer_tool (both
    monkeypatched) and returns the peer's signed result;
  * no capable peer degrades gracefully (status "no_capability", never a crash);
  * the per-call delegation cap (max_tool_delegations) is enforced;
  * the deterministic router maps math/units sub-problems correctly;
  * THE no-raw-token invariant: the outbound /a2a/tool payload carries a recipient-bound
    `user_assertion` and NO raw bearer-token field (asserted against call_peer_tool's real
    payload construction via the shared signing path).

No live broker, no live mesh: discovery + the peer transport are monkeypatched; the LOCAL
path runs the real governed executor (so the local-vs-delegate decision is genuinely tested).
"""
from __future__ import annotations

import asyncio

import pytest

from agent import nodes
from mesh import peer_client as pc

_USER = "alice@example.com|deadbeefdeadbeef"
_PEER_DID = "did:mesh:peer-b"
_PEER_URL = "http://peer-b"

# A raw-token-free, recipient-bound assertion builder (what solve_with_tools is handed).
def _build_assertion(audience_did):
    return {"sub": "x", "email": "alice@example.com", "email_verified": True,
            "iss": "http://home/realms/rag", "aud": audience_did,
            "iat": 1, "exp": 9999999999, "jti": "j"}


def _allow_enforce(monkeypatch):
    async def ok(action, ctx):
        return None
    monkeypatch.setattr("agent.nodes._enforce", ok)


@pytest.fixture(autouse=True)
def _clean_mcp_cache():
    """Reset the governed MCP executor's gateway cache around each test.

    The executor caches a gateway built from settings.mcp_servers; other suites
    (test_mcp_tools) monkeypatch mcp_servers, and pytest's revert restores the string WITHOUT
    rebuilding the cache — so a stale gateway lacking the local tool servers can leak in and
    make run_local_tool fail closed ("server not configured"). Resetting here keeps the
    LOCAL-path tests order-independent (ensure_local_servers_registered then rebuilds cleanly).
    """
    from tools import mcp as mcp_tools
    mcp_tools.reset_cache()
    yield
    mcp_tools.reset_cache()


# ── router ─────────────────────────────────────────────────────────────────────

def test_router_maps_math_and_units_and_none():
    assert nodes._route_capability("2 + 3 * 4") == ("tool.calc", {"expression": "2 + 3 * 4"})
    assert nodes._route_capability("2^10")[0] == "tool.calc"
    assert nodes._route_capability("2^10")[1]["expression"] == "2**10"   # ^ normalised
    cap, args = nodes._route_capability("convert 10 km to mi")
    assert cap == "tool.units" and args == {"value": 10.0, "from": "km", "to": "mi"}
    assert nodes._route_capability("summarise the quarterly report") is None
    assert nodes._route_capability("") is None


# ── LOCAL capability runs locally — no discovery, no delegation ────────────────

def test_local_capability_runs_locally_without_delegation(monkeypatch):
    _allow_enforce(monkeypatch)

    async def boom_find(cap):
        raise AssertionError("discovery must NOT be consulted for a LOCAL capability")
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", boom_find)

    async def boom_call(*a, **k):
        raise AssertionError("call_peer_tool must NOT run for a LOCAL capability")
    monkeypatch.setattr("mesh.peer_client.call_peer_tool", boom_call)

    out = asyncio.run(nodes.solve_with_tools(
        "2 + 3 * 4", user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "completed"
    assert out["source"] == "local"
    assert out["capability"] == "tool.calc"
    assert out["result"]["result"] == 14     # the real governed local calc tool ran


def test_local_units_runs_locally(monkeypatch):
    _allow_enforce(monkeypatch)
    out = asyncio.run(nodes.solve_with_tools(
        "convert 1000 m to km", user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "completed"
    assert out["source"] == "local"
    assert out["result"]["result"] == 1.0


# ── missing-LOCAL capability → discover + delegate, return the peer's result ────

def test_missing_local_capability_delegates_to_peer(monkeypatch):
    _allow_enforce(monkeypatch)
    monkeypatch.setattr(nodes.settings, "tool_delegation_enabled", True)
    monkeypatch.setattr(nodes.settings, "max_tool_delegations", 3)
    monkeypatch.setattr(nodes.settings, "division_id", "division-a")

    # Pretend we DON'T serve tool.calc locally, so the remote branch is taken.
    monkeypatch.setattr("tools.local_tools.server_for_capability", lambda cap: None)

    from mesh.discovery import ToolPeer
    async def fake_find(cap):
        assert cap == "tool.calc"
        return ToolPeer(agent_url=_PEER_URL, agent_did=_PEER_DID,
                        division_id="division-b", capability=cap)
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", fake_find)

    captured: dict = {}
    async def fake_call(peer_url, peer_did, capability, arguments, *,
                        user_assertion, source_division, context_id=None):
        captured.update(peer_url=peer_url, peer_did=peer_did, capability=capability,
                        arguments=arguments, user_assertion=user_assertion,
                        source_division=source_division)
        return pc.PeerToolResponse(status="completed", result={"result": 14},
                                   task_id="t", peer_did=peer_did, trust_score=0.9)
    monkeypatch.setattr("mesh.peer_client.call_peer_tool", fake_call)

    out = asyncio.run(nodes.solve_with_tools(
        "2+3*4", user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "completed"
    assert out["source"] == "peer"
    assert out["peer_did"] == _PEER_DID
    assert out["result"] == {"result": 14}

    # The assertion was minted RECIPIENT-BOUND to the chosen peer's DID, and carries NO token.
    assert captured["peer_url"] == _PEER_URL
    assert captured["capability"] == "tool.calc"
    assert captured["source_division"] == "division-a"
    a = captured["user_assertion"]
    assert a["aud"] == _PEER_DID                 # bound to THIS peer
    assert "token" not in a and "access_token" not in a and "authorization" not in a


# ── default assertion path: claims from the ContextVar, bound to the peer ──────

def test_default_assertion_path_uses_context_claims_and_binds_to_peer(monkeypatch):
    """With NO build_assertion override (the request path), solve_with_tools mints the
    assertion EXACTLY as call_peer_agent does: claims from the _user_claims_ctx ContextVar
    (set by set_user_claims, not a token) bound to the chosen peer's DID via
    _bind_user_assertion. The outbound assertion carries aud=peer_did, exp/jti, and NO token."""
    _allow_enforce(monkeypatch)
    monkeypatch.setattr(nodes.settings, "tool_delegation_enabled", True)
    monkeypatch.setattr(nodes.settings, "max_tool_delegations", 3)
    monkeypatch.setattr(nodes.settings, "division_id", "division-a")
    monkeypatch.setattr("tools.local_tools.server_for_capability", lambda cap: None)

    # The per-request claims the home division validated (sub/email/email_verified/iss).
    claims = {"sub": "u1", "email": "alice@example.com", "email_verified": True,
              "iss": "http://home/realms/rag"}
    nodes.set_user_claims(claims)

    from mesh.discovery import ToolPeer
    async def fake_find(cap):
        return ToolPeer(agent_url=_PEER_URL, agent_did=_PEER_DID,
                        division_id="division-b", capability=cap)
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", fake_find)

    captured: dict = {}
    async def fake_call(peer_url, peer_did, capability, arguments, *,
                        user_assertion, source_division, context_id=None):
        captured.update(user_assertion=user_assertion)
        return pc.PeerToolResponse(status="completed", result={"result": 14},
                                   task_id="t", peer_did=peer_did, trust_score=0.9)
    monkeypatch.setattr("mesh.peer_client.call_peer_tool", fake_call)

    out = asyncio.run(nodes.solve_with_tools("2+3*4", user_id=_USER))   # NO build_assertion
    assert out["status"] == "completed" and out["source"] == "peer"

    a = captured["user_assertion"]
    # Recipient-bound to THIS peer + carries the validated claims, NEVER a token.
    assert a["aud"] == _PEER_DID
    assert a["email"] == "alice@example.com" and a["iss"] == "http://home/realms/rag"
    assert "exp" in a and "jti" in a
    for forbidden in ("token", "access_token", "id_token", "authorization", "bearer", "jwt"):
        assert forbidden not in a


# ── no capable peer → graceful degradation ─────────────────────────────────────

def test_no_peer_degrades_gracefully(monkeypatch):
    _allow_enforce(monkeypatch)
    monkeypatch.setattr(nodes.settings, "tool_delegation_enabled", True)
    monkeypatch.setattr(nodes.settings, "max_tool_delegations", 3)
    monkeypatch.setattr("tools.local_tools.server_for_capability", lambda cap: None)

    async def fake_find(cap):
        return None                  # broker found nobody / broker down
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", fake_find)

    async def boom_call(*a, **k):
        raise AssertionError("must not delegate when no peer was found")
    monkeypatch.setattr("mesh.peer_client.call_peer_tool", boom_call)

    out = asyncio.run(nodes.solve_with_tools(
        "2+3*4", user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "no_capability"
    assert out["source"] == "none"
    assert "tool.calc" in out["reason"]


def test_unknown_capability_degrades(monkeypatch):
    _allow_enforce(monkeypatch)
    out = asyncio.run(nodes.solve_with_tools(
        "tell me a story", user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "no_capability"
    assert out["source"] == "none"


# ── delegation cap enforced ────────────────────────────────────────────────────

def test_delegation_cap_enforced(monkeypatch):
    _allow_enforce(monkeypatch)
    monkeypatch.setattr(nodes.settings, "tool_delegation_enabled", True)
    monkeypatch.setattr("tools.local_tools.server_for_capability", lambda cap: None)

    async def boom_find(cap):
        raise AssertionError("discovery must NOT run once the delegation cap is hit")
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", boom_find)

    out = asyncio.run(nodes.solve_with_tools(
        "2+3*4", user_id=_USER, build_assertion=_build_assertion, max_delegations=0))
    assert out["status"] == "failed"
    assert "cap" in out["reason"].lower()


def test_delegation_disabled_degrades(monkeypatch):
    _allow_enforce(monkeypatch)
    monkeypatch.setattr(nodes.settings, "tool_delegation_enabled", False)
    monkeypatch.setattr("tools.local_tools.server_for_capability", lambda cap: None)

    async def boom_find(cap):
        raise AssertionError("discovery must NOT run when delegation is disabled")
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", boom_find)

    out = asyncio.run(nodes.solve_with_tools(
        "2+3*4", user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "no_capability"
    assert out["source"] == "none"


def test_peer_failure_degrades(monkeypatch):
    _allow_enforce(monkeypatch)
    monkeypatch.setattr(nodes.settings, "tool_delegation_enabled", True)
    monkeypatch.setattr(nodes.settings, "max_tool_delegations", 3)
    monkeypatch.setattr("tools.local_tools.server_for_capability", lambda cap: None)

    from mesh.discovery import ToolPeer
    async def fake_find(cap):
        return ToolPeer(agent_url=_PEER_URL, agent_did=_PEER_DID,
                        division_id="division-b", capability=cap)
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", fake_find)

    async def failing_call(*a, **k):
        raise RuntimeError("transport blew up")
    monkeypatch.setattr("mesh.peer_client.call_peer_tool", failing_call)

    out = asyncio.run(nodes.solve_with_tools(
        "2+3*4", user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "failed"
    assert out["source"] == "peer"


# ── call_peer_tool SEND path: no-raw-token invariant on the wire ───────────────

def test_call_peer_tool_payload_has_assertion_no_token(monkeypatch):
    """The outbound /a2a/tool payload that gets SIGNED carries a recipient-bound
    user_assertion and NO raw bearer-token field. Drives call_peer_tool's real payload
    construction with the network/DID/governance steps stubbed (hermetic)."""
    from config import Settings
    s = Settings(_env_file=None, openai_api_key="t", openfga_store_id="t",
                 openfga_model_id="t", neo4j_password="t", agent_client_id="t",
                 agent_client_secret="t", agent_sponsor_email="s@e.com",
                 approval_hmac_secret="0" * 64, cluster_id="cluster-a",
                 division_id="division-a")
    monkeypatch.setattr(pc, "settings", s)

    captured: dict = {}

    async def _verify_peer(_did):
        return True, 1.0
    async def _govern(_action, _ctx):
        class _G:
            allowed = True
            decision = "allow"
        return _G()
    async def _sign(payload):
        captured.update(payload)
        return {**payload, "_agentmesh": {"sender_did": "x", "signature": "y", "alg": "EdDSA"}}

    class _Breaker:
        def get_state(self):
            from agent_os.circuit_breaker import CircuitState
            return CircuitState.CLOSED
        def record_success(self): ...
        def record_failure(self): ...
    async def _get_cb(_url):
        return _Breaker()
    async def _report(*_a, **_k):
        return None

    class _Resp:
        def raise_for_status(self): ...
        def json(self):
            return {"status": "completed", "result": {"result": 14}, "task_id": "t",
                    "_agentmesh": {"sender_did": _PEER_DID, "signature": "y", "alg": "EdDSA"}}

    class _Client:
        def __init__(self, *a, **k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return _Resp()

    async def _verify_signed(_resp):
        return True, _PEER_DID

    monkeypatch.setattr(pc, "verify_peer_identity", _verify_peer)
    monkeypatch.setattr(pc, "govern_action", _govern)
    monkeypatch.setattr(pc, "sign_outbound_message", _sign)
    monkeypatch.setattr(pc, "_get_circuit_breaker", _get_cb)
    monkeypatch.setattr(pc, "report_trust_event", _report)
    monkeypatch.setattr(pc, "verify_signed_message", _verify_signed)
    monkeypatch.setattr(pc.httpx, "AsyncClient", _Client)

    assertion = _build_assertion(_PEER_DID)
    resp = asyncio.run(pc.call_peer_tool(
        _PEER_URL, _PEER_DID, "tool.calc", {"expression": "2+3*4"},
        user_assertion=assertion, source_division="division-a"))

    assert resp.status == "completed"
    assert resp.result == {"result": 14}
    assert resp.peer_did == _PEER_DID

    # The SIGNED payload: a recipient-bound assertion, NO raw token of any kind.
    assert captured["capability"] == "tool.calc"
    assert captured["arguments"] == {"expression": "2+3*4"}
    assert captured["source_division"] == "division-a"
    assert captured["user_assertion"]["aud"] == _PEER_DID
    for forbidden in ("token", "access_token", "id_token", "authorization", "bearer", "jwt"):
        assert forbidden not in captured, f"raw credential field {forbidden!r} leaked on the wire"


def test_call_peer_tool_fails_closed_on_bad_response_signature(monkeypatch):
    """If the peer's response signature does not verify (or the signer != peer_did), the
    send path fails closed — no result is trusted."""
    from agentmesh.exceptions import AgentMeshError
    from config import Settings
    s = Settings(_env_file=None, openai_api_key="t", openfga_store_id="t",
                 openfga_model_id="t", neo4j_password="t", agent_client_id="t",
                 agent_client_secret="t", agent_sponsor_email="s@e.com",
                 approval_hmac_secret="0" * 64, division_id="division-a")
    monkeypatch.setattr(pc, "settings", s)

    async def _verify_peer(_did): return True, 1.0
    async def _govern(_a, _c):
        class _G:
            allowed = True
            decision = "allow"
        return _G()
    async def _sign(p): return {**p, "_agentmesh": {"sender_did": "x"}}
    class _Breaker:
        def get_state(self):
            from agent_os.circuit_breaker import CircuitState
            return CircuitState.CLOSED
        def record_success(self): ...
        def record_failure(self): ...
    async def _get_cb(_u): return _Breaker()
    async def _report(*_a, **_k): return None
    class _Resp:
        def raise_for_status(self): ...
        def json(self): return {"status": "completed", "_agentmesh": {}}
    class _Client:
        def __init__(self, *a, **k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return _Resp()
    async def _verify_signed(_r):
        return False, None        # response signature does NOT verify

    monkeypatch.setattr(pc, "verify_peer_identity", _verify_peer)
    monkeypatch.setattr(pc, "govern_action", _govern)
    monkeypatch.setattr(pc, "sign_outbound_message", _sign)
    monkeypatch.setattr(pc, "_get_circuit_breaker", _get_cb)
    monkeypatch.setattr(pc, "report_trust_event", _report)
    monkeypatch.setattr(pc, "verify_signed_message", _verify_signed)
    monkeypatch.setattr(pc.httpx, "AsyncClient", _Client)

    with pytest.raises(AgentMeshError):
        asyncio.run(pc.call_peer_tool(
            _PEER_URL, _PEER_DID, "tool.calc", {"expression": "1"},
            user_assertion=_build_assertion(_PEER_DID), source_division="division-a"))


# ── find_peer_for_capability: discover → negotiate → trust-anchor resolution ───

def _patch_discovery_env(monkeypatch, peer_trust):
    """Enable discovery (broker URL set) and install a DATA-PATH trust anchor + skip the
    lazy self-registration network call."""
    from mesh import discovery as disc
    monkeypatch.setenv("DISCOVERY_URL", "http://broker")
    monkeypatch.setattr(disc.settings, "peer_trust_map", __import__("json").dumps(peer_trust))
    async def _no_register(url): return None
    monkeypatch.setattr(disc, "_ensure_registered", _no_register)
    return disc


def test_find_peer_for_capability_returns_trusted_negotiated_peer(monkeypatch):
    anchor = {_PEER_DID: {"issuer": "http://peer-b/realms/rag", "public_jwk": "",
                          "agent_url": _PEER_URL, "division_id": "division-b"}}
    disc = _patch_discovery_env(monkeypatch, anchor)

    async def fake_discover(url, capability=None):
        assert capability == "tool.calc"
        # Broker (open registry) returns the trusted DID advertising the capability — but
        # with an ATTACKER-influenced agent_url that must be IGNORED in favour of the anchor.
        return [{"agent_did": _PEER_DID, "agent_url": "http://attacker.example",
                 "capabilities": ["tool.calc"]}]
    monkeypatch.setattr(disc, "_discover_peers", fake_discover)

    peer = asyncio.run(disc.find_peer_for_capability("tool.calc"))
    assert peer is not None
    assert peer.agent_did == _PEER_DID
    assert peer.agent_url == _PEER_URL          # from the trust ANCHOR, not the broker entry
    assert peer.division_id == "division-b"
    assert peer.capability == "tool.calc"


def test_find_peer_skips_untrusted_did(monkeypatch):
    # Broker advertises a DID that is NOT in our trust anchor → skipped → None.
    disc = _patch_discovery_env(monkeypatch, {})   # empty anchor: nobody is trusted

    async def fake_discover(url, capability=None):
        return [{"agent_did": "did:mesh:stranger", "agent_url": "http://x",
                 "capabilities": ["tool.calc"]}]
    monkeypatch.setattr(disc, "_discover_peers", fake_discover)

    assert asyncio.run(disc.find_peer_for_capability("tool.calc")) is None


def test_find_peer_skips_peer_that_does_not_advertise_capability(monkeypatch):
    anchor = {_PEER_DID: {"issuer": "i", "public_jwk": "", "agent_url": _PEER_URL,
                          "division_id": "division-b"}}
    disc = _patch_discovery_env(monkeypatch, anchor)

    async def fake_discover(url, capability=None):
        # Trusted, but advertises a DIFFERENT capability → negotiation fails → None.
        return [{"agent_did": _PEER_DID, "agent_url": _PEER_URL,
                 "capabilities": ["tool.units"]}]
    monkeypatch.setattr(disc, "_discover_peers", fake_discover)

    assert asyncio.run(disc.find_peer_for_capability("tool.calc")) is None


def test_find_peer_returns_none_when_broker_unreachable(monkeypatch):
    disc = _patch_discovery_env(monkeypatch, {})

    async def boom(url, capability=None):
        raise RuntimeError("broker down")
    monkeypatch.setattr(disc, "_discover_peers", boom)

    # Graceful degradation: a broker failure yields None, never an exception.
    assert asyncio.run(disc.find_peer_for_capability("tool.calc")) is None


def test_find_peer_returns_none_when_discovery_disabled(monkeypatch):
    from mesh import discovery as disc
    monkeypatch.delenv("DISCOVERY_URL", raising=False)
    assert asyncio.run(disc.find_peer_for_capability("tool.calc")) is None


def test_advertised_capabilities_includes_local_tools(monkeypatch):
    from mesh import discovery as disc
    monkeypatch.setenv("AGENT_CAPABILITIES", "finance, hr")
    caps = disc.advertised_capabilities()
    # Env-declared capabilities come first, then the LOCAL tool capabilities are appended.
    assert caps[:2] == ["finance", "hr"]
    assert "tool.calc" in caps and "tool.units" in caps
