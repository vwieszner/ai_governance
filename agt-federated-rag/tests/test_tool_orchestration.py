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

def test_router_maps_all_four_capabilities_and_none():
    # PII screen: the whole problem text IS the input to scan.
    cap, args = nodes._route_capability("Screen this for PII: alice@example.com")
    assert cap == "tool.pii"
    assert args == {"text": "Screen this for PII: alice@example.com"}
    assert nodes._route_capability("redact the customer record")[0] == "tool.pii"
    # Data-sensitivity classification → tool.classify (also takes {"text": ...}).
    cap, args = nodes._route_capability("Classify the sensitivity of this document")
    assert cap == "tool.classify"
    assert args == {"text": "Classify the sensitivity of this document"}
    assert nodes._route_capability("what confidentiality level is this")[0] == "tool.classify"
    # EU AI Act risk TIERING → tool.risk (input key is "description", NOT text/topic).
    cap, args = nodes._route_capability("Assess the risk tier of this CV-screening system")
    assert cap == "tool.risk"
    assert args == {"description": "Assess the risk tier of this CV-screening system"}
    assert nodes._route_capability("which tier is a recruitment AI")[0] == "tool.risk"
    # Compliance / obligation lookup: the problem text is the topic. "high-risk" stays
    # compliance (an article lookup), NOT risk tiering.
    cap, args = nodes._route_capability("Which EU AI Act article covers high-risk systems?")
    assert cap == "tool.compliance"
    assert args == {"topic": "Which EU AI Act article covers high-risk systems?"}
    assert nodes._route_capability("what are our GDPR obligations")[0] == "tool.compliance"
    # No tool grammar matches → None (caller degrades).
    assert nodes._route_capability("tell me a joke") is None
    assert nodes._route_capability("") is None


def test_router_risk_phrasings_map_to_tool_risk():
    """Risk-tiering intents (assess / tier / 'is this high-risk' / 'AI system' wording) route to
    tool.risk with the 'description' argument key — and do NOT fall into the compliance lookup."""
    for problem in (
        "Is this high-risk?",
        "Is this AI system high-risk?",
        "Assess this AI system",
        "What risk tier is a recruitment AI?",
        "which tier is this hiring use case",
    ):
        cap, args = nodes._route_capability(problem)
        assert cap == "tool.risk", problem
        assert args == {"description": problem}


def test_router_classify_phrasings_map_to_tool_classify():
    """Classification intents (classify / sensitivity / label / 'how sensitive' wording) route to
    tool.classify with the 'text' argument key."""
    for problem in (
        "Classify the sensitivity of this document",
        "How sensitive is this file?",
        "Label this document",
        "What confidentiality level is this?",
    ):
        cap, args = nodes._route_capability(problem)
        assert cap == "tool.classify", problem
        assert args == {"text": problem}


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
        "Screen this for PII: alice@example.com", user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "completed"
    assert out["source"] == "local"
    assert out["capability"] == "tool.pii"
    # the real governed local pii-scan tool ran (found + masked the e-mail)
    assert out["result"]["has_pii"] is True
    assert out["result"]["findings"][0]["type"] == "EMAIL"


def test_local_compliance_runs_locally(monkeypatch):
    _allow_enforce(monkeypatch)
    out = asyncio.run(nodes.solve_with_tools(
        "Which EU AI Act article covers high-risk systems?",
        user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "completed"
    assert out["source"] == "local"
    assert out["capability"] == "tool.compliance"
    assert any(m["framework"] == "EU AI Act" for m in out["result"]["matches"])


def test_direct_capability_bypasses_router(monkeypatch):
    """The /solve DIRECT form: an explicit capability + arguments skips _route_capability and
    runs the tool with exactly the arguments given."""
    _allow_enforce(monkeypatch)
    out = asyncio.run(nodes.solve_with_tools(
        None, user_id=_USER, capability="tool.pii",
        arguments={"text": "card 4111 1111 1111 1111"}, build_assertion=_build_assertion))
    assert out["status"] == "completed"
    assert out["source"] == "local"
    assert out["capability"] == "tool.pii"
    assert out["result"]["findings"][0]["type"] == "CARD"   # Luhn-valid test card


# ── missing-LOCAL capability → discover + delegate, return the peer's result ────

def test_missing_local_capability_delegates_to_peer(monkeypatch):
    _allow_enforce(monkeypatch)
    monkeypatch.setattr(nodes.settings, "tool_delegation_enabled", True)
    monkeypatch.setattr(nodes.settings, "max_tool_delegations", 3)
    monkeypatch.setattr(nodes.settings, "division_id", "division-a")

    # Pretend we DON'T serve tool.compliance locally, so the remote branch is taken.
    monkeypatch.setattr("tools.local_tools.server_for_capability", lambda cap: None)

    from mesh.discovery import ToolPeer
    async def fake_find(cap):
        assert cap == "tool.compliance"
        return ToolPeer(agent_url=_PEER_URL, agent_did=_PEER_DID,
                        division_id="division-b", capability=cap)
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", fake_find)

    peer_result = {"topic": "high-risk", "matches": [{"framework": "EU AI Act",
                   "article": "Art. 6", "summary": "..."}]}
    captured: dict = {}
    async def fake_call(peer_url, peer_did, capability, arguments, *,
                        user_assertion, source_division, context_id=None):
        captured.update(peer_url=peer_url, peer_did=peer_did, capability=capability,
                        arguments=arguments, user_assertion=user_assertion,
                        source_division=source_division)
        return pc.PeerToolResponse(status="completed", result=peer_result,
                                   task_id="t", peer_did=peer_did, trust_score=0.9)
    monkeypatch.setattr("mesh.peer_client.call_peer_tool", fake_call)

    out = asyncio.run(nodes.solve_with_tools(
        "Which EU AI Act article covers high-risk systems?",
        user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "completed"
    assert out["source"] == "peer"
    assert out["peer_did"] == _PEER_DID
    assert out["result"] == peer_result

    # The assertion was minted RECIPIENT-BOUND to the chosen peer's DID, and carries NO token.
    assert captured["peer_url"] == _PEER_URL
    assert captured["capability"] == "tool.compliance"
    assert captured["arguments"] == {"topic": "Which EU AI Act article covers high-risk systems?"}
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
        return pc.PeerToolResponse(status="completed", result={"matches": []},
                                   task_id="t", peer_did=peer_did, trust_score=0.9)
    monkeypatch.setattr("mesh.peer_client.call_peer_tool", fake_call)

    # NO build_assertion → the assertion is minted from the ContextVar claims.
    out = asyncio.run(nodes.solve_with_tools(
        "what are our GDPR obligations", user_id=_USER))
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
        "what are our GDPR obligations", user_id=_USER, build_assertion=_build_assertion))
    assert out["status"] == "no_capability"
    assert out["source"] == "none"
    assert "tool.compliance" in out["reason"]


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
        "what are our GDPR obligations", user_id=_USER,
        build_assertion=_build_assertion, max_delegations=0))
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
        "what are our GDPR obligations", user_id=_USER, build_assertion=_build_assertion))
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
        "what are our GDPR obligations", user_id=_USER, build_assertion=_build_assertion))
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
            return {"status": "completed", "result": {"matches": []}, "task_id": "t",
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
        _PEER_URL, _PEER_DID, "tool.compliance", {"topic": "high-risk"},
        user_assertion=assertion, source_division="division-a"))

    assert resp.status == "completed"
    assert resp.result == {"matches": []}
    assert resp.peer_did == _PEER_DID

    # The SIGNED payload: a recipient-bound assertion, NO raw token of any kind.
    assert captured["capability"] == "tool.compliance"
    assert captured["arguments"] == {"topic": "high-risk"}
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
            _PEER_URL, _PEER_DID, "tool.compliance", {"topic": "high-risk"},
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
        assert capability == "tool.compliance"
        # Broker (open registry) returns the trusted DID advertising the capability — but
        # with an ATTACKER-influenced agent_url that must be IGNORED in favour of the anchor.
        return [{"agent_did": _PEER_DID, "agent_url": "http://attacker.example",
                 "capabilities": ["tool.compliance"]}]
    monkeypatch.setattr(disc, "_discover_peers", fake_discover)

    peer = asyncio.run(disc.find_peer_for_capability("tool.compliance"))
    assert peer is not None
    assert peer.agent_did == _PEER_DID
    assert peer.agent_url == _PEER_URL          # from the trust ANCHOR, not the broker entry
    assert peer.division_id == "division-b"
    assert peer.capability == "tool.compliance"


def test_find_peer_skips_untrusted_did(monkeypatch):
    # Broker advertises a DID that is NOT in our trust anchor → skipped → None.
    disc = _patch_discovery_env(monkeypatch, {})   # empty anchor: nobody is trusted

    async def fake_discover(url, capability=None):
        return [{"agent_did": "did:mesh:stranger", "agent_url": "http://x",
                 "capabilities": ["tool.compliance"]}]
    monkeypatch.setattr(disc, "_discover_peers", fake_discover)

    assert asyncio.run(disc.find_peer_for_capability("tool.compliance")) is None


def test_find_peer_skips_peer_that_does_not_advertise_capability(monkeypatch):
    anchor = {_PEER_DID: {"issuer": "i", "public_jwk": "", "agent_url": _PEER_URL,
                          "division_id": "division-b"}}
    disc = _patch_discovery_env(monkeypatch, anchor)

    async def fake_discover(url, capability=None):
        # Trusted, but advertises a DIFFERENT capability → negotiation fails → None.
        return [{"agent_did": _PEER_DID, "agent_url": _PEER_URL,
                 "capabilities": ["tool.pii"]}]
    monkeypatch.setattr(disc, "_discover_peers", fake_discover)

    assert asyncio.run(disc.find_peer_for_capability("tool.compliance")) is None


def test_find_peer_returns_none_when_broker_unreachable(monkeypatch):
    disc = _patch_discovery_env(monkeypatch, {})

    async def boom(url, capability=None):
        raise RuntimeError("broker down")
    monkeypatch.setattr(disc, "_discover_peers", boom)

    # Graceful degradation: a broker failure with no configured route yields None, not a raise.
    monkeypatch.setattr(disc.settings, "peer_tool_map", "")
    assert asyncio.run(disc.find_peer_for_capability("tool.compliance")) is None


def test_find_peer_returns_none_when_discovery_disabled(monkeypatch):
    from mesh import discovery as disc
    monkeypatch.delenv("DISCOVERY_URL", raising=False)
    monkeypatch.setattr(disc.settings, "peer_tool_map", "")   # no configured route either
    assert asyncio.run(disc.find_peer_for_capability("tool.compliance")) is None


# ── CONFIGURED (broker-less) peer_tool_map fallback ────────────────────────────

def test_find_peer_configured_fallback_no_broker(monkeypatch):
    """With NO discovery broker but a peer_tool_map entry whose DID is a trust anchor,
    find_peer_for_capability resolves the peer from the CONFIGURED map + the anchor (the
    template-deployment path that needs no broker service)."""
    import json as _json
    from mesh import discovery as disc
    monkeypatch.delenv("DISCOVERY_URL", raising=False)        # no broker
    anchor = {_PEER_DID: {"issuer": "i", "public_jwk": "", "agent_url": _PEER_URL,
                          "division_id": "division-b"}}
    monkeypatch.setattr(disc.settings, "peer_trust_map", _json.dumps(anchor))
    monkeypatch.setattr(disc.settings, "peer_tool_map",
                        _json.dumps({"tool.compliance": _PEER_DID}))

    peer = asyncio.run(disc.find_peer_for_capability("tool.compliance"))
    assert peer is not None
    assert peer.agent_did == _PEER_DID
    assert peer.agent_url == _PEER_URL          # from the trust ANCHOR (never fabricated)
    assert peer.division_id == "division-b"
    assert peer.capability == "tool.compliance"


def test_find_peer_configured_fallback_did_not_in_trust_returns_none(monkeypatch):
    """A peer_tool_map DID that is NOT a trust anchor resolves to None — the map can only
    SELECT among already-trusted peers; it can never fabricate one (security boundary)."""
    import json as _json
    from mesh import discovery as disc
    monkeypatch.delenv("DISCOVERY_URL", raising=False)
    monkeypatch.setattr(disc.settings, "peer_trust_map", "{}")   # nobody trusted
    monkeypatch.setattr(disc.settings, "peer_tool_map",
                        _json.dumps({"tool.compliance": "did:mesh:stranger"}))

    assert asyncio.run(disc.find_peer_for_capability("tool.compliance")) is None


def test_find_peer_configured_fallback_when_broker_returns_nothing(monkeypatch):
    """Broker is configured but returns no trusted peer → the CONFIGURED map is the fallback."""
    import json as _json
    anchor = {_PEER_DID: {"issuer": "i", "public_jwk": "", "agent_url": _PEER_URL,
                          "division_id": "division-b"}}
    disc = _patch_discovery_env(monkeypatch, anchor)         # broker URL set
    monkeypatch.setattr(disc.settings, "peer_tool_map",
                        _json.dumps({"tool.compliance": _PEER_DID}))

    async def empty_discover(url, capability=None):
        return []                                            # broker knows no capable peer
    monkeypatch.setattr(disc, "_discover_peers", empty_discover)

    peer = asyncio.run(disc.find_peer_for_capability("tool.compliance"))
    assert peer is not None and peer.agent_did == _PEER_DID
    assert peer.agent_url == _PEER_URL


def test_peer_tool_map_routes_each_capability_to_its_own_peer(monkeypatch):
    """PEER_TOOL_MAP is a full ROUTING TABLE: different capabilities resolve to DIFFERENT
    trusted peers (didA vs didB), each peer's url/division taken from its OWN trust anchor."""
    import json as _json
    from mesh import discovery as disc
    monkeypatch.delenv("DISCOVERY_URL", raising=False)            # broker-less: pure configured
    did_a, url_a = "did:mesh:division-b", "http://division-b"
    did_b, url_b = "did:mesh:division-c", "http://division-c"
    anchor = {
        did_a: {"issuer": "ia", "public_jwk": "", "agent_url": url_a, "division_id": "division-b"},
        did_b: {"issuer": "ib", "public_jwk": "", "agent_url": url_b, "division_id": "division-c"},
    }
    monkeypatch.setattr(disc.settings, "peer_trust_map", _json.dumps(anchor))
    monkeypatch.setattr(disc.settings, "peer_tool_map",
                        _json.dumps({"tool.compliance": did_a, "tool.risk": did_b}))

    peer_c = asyncio.run(disc.find_peer_for_capability("tool.compliance"))
    assert peer_c is not None
    assert peer_c.agent_did == did_a and peer_c.agent_url == url_a
    assert peer_c.division_id == "division-b" and peer_c.capability == "tool.compliance"

    peer_r = asyncio.run(disc.find_peer_for_capability("tool.risk"))
    assert peer_r is not None
    assert peer_r.agent_did == did_b and peer_r.agent_url == url_b
    assert peer_r.division_id == "division-c" and peer_r.capability == "tool.risk"

    # A capability not in the table (this division serves it, or nobody does) → no route.
    assert asyncio.run(disc.find_peer_for_capability("tool.classify")) is None


def test_locally_served_capability_not_delegated_even_if_in_map(monkeypatch):
    """solve_with_tools prefers LOCAL: a capability this division serves locally runs locally
    and is NOT delegated even when PEER_TOOL_MAP names a peer for it (local-first invariant)."""
    import json as _json
    _allow_enforce(monkeypatch)
    monkeypatch.setattr(nodes.settings, "tool_delegation_enabled", True)
    monkeypatch.setattr(nodes.settings, "division_id", "division-a")
    # This division SERVES tool.pii locally — server_for_capability returns the real server.
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)          # serve all local tools
    # ...yet the routing table ALSO lists a peer for tool.pii.
    monkeypatch.setattr(nodes.settings, "peer_tool_map",
                        _json.dumps({"tool.pii": _PEER_DID}))

    # Discovery / delegation MUST NOT be consulted for a locally-served capability.
    async def boom_find(cap):
        raise AssertionError("a locally-served capability must NOT be routed to a peer")
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", boom_find)
    async def boom_call(*a, **k):
        raise AssertionError("call_peer_tool must NOT run for a locally-served capability")
    monkeypatch.setattr("mesh.peer_client.call_peer_tool", boom_call)

    out = asyncio.run(nodes.solve_with_tools(
        None, user_id=_USER, capability="tool.pii",
        arguments={"text": "reach me at alice@example.com"}, build_assertion=_build_assertion))
    assert out["status"] == "completed"
    assert out["source"] == "local"            # ran locally despite the map entry
    assert out["capability"] == "tool.pii"
    assert out["result"]["has_pii"] is True


def test_advertised_capabilities_includes_local_tools(monkeypatch):
    from mesh import discovery as disc
    monkeypatch.setenv("AGENT_CAPABILITIES", "finance, hr")
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)      # serve ALL local tools
    caps = disc.advertised_capabilities()
    # Env-declared capabilities come first, then the LOCAL tool capabilities are appended.
    assert caps[:2] == ["finance", "hr"]
    for cap in ("tool.pii", "tool.compliance", "tool.risk", "tool.classify"):
        assert cap in caps


# ── POST /solve endpoint — the governed user trigger ───────────────────────────
# These drive the endpoint coroutine directly (the same pattern test_killswitch.py uses for
# /query): the JWT + rate-limit gates are monkeypatched, and the solve path runs either the
# REAL local tool (served capability) or a monkeypatched discover+delegate (lacked capability).

from api import main   # noqa: E402

_SOLVE_CLAIMS = {"sub": "kc-mem", "email": "alice@example.com", "email_verified": True,
                 "iss": "http://localhost:9002/realms/rag"}


class _SolveFakeRedis:
    def __init__(self): self.kv: dict = {}
    async def get(self, k): return self.kv.get(k)
    async def set(self, k, v): self.kv[k] = v
    async def incr(self, k):
        self.kv[k] = int(self.kv.get(k, 0)) + 1
        return self.kv[k]
    async def expire(self, k, ttl): return True


def _solve_req(body: dict):
    class _Req:
        async def json(self): return body
    return _Req()


def _patch_solve_auth(monkeypatch):
    """Pass the /solve auth gates (kill-switch off, valid bearer, principal, no rate-limit)."""
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "division-a")
    fake = _SolveFakeRedis()
    async def get_redis(): return fake
    monkeypatch.setattr(main, "_get_redis", get_redis)
    async def fake_bearer(auth): return ("tok", _SOLVE_CLAIMS)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)
    monkeypatch.setattr(main, "principal", lambda claims: _USER)
    async def no_rl(subject): return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rl)
    # Allow every governance gate so the real local tool can run end-to-end.
    async def ok(action, ctx): return None
    monkeypatch.setattr("agent.nodes._enforce", ok)
    from tools import mcp as mcp_tools
    mcp_tools.reset_cache()
    return fake


def test_solve_runs_served_capability_locally(monkeypatch):
    """A request whose capability THIS division serves runs LOCALLY through the governed
    executor — no discovery, no delegation. DIRECT form ({capability, arguments})."""
    _patch_solve_auth(monkeypatch)
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)     # serve all local tools

    async def boom_find(cap):
        raise AssertionError("discovery must NOT run for a locally-served capability")
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", boom_find)

    body = {"capability": "tool.pii", "arguments": {"text": "reach me at alice@example.com"}}
    resp = asyncio.run(main.solve(_solve_req(body), authorization="Bearer tok"))
    out = __import__("json").loads(bytes(resp.body).decode())
    assert out["status"] == "completed"
    assert out["source"] == "local"
    assert out["capability"] == "tool.pii"
    assert out["result"]["has_pii"] is True
    assert out["result"]["findings"][0]["type"] == "EMAIL"


def test_solve_routes_free_text_problem(monkeypatch):
    """ROUTED form: a free-text 'problem' is mapped to a capability by _route_capability."""
    _patch_solve_auth(monkeypatch)
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)

    body = {"problem": "Which EU AI Act article covers high-risk systems?"}
    resp = asyncio.run(main.solve(_solve_req(body), authorization="Bearer tok"))
    out = __import__("json").loads(bytes(resp.body).decode())
    assert out["status"] == "completed"
    assert out["source"] == "local"
    assert out["capability"] == "tool.compliance"
    assert any(m["framework"] == "EU AI Act" for m in out["result"]["matches"])


def test_solve_routes_risk_problem_with_description_key(monkeypatch):
    """A risk-tiering problem routes to tool.risk and runs the REAL local risk-score tool —
    confirming the router builds the right per-capability argument key ("description")."""
    _patch_solve_auth(monkeypatch)
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)

    body = {"problem": "Assess the risk tier of a CV-screening recruitment system"}
    resp = asyncio.run(main.solve(_solve_req(body), authorization="Bearer tok"))
    out = __import__("json").loads(bytes(resp.body).decode())
    assert out["status"] == "completed"
    assert out["source"] == "local"
    assert out["capability"] == "tool.risk"
    # recruitment / CV-screening is an Annex III high-risk use case.
    assert out["result"]["tier"] == "high"


def test_solve_delegates_when_capability_lacked(monkeypatch):
    """A request whose capability this division LACKS is delegated: server_for_capability→None,
    find_peer_for_capability→a fake peer, call_peer_tool→a result; /solve returns it."""
    _patch_solve_auth(monkeypatch)
    monkeypatch.setattr(main.settings, "tool_delegation_enabled", True)
    monkeypatch.setattr(main.settings, "max_tool_delegations", 3)
    # This division serves NO local tools → every capability must delegate.
    monkeypatch.setattr("tools.local_tools.server_for_capability", lambda cap: None)

    from mesh.discovery import ToolPeer
    async def fake_find(cap):
        assert cap == "tool.compliance"
        return ToolPeer(agent_url=_PEER_URL, agent_did=_PEER_DID,
                        division_id="division-b", capability=cap)
    monkeypatch.setattr("mesh.discovery.find_peer_for_capability", fake_find)

    peer_result = {"topic": "high-risk", "matches": [{"framework": "EU AI Act",
                   "article": "Art. 6", "summary": "..."}]}
    captured: dict = {}
    async def fake_call(peer_url, peer_did, capability, arguments, *,
                        user_assertion, source_division, context_id=None):
        captured.update(user_assertion=user_assertion, capability=capability)
        return pc.PeerToolResponse(status="completed", result=peer_result,
                                   task_id="t", peer_did=peer_did, trust_score=0.9)
    monkeypatch.setattr("mesh.peer_client.call_peer_tool", fake_call)

    body = {"capability": "tool.compliance", "arguments": {"topic": "high-risk"}}
    resp = asyncio.run(main.solve(_solve_req(body), authorization="Bearer tok"))
    out = __import__("json").loads(bytes(resp.body).decode())
    assert out["status"] == "completed"
    assert out["source"] == "peer"
    assert out["peer_did"] == _PEER_DID
    assert out["result"] == peer_result
    # The delegated assertion was minted from the request CLAIMS (set_user_claims), bound to
    # the peer, and carries NO raw token — the no-raw-token invariant on the /solve path.
    a = captured["user_assertion"]
    assert a["aud"] == _PEER_DID
    for forbidden in ("token", "access_token", "id_token", "authorization", "bearer", "jwt"):
        assert forbidden not in a


def test_solve_401_without_token(monkeypatch):
    """No Authorization header → 401 (the real _get_bearer_token fails closed)."""
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "division-a")
    fake = _SolveFakeRedis()
    async def get_redis(): return fake
    monkeypatch.setattr(main, "_get_redis", get_redis)
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.solve(_solve_req({"problem": "screen for PII"}), authorization=None))
    assert ei.value.status_code == 401


def test_solve_503_on_kill_switch(monkeypatch):
    """Kill-switch engaged → 503 before any auth/tool work (administrative disable)."""
    monkeypatch.setattr(main.settings, "agent_kill_switch_engaged", False)
    monkeypatch.setattr(main.settings, "division_id", "division-a")
    fake = _SolveFakeRedis()
    fake.kv[main._killswitch_key("division-a")] = "1"   # runtime engage
    async def get_redis(): return fake
    monkeypatch.setattr(main, "_get_redis", get_redis)
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.solve(_solve_req({"problem": "screen for PII"}),
                               authorization="Bearer tok"))
    assert ei.value.status_code == 503
