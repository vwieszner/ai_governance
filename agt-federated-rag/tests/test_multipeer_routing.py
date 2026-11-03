"""True multi-peer routing for discovered delegation (FR-3 residual).

When discovery selects a peer, the DID-signed request must go to THAT peer — for query
delegation (/a2a/query via call_peer_agent) and tool delegation (/a2a/tool via
call_peer_tool / solve_with_tools). These pin the routing + its security invariants with
TWO trusted peers (beta, gamma) configured in the peer_trust map:

  * routed to the discovered peer, not the legacy configured one;
  * destination URL comes from the LOCAL trust anchor, never the broker's advertised URL;
  * a discovered DID not in the trust map is refused (fail closed) → configured fallback;
  * the user assertion ``aud`` is bound to the ACTUAL target DID;
  * the response must be signed by THAT peer (a different trusted peer's signature fails);
  * the circuit breaker is per actual peer (gamma's open breaker never blocks beta);
  * legacy single-peer (PEER_AGENT_* only) behaves as before.

Real code under test: mesh.peer_client (real Ed25519 signing with this agent's identity,
real verify_signed_message against the anchored peer key, real IdentityRegistry trust
gate, real AgentMesh governance gate, real CircuitBreaker, real httpx.AsyncClient). The
network is replaced by one httpx.MockTransport that dispatches by host to an in-process
handler PER PEER, each holding that peer's own Ed25519 key — so "which peer answered" is
decided by the URL the real client actually dialled. Hermetic: no sockets, no broker.
"""
from __future__ import annotations

import json
import time
import uuid

import httpx
import pytest
from agentmesh.exceptions import AgentMeshError

import mesh.agent_identity as ai
from agent import nodes
from config import settings
from mesh import discovery as disc
from mesh import peer_client as pc
from mesh.agent_identity import AgentIdentity, _canonical_bytes

BETA_URL = "http://beta-agent.internal:9100"
GAMMA_URL = "http://gamma-agent.internal:9200"
EVIL_URL = "http://evil.attacker:6666"            # what a rogue broker row advertises


def _sign_as(identity: AgentIdentity, body: dict) -> dict:
    signed = dict(body)
    signed["ts"] = int(time.time())
    signed["nonce"] = str(uuid.uuid4())
    signed["_agentmesh"] = {"sender_did": str(identity.did),
                            "signature": identity.sign(_canonical_bytes(signed)),
                            "alg": "EdDSA"}
    return signed


def _anchor(identity: AgentIdentity, url: str, division: str) -> dict:
    return {"issuer": f"http://{division}/realms/rag",
            "public_jwk": json.dumps(identity.to_jwk(include_private=False)),
            "agent_url": url, "division_id": division}


class _Mesh:
    """Two real peer identities behind one MockTransport, dispatching by dialled host."""

    def __init__(self, self_id: AgentIdentity, beta: AgentIdentity, gamma: AgentIdentity):
        self.self_id, self.beta, self.gamma = self_id, beta, gamma
        self.hits: list[tuple[str, str, dict]] = []      # (host:port, path, signed body)
        self.signer_override: dict[str, AgentIdentity] = {}
        self.fail_hosts: set[str] = set()
        self.by_host = {"beta-agent.internal:9100": beta, "gamma-agent.internal:9200": gamma}

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = f"{request.url.host}:{request.url.port}"
        body = json.loads(request.content)
        self.hits.append((host, request.url.path, body))
        peer = self.by_host.get(host)
        if peer is None:
            raise httpx.ConnectError(f"no route to {host}", request=request)
        if host in self.fail_hosts:
            return httpx.Response(503, json={"detail": "down"})
        # The peer verifies the caller's signature with the caller's PUBLIC key.
        sig = body["_agentmesh"]["signature"]
        assert body["_agentmesh"]["sender_did"] == str(self.self_id.did)
        assert self.self_id.verify_signature(_canonical_bytes(body), sig)
        resp = {"status": "completed", "task_id": f"task-{host}",
                "answer": f"answer from {host}", "result": {"served_by": host}}
        signer = self.signer_override.get(host, peer)
        return httpx.Response(200, json=_sign_as(signer, resp))


@pytest.fixture
def mesh2(monkeypatch):
    """Self (alpha) + two trusted peers (beta, gamma); legacy configured peer = beta."""
    self_id = AgentIdentity.create(name="alpha", sponsor="alpha@example.com")
    beta = AgentIdentity.create(name="beta", sponsor="beta@example.com")
    gamma = AgentIdentity.create(name="gamma", sponsor="gamma@example.com")
    trust = {str(beta.did): _anchor(beta, BETA_URL, "beta"),
             str(gamma.did): _anchor(gamma, GAMMA_URL, "gamma")}
    monkeypatch.setattr(settings, "peer_trust_map", json.dumps(trust))
    monkeypatch.setattr(settings, "peer_agent_url", BETA_URL)
    monkeypatch.setattr(settings, "peer_agent_did", str(beta.did))
    monkeypatch.setattr(settings, "division_id", "alpha")
    # Isolated module state: our identity, a registry rebuilt from THIS trust map, fresh
    # nonce cache (in-process guard; no Redis), fresh per-peer breakers.
    monkeypatch.setattr(ai, "_identity", self_id)
    monkeypatch.setattr(ai, "_identity_registry", None)
    monkeypatch.setattr(ai, "_seen_nonces", {})

    async def _no_redis(_did, _nonce):
        return None
    monkeypatch.setattr(ai, "_seen_nonce_redis", _no_redis)
    monkeypatch.setattr(pc, "_circuit_breakers", {})

    m = _Mesh(self_id, beta, gamma)
    transport = httpx.MockTransport(m.handler)
    real_client = httpx.AsyncClient

    class _Client(real_client):                       # real httpx client, mocked wire only
        def __init__(self, *a, **k):
            k.pop("verify", None)
            super().__init__(*a, transport=transport, **k)

    monkeypatch.setattr(pc.httpx, "AsyncClient", _Client)
    return m


def _broker(monkeypatch, peers: list[dict]) -> None:
    monkeypatch.setenv("DISCOVERY_URL", "http://broker:8600")

    async def fake_discover(url, capability=None, timeout=10.0):
        return peers

    async def fake_register(url, caps, timeout=10.0):
        return {}
    monkeypatch.setattr(disc, "_discover_peers", fake_discover)
    monkeypatch.setattr(disc, "_register_self", fake_register)
    monkeypatch.setattr(disc, "_self_registered", False)


def _advert(did: str, url: str, division: str, caps: list[str]) -> dict:
    return {"division_id": division, "agent_did": did, "agent_url": url,
            "issuer": "http://x", "public_jwk": "{}", "capabilities": caps}


# ── Query delegation: transport level ──────────────────────────────────────────

async def test_query_routes_to_target_did_not_configured_peer(mesh2):
    gamma_did = str(mesh2.gamma.did)
    resp = await pc.call_peer_agent("q", "user:alice", "ctx",
                                    user_assertion={"sub": "a", "iss": "http://alpha"},
                                    target_did=gamma_did)
    assert [(h, p) for h, p, _ in mesh2.hits] == [("gamma-agent.internal:9200", "/a2a/query")]
    assert resp.peer_did == gamma_did
    assert resp.answer == "answer from gamma-agent.internal:9200"
    sent = mesh2.hits[0][2]
    assert sent["user_assertion"]["aud"] == gamma_did          # bound to the ACTUAL target
    assert sent["source_division"] == "alpha"


async def test_untrusted_target_did_refused_before_send(mesh2):
    stranger = AgentIdentity.create(name="stranger", sponsor="s@example.com")
    with pytest.raises(AgentMeshError, match="not in the local trust map"):
        await pc.call_peer_agent("q", "user:alice", "ctx", target_did=str(stranger.did))
    assert mesh2.hits == []                                    # nothing signed or sent


async def test_response_signed_by_other_trusted_peer_rejected(mesh2):
    """gamma's endpoint answers with BETA's (trusted!) key → fail closed: the response
    must be signed by the peer we routed to, not merely by some trusted peer."""
    mesh2.signer_override["gamma-agent.internal:9200"] = mesh2.beta
    with pytest.raises(AgentMeshError, match="signature"):
        await pc.call_peer_agent("q", "user:alice", "ctx", target_did=str(mesh2.gamma.did))
    assert [h for h, _, _ in mesh2.hits] == ["gamma-agent.internal:9200"]


async def test_circuit_breaker_is_per_actual_peer(mesh2):
    from agent_os.circuit_breaker import CircuitState
    mesh2.fail_hosts.add("gamma-agent.internal:9200")
    for _ in range(5):
        with pytest.raises(AgentMeshError):
            await pc.call_peer_agent("q", "u", "c", target_did=str(mesh2.gamma.did))
    assert await pc.get_peer_circuit_state(GAMMA_URL) == CircuitState.OPEN
    assert await pc.get_peer_circuit_state(BETA_URL) == CircuitState.CLOSED
    n = len(mesh2.hits)
    with pytest.raises(RuntimeError, match="Circuit breaker OPEN"):
        await pc.call_peer_agent("q", "u", "c", target_did=str(mesh2.gamma.did))
    assert len(mesh2.hits) == n                                 # failed fast, not sent
    ok = await pc.call_peer_agent("q", "u", "c", target_did=str(mesh2.beta.did))
    assert ok.peer_did == str(mesh2.beta.did)                   # beta unaffected


# ── Query delegation: through the graph node (discover → negotiate → route) ────

async def test_node_routes_to_discovered_peer_ignoring_broker_url(mesh2, monkeypatch):
    """The broker advertises gamma (a TRUSTED DID) at an attacker URL. The signed request
    goes to gamma's TRUST-ANCHOR URL; the advertised URL is never dialled."""
    gamma_did = str(mesh2.gamma.did)
    _broker(monkeypatch, [_advert(gamma_did, EVIL_URL, "evil-division",
                                  ["technical_architecture"])])
    nodes.set_user_claims({"sub": "a", "email": "alice@example.com",
                           "email_verified": True, "iss": "http://alpha"})

    out = await nodes.call_peer_agent({"query": "What Kubernetes version do we run?",
                                       "user_id": "alice", "context_id": "ctx"})

    assert "error" not in out, out
    assert out["peer_answer"] == "answer from gamma-agent.internal:9200"
    assert [h for h, _, _ in mesh2.hits] == ["gamma-agent.internal:9200"]   # not evil, not beta
    assert mesh2.hits[0][2]["user_assertion"]["aud"] == gamma_did
    assert out["discovery_summary"]["source"] == "discovered"
    assert out["discovery_summary"]["division"] == "gamma"      # anchor, not broker's division


async def test_node_untrusted_discovered_did_falls_back_to_configured(mesh2, monkeypatch):
    stranger = AgentIdentity.create(name="stranger", sponsor="s@example.com")
    _broker(monkeypatch, [_advert(str(stranger.did), EVIL_URL, "evil",
                                  ["technical_architecture"])])
    nodes.set_user_claims({"sub": "a", "iss": "http://alpha"})

    out = await nodes.call_peer_agent({"query": "What Kubernetes version do we run?",
                                       "user_id": "alice", "context_id": "ctx"})

    assert out["discovery_summary"]["source"] == "configured-fallback"
    assert [h for h, _, _ in mesh2.hits] == ["beta-agent.internal:9100"]    # configured peer
    assert mesh2.hits[0][2]["user_assertion"]["aud"] == str(mesh2.beta.did)


# ── Tool delegation (/a2a/tool) ────────────────────────────────────────────────

async def test_call_peer_tool_refuses_non_anchor_url(mesh2):
    """A caller handing call_peer_tool the broker-advertised URL for a trusted DID is
    refused before signing; an untrusted DID is refused too."""
    gamma_did = str(mesh2.gamma.did)
    with pytest.raises(AgentMeshError, match="trust-anchor"):
        await pc.call_peer_tool(EVIL_URL, gamma_did, "tool.compliance", {},
                                user_assertion={"aud": gamma_did}, source_division="alpha")
    stranger = AgentIdentity.create(name="stranger", sponsor="s@example.com")
    with pytest.raises(AgentMeshError, match="not in the local trust map"):
        await pc.call_peer_tool(EVIL_URL, str(stranger.did), "tool.compliance", {},
                                user_assertion={}, source_division="alpha")
    assert mesh2.hits == []


async def test_solve_with_tools_routes_each_capability_to_its_discovered_peer(mesh2, monkeypatch):
    """Two capabilities, two peers: the broker says gamma serves tool.compliance (at an
    attacker URL) and beta serves tool.risk. Each delegated tool call lands on THAT peer's
    anchor URL with aud = that peer's DID."""
    monkeypatch.setenv("AGT_LOCAL_TOOLS", "tool.pii")          # we serve neither locally
    beta_did, gamma_did = str(mesh2.beta.did), str(mesh2.gamma.did)
    monkeypatch.setenv("DISCOVERY_URL", "http://broker:8600")

    async def fake_discover(url, capability=None, timeout=10.0):
        return {"tool.compliance": [_advert(gamma_did, EVIL_URL, "evil", ["tool.compliance"])],
                "tool.risk": [_advert(beta_did, EVIL_URL, "evil", ["tool.risk"])]}[capability]

    async def fake_register(url, caps, timeout=10.0):
        return {}
    monkeypatch.setattr(disc, "_discover_peers", fake_discover)
    monkeypatch.setattr(disc, "_register_self", fake_register)
    monkeypatch.setattr(disc, "_self_registered", True)
    nodes.set_user_claims({"sub": "a", "iss": "http://alpha"})

    c = await nodes.solve_with_tools(capability="tool.compliance", arguments={"topic": "x"},
                                     user_id="alice")
    r = await nodes.solve_with_tools(capability="tool.risk", arguments={"amount": 1},
                                     user_id="alice")

    assert c["status"] == "completed" and c["peer_did"] == gamma_did
    assert r["status"] == "completed" and r["peer_did"] == beta_did
    assert [(h, p) for h, p, _ in mesh2.hits] == [("gamma-agent.internal:9200", "/a2a/tool"),
                                                   ("beta-agent.internal:9100", "/a2a/tool")]
    assert mesh2.hits[0][2]["user_assertion"]["aud"] == gamma_did
    assert mesh2.hits[1][2]["user_assertion"]["aud"] == beta_did


# ── Back-compat: legacy single-peer config ─────────────────────────────────────

async def test_legacy_single_peer_unchanged(mesh2, monkeypatch):
    """PEER_AGENT_* only (no PEER_TRUST_MAP), discovery off: no target_did is passed and
    the transport sends to the configured peer exactly as before."""
    beta = mesh2.beta
    monkeypatch.setattr(settings, "peer_trust_map", "")
    monkeypatch.setattr(settings, "peer_agent_public_jwk",
                        json.dumps(beta.to_jwk(include_private=False)))
    monkeypatch.setattr(settings, "peer_agent_issuer", "http://beta/realms/rag")
    monkeypatch.setattr(ai, "_identity_registry", None)
    monkeypatch.delenv("DISCOVERY_URL", raising=False)

    seen: dict = {}
    real = nodes._mesh_call_peer

    async def spy(**kwargs):
        seen.update(kwargs)
        return await real(**kwargs)
    monkeypatch.setattr(nodes, "_mesh_call_peer", spy)
    nodes.set_user_claims({"sub": "a", "iss": "http://alpha"})

    out = await nodes.call_peer_agent({"query": "What Kubernetes version do we run?",
                                       "user_id": "alice", "context_id": "ctx"})

    assert "target_did" not in seen                              # legacy call shape
    assert out["discovery_summary"]["source"] == "configured-fallback"
    assert out["peer_answer"] == "answer from beta-agent.internal:9100"
    assert [h for h, _, _ in mesh2.hits] == ["beta-agent.internal:9100"]
    assert mesh2.hits[0][2]["user_assertion"]["aud"] == str(beta.did)
