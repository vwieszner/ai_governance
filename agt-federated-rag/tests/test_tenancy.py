"""M0 tenancy-foundation tests (IMPLEMENTATION_PLAN.md M0).

Proves the division_id config contract that the tenancy threading relies on:
division_id defaults to cluster_id (back-compat), an explicit division_id wins,
and the trusted-peer set parses. The runtime threading (A2A `source_division`
envelope, OpenFGA division-scoped audit, /a2a/query attribution) is built on this
contract; the cross-stack isolation proof (test_isolation) lands with the
onboarding generator that stands up two physically-separate division stacks.
"""
from __future__ import annotations


def test_division_id_defaults_to_cluster_id(make_settings):
    # A single-cluster .env that sets only CLUSTER_ID still yields a division_id.
    s = make_settings(cluster_id="division-x")  # division_id left unset
    assert s.division_id == "division-x"


def test_division_id_explicit_overrides_cluster_id(make_settings):
    s = make_settings(cluster_id="cluster-a", division_id="division-alpha")
    assert s.division_id == "division-alpha"


def test_trusted_peers_parsed(make_settings):
    s = make_settings(trusted_peers="alpha, beta ,gamma")
    assert s.trusted_peers_list == ["alpha", "beta", "gamma"]


def test_trusted_peers_empty_is_empty_list(make_settings):
    s = make_settings()
    assert s.trusted_peers_list == []


def test_residency_and_transport_defaults(make_settings):
    s = make_settings()
    assert s.residency_mode == "external"   # M6 will enforce "local"
    assert s.require_mtls is False          # M7 will enforce True


def test_openfga_audit_carries_division_id(make_settings, monkeypatch):
    """FR-1.4: every OpenFGA authorization decision is attributed to its division in
    the audit log. Asserts the openfga.check structured event includes division_id
    (previously only verified by reading the diff)."""
    import asyncio

    import structlog

    from auth import openfga as ofga

    s = make_settings(division_id="division-alpha")
    monkeypatch.setattr(ofga, "settings", s)

    auth = ofga.OpenFGAAuth()

    class _Resp:
        allowed = True

    class _Client:
        async def check(self, _body):
            return _Resp()

    auth._client = _Client()
    with structlog.testing.capture_logs() as logs:
        asyncio.run(auth.check("user:alice", "chunkx", ofga.Relation.VIEWER))
    checks = [e for e in logs if e.get("event") == "openfga.check"]
    assert checks, "no openfga.check audit event emitted"
    assert checks[0]["division_id"] == "division-alpha"


def test_division_id_threaded_into_a2a_envelope(make_settings, monkeypatch):
    """The outbound A2A payload carries source_division == settings.division_id.

    We drive the real payload-construction in mesh.peer_client by stubbing the
    network/DID/governance steps so the test stays hermetic but still exercises
    the actual threading code path (not a re-implementation).
    """
    import asyncio

    import mesh.peer_client as pc

    s = make_settings(cluster_id="cluster-a", division_id="division-alpha",
                      peer_agent_did="did:mesh:peer", peer_agent_url="http://peer:9")
    monkeypatch.setattr(pc, "settings", s)

    captured: dict = {}

    async def _verify_peer(_did):
        return True, 1.0

    async def _govern(_action, _ctx):
        class _G:  # minimal GovernanceResult stand-in
            allowed = True
            decision = "allow"
        return _G()

    async def _sign(payload):
        captured.update(payload)          # capture exactly what gets signed
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
            return {"status": "completed", "answer": "ok", "task_id": "t",
                    "_agentmesh": {"sender_did": "x", "signature": "y", "alg": "EdDSA"}}

    class _Client:
        def __init__(self, *a, **k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return _Resp()

    async def _verify_signed(_resp):
        return True, "did:mesh:peer"

    monkeypatch.setattr(pc, "verify_peer_identity", _verify_peer)
    monkeypatch.setattr(pc, "govern_action", _govern)
    monkeypatch.setattr(pc, "sign_outbound_message", _sign)
    monkeypatch.setattr(pc, "_get_circuit_breaker", _get_cb)
    monkeypatch.setattr(pc, "report_trust_event", _report)
    monkeypatch.setattr(pc, "verify_signed_message", _verify_signed)
    monkeypatch.setattr(pc.httpx, "AsyncClient", _Client)

    asyncio.run(pc.call_peer_agent("q", "user:alice", "ctx"))
    assert captured.get("source_division") == "division-alpha"
    assert captured.get("source_cluster") == "cluster-a"
