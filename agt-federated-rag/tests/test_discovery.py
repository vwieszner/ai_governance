"""M3 discovery-service tests (IMPLEMENTATION_PLAN.md M3, FR-3.1/3.2/3.5).

Pins: a DID-signed registration is accepted and discoverable by capability; discovery
excludes self; an unsigned or forged (tampered-after-signing) registration is rejected;
and the registry exposes ONLY control-plane metadata (never division data).
"""
from __future__ import annotations

import json
import time
import uuid

import pytest


def _identity():
    from mesh.agent_identity import AgentIdentity
    return AgentIdentity.create(name="t", sponsor="admin@example.com")


def _signed_registration(identity, division_id, agent_url, issuer, caps):
    from mesh.agent_identity import _canonical_bytes
    p = {
        "division_id": division_id, "agent_url": agent_url, "issuer": issuer,
        "public_jwk": json.dumps(identity.to_jwk(include_private=False)),
        "capabilities": caps, "ts": int(time.time()), "nonce": str(uuid.uuid4()),
    }
    p["_agentmesh"] = {"sender_did": str(identity.did),
                       "signature": identity.sign(_canonical_bytes(p)), "alg": "EdDSA"}
    return p


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from discovery.service import _registry, app
    _registry._entries.clear()
    return TestClient(app)


def test_register_then_discover_by_capability(client):
    idn = _identity()
    reg = _signed_registration(idn, "beta", "http://localhost:9100",
                               "http://localhost:9102/realms/rag", ["technical_architecture", "kubernetes"])
    assert client.post("/register", json=reg).status_code == 200
    r = client.get("/discover", params={"capability": "kubernetes"}).json()
    assert r["count"] == 1
    assert r["peers"][0]["agent_did"] == str(idn.did)
    assert r["peers"][0]["agent_url"] == "http://localhost:9100"
    assert r["peers"][0]["issuer"] == "http://localhost:9102/realms/rag"
    assert client.get("/discover", params={"capability": "no-such-cap"}).json()["count"] == 0


def test_discover_excludes_self(client):
    idn = _identity()
    client.post("/register", json=_signed_registration(idn, "beta", "http://x", "http://i", ["c"]))
    assert client.get("/discover", params={"exclude_did": str(idn.did)}).json()["count"] == 0


def test_unsigned_registration_rejected(client):
    idn = _identity()
    reg = _signed_registration(idn, "beta", "http://x", "http://i", ["c"])
    del reg["_agentmesh"]
    assert client.post("/register", json=reg).status_code == 401


def test_forged_registration_rejected(client):
    idn = _identity()
    reg = _signed_registration(idn, "beta", "http://x", "http://i", ["c"])
    reg["agent_url"] = "http://evil"            # tamper the signed body
    assert client.post("/register", json=reg).status_code == 401


def test_registry_is_control_plane_only(client):
    idn = _identity()
    client.post("/register", json=_signed_registration(idn, "beta", "http://x", "http://i", ["c"]))
    peer = client.get("/discover").json()["peers"][0]
    assert set(peer) == {"division_id", "agent_did", "agent_url", "issuer",
                         "public_jwk", "capabilities", "registered_at"}
