"""Admin artifact endpoints — wiring the artifact store into a governed flow.

Exercises the evidence-pack export -> list -> retrieve round-trip on the LOCAL backend, the
admin gate (non-admin 403), and the path-safety guard (bad name 400). Mirrors the direct-handler
test style of test_audit_endpoint.py.
"""
from __future__ import annotations

import asyncio
import json

import pytest

import artifact_store
from api import main

_ADMIN = {"sub": "kc-admin", "email": "bob@example.com", "email_verified": True,
          "iss": "http://localhost:9002/realms/rag",
          "realm_access": {"roles": ["data-owner", "division-admin"]}}
_MEMBER = {"sub": "kc-m", "email": "alice@example.com", "email_verified": True,
           "iss": "http://localhost:9002/realms/rag", "realm_access": {"roles": ["member"]}}


def _patch(monkeypatch, claims):
    async def fake_bearer(auth):
        return ("tok", claims)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    async def no_rate_limit(subject, **kw):
        return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rate_limit)


@pytest.fixture
def env(monkeypatch, tmp_path):
    import audit_log
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    monkeypatch.setattr(main.settings, "audit_log_dir", str(audit_dir))
    monkeypatch.setattr(main.settings, "artifact_backend", "local")
    monkeypatch.setattr(main.settings, "artifact_local_dir", str(tmp_path / "artifacts"))
    artifact_store._backend = None
    chain = audit_log.AuditChain(audit_dir / "alpha_agent.jsonl")
    chain.append("auth_decision", {"allowed": True, "user_id": "alice|ns"})
    yield
    artifact_store._backend = None


def test_export_pack_then_list_and_get(env, monkeypatch):
    _patch(monkeypatch, _ADMIN)
    resp = asyncio.run(main.export_audit_pack(authorization="Bearer t", event=None, limit=10000))
    assert resp.status_code == 201
    ref = json.loads(bytes(resp.body).decode())["artifact"]
    assert ref["division"] == "alpha"
    assert ref["key"].startswith("alpha/evidence-packs/")
    name = ref["name"]

    lst = asyncio.run(main.list_artifacts_endpoint(authorization="Bearer t", prefix=""))
    assert name in json.loads(bytes(lst.body).decode())["artifacts"]

    got = asyncio.run(main.get_artifact_endpoint(name=name, authorization="Bearer t"))
    pack = json.loads(bytes(got.body).decode())
    assert pack["division"] == "alpha"
    assert pack["count"] == 1
    assert "audit" in pack


def test_export_requires_admin(env, monkeypatch):
    _patch(monkeypatch, _MEMBER)
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.export_audit_pack(authorization="Bearer t", event=None, limit=10000))
    assert ei.value.status_code == 403


def test_get_rejects_bad_name(env, monkeypatch):
    _patch(monkeypatch, _ADMIN)
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.get_artifact_endpoint(name="../escape", authorization="Bearer t"))
    assert ei.value.status_code == 400
