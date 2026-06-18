"""Federation-wiring tests (IMPLEMENTATION_PLAN.md M2/M3).

scripts/federate_divisions.py cross-wires onboarded divisions: it upserts PEER_AGENT_*
+ TRUSTED_ISSUERS into each agent's .env and applies declarative cross_grants. These
hermetic tests pin the pure logic — the .env upsert must be idempotent (re-runnable
without duplicating keys) and the manifest must parse cross_grants — so a re-federate
never corrupts an agent's config. The cross-grant principal parity with the runtime
principal is covered by tests/test_a2a.py::test_seed_principal_matches_runtime_principal.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest


class _FakeResp:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    def __init__(self, resp: _FakeResp):
        self._resp = resp
        self.calls = 0

    async def post(self, url, json=None, headers=None):
        self.calls += 1
        return self._resp


def test_ofga_write_swallows_already_exists_but_raises_real_failures():
    # Quality M1: provisioning writes must be idempotent yet NOT silent — a genuine
    # failure (bad token / wrong store / model drift) must surface, not be swallowed.
    from scripts.onboard_division import _ofga_write
    tk = {"user": "user:a@x|ns", "relation": "viewer", "object": "chunk:c"}

    asyncio.run(_ofga_write(_FakeClient(_FakeResp(200, "{}")), "o", "s", {}, tk))     # ok
    asyncio.run(_ofga_write(                                                          # idempotent
        _FakeClient(_FakeResp(400, '{"message":"tuple already exists"}')), "o", "s", {}, tk))
    with pytest.raises(Exception):                                                    # 403 bad token
        asyncio.run(_ofga_write(_FakeClient(_FakeResp(403, "forbidden")), "o", "s", {}, tk))
    with pytest.raises(Exception):                                                    # 404 wrong store
        asyncio.run(_ofga_write(_FakeClient(_FakeResp(404, "store not found")), "o", "s", {}, tk))


def test_upsert_env_replaces_existing_and_appends_new(tmp_path: Path):
    from scripts.federate_divisions import _upsert_env

    env = tmp_path / ".env.alpha"
    env.write_text(
        "OIDC_ISSUER=http://localhost:8102/realms/rag\n"
        "PEER_AGENT_URL=http://stale:9999\n"
        "# a comment PEER_AGENT_DID=should-not-match\n",
        encoding="utf-8",
    )
    _upsert_env(env, {
        "PEER_AGENT_URL": "http://localhost:8200",
        "PEER_AGENT_DID": "did:mesh:beta",
        "TRUSTED_ISSUERS": "http://localhost:8202/realms/rag",
    }, dry_run=False)

    text = env.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line and not line.lstrip().startswith("#")]
    # existing key replaced in place (not duplicated)
    assert "PEER_AGENT_URL=http://localhost:8200" in lines
    assert sum(1 for line in lines if line.startswith("PEER_AGENT_URL=")) == 1
    # new keys appended
    assert "PEER_AGENT_DID=did:mesh:beta" in lines
    assert "TRUSTED_ISSUERS=http://localhost:8202/realms/rag" in lines
    # untouched key preserved; comment preserved
    assert "OIDC_ISSUER=http://localhost:8102/realms/rag" in lines
    assert "# a comment PEER_AGENT_DID=should-not-match" in text


def test_upsert_env_is_idempotent(tmp_path: Path):
    from scripts.federate_divisions import _upsert_env

    env = tmp_path / ".env.beta"
    env.write_text("FOO=bar\n", encoding="utf-8")
    updates = {"PEER_AGENT_URL": "http://localhost:8100", "PEER_AGENT_DID": "did:mesh:alpha"}
    _upsert_env(env, updates, dry_run=False)
    first = env.read_text(encoding="utf-8")
    changes = _upsert_env(env, updates, dry_run=False)   # re-run
    assert changes == []                                  # nothing changed second time
    assert env.read_text(encoding="utf-8") == first


def test_dry_run_writes_nothing(tmp_path: Path):
    from scripts.federate_divisions import _upsert_env

    env = tmp_path / ".env.gamma"
    env.write_text("FOO=bar\n", encoding="utf-8")
    _upsert_env(env, {"PEER_AGENT_URL": "http://x"}, dry_run=True)
    assert env.read_text(encoding="utf-8") == "FOO=bar\n"   # unchanged


def test_manifest_parses_cross_grants():
    # beta's real manifest declares alice@alpha's cross-division pre-authorization.
    from pathlib import Path as P

    from scripts.onboard_division import load_manifest

    root = P(__file__).resolve().parents[2]
    m = load_manifest(root / "infra" / "divisions" / "beta.yml")
    assert m.cross_grants, "beta should declare cross_grants"
    g = m.cross_grants[0]
    assert g["user_email"] == "alice@example.com"
    assert g["home_division"] == "alpha"
    assert g["relation"] == "viewer"
    assert g["doc"] == "technical_architecture"
