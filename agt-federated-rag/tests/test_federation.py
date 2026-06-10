"""Federation-wiring tests (IMPLEMENTATION_PLAN.md M2/M3).

scripts/federate_divisions.py cross-wires onboarded divisions: it upserts PEER_AGENT_*
+ TRUSTED_ISSUERS into each agent's .env and applies declarative cross_grants. These
hermetic tests pin the pure logic — the .env upsert must be idempotent (re-runnable
without duplicating keys) and the manifest must parse cross_grants — so a re-federate
never corrupts an agent's config. The cross-grant principal parity with the runtime
principal is covered by tests/test_a2a.py::test_seed_principal_matches_runtime_principal.
"""
from __future__ import annotations

from pathlib import Path


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
    lines = [l for l in text.splitlines() if l and not l.lstrip().startswith("#")]
    # existing key replaced in place (not duplicated)
    assert "PEER_AGENT_URL=http://localhost:8200" in lines
    assert sum(1 for l in lines if l.startswith("PEER_AGENT_URL=")) == 1
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
