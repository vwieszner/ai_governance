"""M0 onboarding-generator tests (IMPLEMENTATION_PLAN.md M0).

Proves the parameterized onboarding generalizes the hardcoded setup into N
divisions from config, and that generating a division edits NO source — adding a
division = adding a manifest (FR-1.1/1.4, NFR-8). Pure (no docker/network).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.onboard_division import (
    DIVISIONS_DIR,
    GENERATED_DIR,
    ROOT,
    compose_project,
    derive_ports,
    discover_manifests,
    load_manifest,
    onboard,
)


def test_three_divisions_from_config():
    manifests = discover_manifests(DIVISIONS_DIR)
    assert len(manifests) >= 3, "expected >=3 division manifests (alpha/beta/gamma)"

    divisions = [load_manifest(p) for p in manifests]
    ids = [m.division_id for m in divisions]
    assert len(set(ids)) == len(ids), "division_ids must be unique"

    projects = [compose_project(d) for d in ids]
    assert len(set(projects)) == len(projects), "compose project names must be unique"

    # Every published port across ALL divisions must be globally distinct (no clash
    # => N divisions coexist as separate stacks).
    all_ports: list[int] = []
    for m in divisions:
        all_ports.extend(derive_ports(m.port_base).values())
    assert len(set(all_ports)) == len(all_ports), f"port collision across divisions: {all_ports}"


def test_derive_ports_layout():
    p = derive_ports(8100)
    assert p == {"agent": 8100, "openfga": 8101, "keycloak": 8102,
                 "temporal": 8103, "temporal_ui": 8104, "qdrant": 8105, "redis": 8106}


def test_reserved_port_base_rejected():
    # A co-resident project reserves port_base+1 (=8000+N*100+1) as its BACKEND, so the
    # old 8100/8200/8300/8400 bases (openfga=+1) collide. The guard must refuse them.
    import pytest

    from scripts.onboard_division import assert_port_base_clean
    for colliding in (8100, 8200, 8300, 8400):
        with pytest.raises(ValueError):
            assert_port_base_clean(colliding)
    for clean in (9000, 9100, 9200):
        assert_port_base_clean(clean)            # no raise


def test_real_manifests_use_clean_port_bases():
    # The shipped division manifests must sit in a clean band (load_manifest enforces it).
    from scripts.onboard_division import load_manifest
    for div, expected in (("alpha", 9000), ("beta", 9100), ("gamma", 9200)):
        m = load_manifest(DIVISIONS_DIR / f"{div}.yml")
        assert m.port_base == expected


def test_manifest_requires_division_id_and_port_base(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("display_name: No Id\nport_base: 8400\n", encoding="utf-8")
    import pytest
    with pytest.raises(ValueError):
        load_manifest(bad)
    bad2 = tmp_path / "bad2.yml"
    bad2.write_text("division_id: x\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(bad2)


def _snapshot_sources() -> dict[str, str]:
    """Hash every tracked source file that onboarding must NOT touch."""
    snap: dict[str, str] = {}
    roots = [ROOT / "scripts", ROOT / "infra" / "divisions", ROOT / "agt-federated-rag"]
    for r in roots:
        for f in r.rglob("*"):
            # skip generated output, venv, caches, the gitignored agent env/identity files
            parts = set(f.parts)
            if (not f.is_file() or "generated" in parts or "__pycache__" in parts
                    or ".venv" in parts or f.suffix in (".pyc",)):
                continue
            snap[str(f)] = hashlib.sha256(f.read_bytes()).hexdigest()
    return snap


def test_onboard_no_source_edit():
    before = _snapshot_sources()
    # Dry-run renders the stack env into infra/generated/<id>/ only — no docker, no source edits.
    plan = onboard(DIVISIONS_DIR / "alpha.yml", dry_run=True)
    after = _snapshot_sources()
    assert before == after, "onboarding a division must not modify any source file"

    # And it DID produce the generated artifact under infra/generated/.
    stack_env = Path(plan["stack_env"])
    assert stack_env.exists()
    assert GENERATED_DIR in stack_env.parents, "generated output must live under infra/generated/"
    body = stack_env.read_text(encoding="utf-8")
    # Derive the expected port from the manifest (don't hardcode) so re-homing a
    # division to a free port slot doesn't break this test.
    exp_ofga = derive_ports(load_manifest(DIVISIONS_DIR / "alpha.yml").port_base)["openfga"]
    assert "DIV_ID=alpha" in body and f"DIV_OPENFGA_PORT={exp_ofga}" in body
