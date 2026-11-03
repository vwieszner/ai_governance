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


# ── Optional per-division LLM gateway (manifest `llm_gateway: true`) ─────────────
# Hermetic: render-only (dry_run), no docker/network. The live proof is
# examples/llm-gateway/prove_gateway.py; these pin the deployment wiring.

_FAKE_SECRETS = {"openfga_api_token": "t", "agent_client_secret": "c", "approval_hmac_secret": "h"}


def _gw_manifest(tmp_path, div: str, residency: str = "external", extra: str = "") -> Path:
    p = tmp_path / f"{div}.yml"
    p.write_text(f"division_id: {div}\ndisplay_name: GW\nport_base: 9600\n"
                 f"docs_dir: tests/docs/cluster-a\nresidency_mode: {residency}\n"
                 f"llm_gateway: true\n{extra}", encoding="utf-8")
    return p


def _env_dict(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def _gateway_model_names() -> set[str]:
    import yaml
    from scripts.onboard_division import GATEWAY_CONFIG
    cfg = yaml.safe_load(GATEWAY_CONFIG.read_text(encoding="utf-8"))
    return {m["model_name"] for m in cfg["model_list"]}


def test_gateway_off_by_default_leaves_onboarding_unchanged():
    for p in discover_manifests(DIVISIONS_DIR):
        assert load_manifest(p).llm_gateway is False, f"{p.name}: gateway must stay opt-in"
    plan = onboard(DIVISIONS_DIR / "alpha.yml", dry_run=True)
    assert plan["profiles"] == [] and plan["llm_gateway"] is None
    body = Path(plan["stack_env"]).read_text(encoding="utf-8")
    assert "LITELLM" not in body and "DIV_LLM_GATEWAY_PORT" not in body


def test_gateway_dry_run_renders_profile_port_and_secrets(tmp_path):
    import json
    import shutil

    from scripts.onboard_division import (
        GATEWAY_PROFILE,
        LOCAL_LLM_UNSET,
        gateway_port,
        generated_dir,
    )
    div = "gwunittest"
    try:
        plan = onboard(_gw_manifest(tmp_path, div), dry_run=True)
        assert plan["profiles"] == [GATEWAY_PROFILE]
        assert plan["llm_gateway"]["port"] == gateway_port(9600) == 9607
        env = _env_dict(Path(plan["stack_env"]).read_text(encoding="utf-8"))
        assert env["DIV_LLM_GATEWAY_PORT"] == "9607"
        assert env["LITELLM_MASTER_KEY"].startswith("sk-") and len(env["LITELLM_DB_PASSWORD"]) == 32
        assert env["LOCAL_LLM_BASE"] == LOCAL_LLM_UNSET          # never empty (fails closed)
        sec = json.loads((generated_dir(div) / "secrets.json").read_text(encoding="utf-8"))
        assert sec["litellm_master_key"] == env["LITELLM_MASTER_KEY"]
        # Re-run is idempotent: the gateway secrets are reused, not rotated.
        onboard(_gw_manifest(tmp_path, div), dry_run=True)
        assert json.loads((generated_dir(div) / "secrets.json").read_text(encoding="utf-8")) == sec
    finally:
        shutil.rmtree(generated_dir(div), ignore_errors=True)


def test_gateway_key_spec_by_residency(tmp_path):
    from scripts.onboard_division import (
        GATEWAY_EXTERNAL_CHAT,
        GATEWAY_LOCAL_CHAT,
        gateway_key_spec,
    )
    ext = gateway_key_spec(load_manifest(_gw_manifest(tmp_path, "gwext")))
    assert GATEWAY_LOCAL_CHAT in ext["models"] and "aliases" not in ext
    loc = gateway_key_spec(load_manifest(_gw_manifest(
        tmp_path, "gwloc", "local", "llm_gateway_local_base: http://vllm.internal:8000/v1\n")))
    # residency=local: ONLY the in-boundary model; every external chat model the app may
    # send is aliased onto it by the key.
    assert loc["models"] == [GATEWAY_LOCAL_CHAT]
    assert loc["aliases"] == {m: GATEWAY_LOCAL_CHAT for m in GATEWAY_EXTERNAL_CHAT}
    # An unknown residency value fails closed to the local-only key.
    odd = gateway_key_spec(load_manifest(_gw_manifest(tmp_path, "gwodd", "eu-only")))
    assert odd["models"] == [GATEWAY_LOCAL_CHAT]
    # Every model a key names is a real model group in the shared gateway config.
    names = _gateway_model_names()
    assert set(ext["models"]) <= names and set(loc["aliases"]) <= names


def test_gateway_config_never_falls_back_local_to_external():
    import yaml
    from scripts.onboard_division import GATEWAY_CONFIG
    cfg = yaml.safe_load(GATEWAY_CONFIG.read_text(encoding="utf-8"))
    for fb in cfg["router_settings"]["fallbacks"]:
        for src, targets in fb.items():
            if src.startswith("local/"):
                assert all(t.startswith("local/") for t in targets), f"local->external fallback: {fb}"


def test_deployment_llm_models_are_gateway_model_groups():
    import yaml
    from scripts.onboard_division import render_agent_env
    names = _gateway_model_names()
    cm = yaml.safe_load((ROOT / "k8s" / "base" / "configmap.yaml").read_text(encoding="utf-8"))
    assert cm["data"]["LLM_MODEL"] in names and cm["data"]["EMBEDDING_MODEL"] in names
    m = load_manifest(DIVISIONS_DIR / "alpha.yml")
    env = _env_dict(render_agent_env(m, derive_ports(m.port_base), _FAKE_SECRETS, "s", "m", "nv"))
    assert env["LLM_MODEL"] in names and env["EMBEDDING_MODEL"] in names


def test_agent_env_points_at_gateway_only_when_keyed(tmp_path):
    from scripts.onboard_division import render_agent_env
    m = load_manifest(_gw_manifest(tmp_path, "gwenv"))
    ports = derive_ports(m.port_base)
    direct = _env_dict(render_agent_env(m, ports, _FAKE_SECRETS, "s", "m", "nv-key"))
    assert direct["OPENAI_API_BASE"] == "https://integrate.api.nvidia.com/v1"
    assert direct["OPENAI_API_KEY"] == "nv-key"
    gw = _env_dict(render_agent_env(m, ports, _FAKE_SECRETS, "s", "m", "nv-key",
                                    llm_gateway_key="sk-virtual"))
    assert gw["OPENAI_API_BASE"] == "http://localhost:9607/v1"
    assert gw["OPENAI_API_KEY"] == "sk-virtual"     # the provider key never reaches the agent


def test_gateway_port_reserved_collision_rejected(tmp_path):
    import pytest
    from scripts.onboard_division import RESERVED_PORTS, assert_port_base_clean
    # 8094's own ports are clean, but its gateway port (8094+7=8101) is a reserved port.
    assert 8101 in RESERVED_PORTS
    assert_port_base_clean(8094)
    p = tmp_path / "bad.yml"
    p.write_text("division_id: gwbad\nport_base: 8094\nllm_gateway: true\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(p)


def test_compose_gateway_services_are_opt_in_and_pinned():
    import yaml
    from scripts.onboard_division import GATEWAY_PROFILE, TEMPLATE
    svcs = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))["services"]
    gw, init = svcs["llm-gateway"], svcs["llm-gateway-db-init"]
    assert gw["profiles"] == [GATEWAY_PROFILE] and init["profiles"] == [GATEWAY_PROFILE]
    assert "@sha256:" in gw["image"]                                   # pinned by digest
    assert "llm-gateway.internal" in gw["networks"]["default"]["aliases"]
    # compose interpolates DISABLED profiles too: a `${VAR:?}` here would break every
    # division that does not opt in.
    for name in ("llm-gateway", "llm-gateway-db-init"):
        assert ":?" not in yaml.safe_dump(svcs[name]), name
    # The shared config + init script are mounted from their single source.
    assert any("k8s/llm-gateway/litellm-config.yaml" in v for v in gw["volumes"])
    assert any("k8s/llm-gateway/init-db.sh" in v for v in init["volumes"])


def test_gateway_urls_are_inboundary_for_residency():
    from scripts.bootstrap_k8s import gateway_url

    from residency import is_inboundary_url
    assert is_inboundary_url(gateway_url("gamma"))                     # k8s FQDN
    assert is_inboundary_url("http://llm-gateway.internal:4000/v1")   # compose alias
    assert is_inboundary_url("http://localhost:9607/v1")              # host-process agent
    assert not is_inboundary_url("http://llm-gateway:4000/v1")        # bare name = external


def test_k8s_gateway_kustomization_wraps_overlay_and_component():
    import shutil
    import subprocess

    import yaml
    from scripts.bootstrap_k8s import gateway_url, render_gateway_kustomization
    k = yaml.safe_load(render_gateway_kustomization("gamma"))
    assert k["namespace"] == "agt-div-gamma"
    kdir = ROOT / "infra" / "generated" / "gamma" / "k8s"
    for rel in (*k["resources"], *k["components"]):
        assert (kdir / rel).resolve().is_dir(), rel
    assert (kdir / k["components"][0]).resolve() == ROOT / "k8s" / "llm-gateway"
    patch = yaml.safe_load(k["patches"][0]["patch"])
    assert {op["path"]: op["value"] for op in patch} == {
        "/data/OPENAI_API_BASE": gateway_url("gamma"),
        "/data/EMBEDDING_API_BASE": gateway_url("gamma")}
    comp = yaml.safe_load((ROOT / "k8s" / "llm-gateway" / "kustomization.yaml").read_text(encoding="utf-8"))
    assert comp["kind"] == "Component"
    if shutil.which("kustomize") is None:
        return  # the full render is covered when a kustomize binary is on PATH
    kdir.mkdir(parents=True, exist_ok=True)
    (kdir / "kustomization.yaml").write_text(render_gateway_kustomization("gamma"), encoding="utf-8")
    out = subprocess.run(["kustomize", "build", str(kdir)], capture_output=True, text=True, check=True)
    objs = {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(out.stdout) if d}
    assert objs[("ConfigMap", "agent-config")]["data"]["OPENAI_API_BASE"] == gateway_url("gamma")
    assert objs[("Deployment", "llm-gateway")]["metadata"]["namespace"] == "agt-div-gamma"
    assert objs[("NetworkPolicy", "allow-intra-namespace")]["spec"]["podSelector"] == {
        "matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["llm-gateway"]}]}
