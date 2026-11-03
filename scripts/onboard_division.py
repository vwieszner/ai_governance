"""Onboard a division as a PHYSICALLY ISOLATED stack (IMPLEMENTATION_PLAN.md M0, D-3).

Reads a division manifest (infra/divisions/<id>.yml) and stands up that division's
OWN stack — its own Postgres+OpenFGA store, Keycloak realm host, Temporal, Qdrant,
Redis — from infra/division-stack.template.yml, then provisions it (OpenFGA store +
model, Keycloak realm/clients/users, AgentMesh DID, agent .env, ingest, seed tuples).

NO source edits: everything generated lands under infra/generated/<id>/ and the
per-division agent env file. Adding a division = adding a manifest; the code is
untouched (FR-1.1/1.4, NFR-8).

Usage (from repo root, project venv; NVIDIA_API_KEY in ./.env):
    .venv\\Scripts\\python.exe scripts/onboard_division.py infra/divisions/alpha.yml [--no-neo4j]
    .venv\\Scripts\\python.exe scripts/onboard_division.py infra/divisions/alpha.yml --dry-run   # render only, no docker/network

Port layout (derived from manifest port_base so divisions never clash):
    agent=base+0  openfga=base+1  keycloak=base+2  temporal=base+3  temporal_ui=base+4  qdrant=base+5  redis=base+6
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGT = ROOT / "agt-federated-rag"
VENV_PY = ROOT / ".venv" / "Scripts" / "python.exe"
TEMPLATE = ROOT / "infra" / "division-stack.template.yml"
DIVISIONS_DIR = ROOT / "infra" / "divisions"
GENERATED_DIR = ROOT / "infra" / "generated"

# Port offsets from a division's port_base. Distinct base per division => no clashes.
PORT_OFFSETS = {
    "agent": 0, "openfga": 1, "keycloak": 2,
    "temporal": 3, "temporal_ui": 4, "qdrant": 5, "redis": 6,
}

REALM = "rag"  # one realm per division (each division has its OWN Keycloak host)
# Seed-user (alice/bob) password is per-division random (see make_division_secrets);
# set RAG_SEED_PASSWORD to pin a known value for reproducible provisioning / tests.

# Shared single-source-of-truth provisioning bits (quality B-1). Ensure repo root is
# importable whether this file is run as a script (sys.path[0]=scripts/) or imported
# as scripts.onboard_division (tests).
sys.path.insert(0, str(ROOT))
from scripts._provisioning import (  # noqa: E402
    AUTH_MODEL,
    QDRANT_INGEST_SNIPPET,
    load_root_env,
)


def log(msg: str) -> None:
    print(f"[onboard] {msg}", flush=True)


# ── Pure helpers (no docker / no network — unit-tested by tests/test_onboarding.py) ──


@dataclass
class Manifest:
    division_id: str
    display_name: str
    port_base: int
    docs_dir: str
    residency_mode: str = "external"
    trusted_peers: list[str] = field(default_factory=list)
    seed_viewer: str = ""    # doc title alice may view directly
    seed_approval: str = ""  # doc title that needs the owner's approval (bob owns)
    # Governed tool capabilities this division SERVES locally (e.g. [tool.pii,
    # tool.compliance] for the compliance division; [] for a pure consumer). Written
    # to the agent env as AGT_LOCAL_TOOLS (CSV); tools.local_tools reads it to decide
    # which capabilities to register + advertise. Unset/missing key (None) = serve ALL
    # tools (the back-compat default — distinct from an explicit empty list = serve none).
    local_tools: list[str] | None = None
    # Cross-division pre-authorizations (FR-3.7): grant a named EXTERNAL user (from a
    # peer division) a relation on one of THIS division's docs, applied by
    # scripts/federate_divisions.py. Each item: {user_email, home_division, relation, doc}.
    cross_grants: list[dict] = field(default_factory=list)


def _parse_manifest_text(text: str) -> dict:
    """Parse a division manifest. Uses PyYAML (already a transitive dependency via
    agentmesh/agent-sre) for correctness — it handles #-in-value, quoting, and
    nested keys, which a hand-rolled parser does not. Falls back to a minimal
    key:value/[list] reader only if PyYAML is somehow unavailable."""
    try:
        import yaml
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except ImportError:
        out: dict[str, object] = {}
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].rstrip()
            if not line or ":" not in line:
                continue
            key, _, val = line.partition(":")
            key, val = key.strip(), val.strip()
            if not key:
                continue
            if val.startswith("[") and val.endswith("]"):
                inner = val[1:-1].strip()
                out[key] = [v.strip() for v in inner.split(",") if v.strip()] if inner else []
            elif val:
                out[key] = val
        return out


def load_manifest(path: str | Path) -> Manifest:
    data = _parse_manifest_text(Path(path).read_text(encoding="utf-8"))
    div = str(data.get("division_id", "")).strip()
    if not div:
        raise ValueError(f"{path}: manifest missing required 'division_id'")
    if not div.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"{path}: division_id '{div}' must be alphanumeric (+-/_)")
    try:
        port_base = int(str(data.get("port_base", "")).strip())
    except ValueError as exc:
        raise ValueError(f"{path}: manifest needs an integer 'port_base'") from exc
    assert_port_base_clean(port_base)  # reject collisions with the co-resident project
    peers = data.get("trusted_peers") or []
    if isinstance(peers, str):
        peers = [p.strip() for p in peers.split(",") if p.strip()]
    # local_tools: distinguish "key absent" (None -> serve ALL tools, back-compat) from
    # an explicit "[]" / "" (serve NONE locally -> the consumer that must delegate). A
    # CSV string ("tool.pii,tool.compliance") is accepted alongside a YAML list.
    lt_raw = data.get("local_tools", None)
    if lt_raw is None:
        local_tools: list[str] | None = None
    elif isinstance(lt_raw, str):
        local_tools = [t.strip() for t in lt_raw.split(",") if t.strip()]
    else:
        local_tools = [str(t).strip() for t in lt_raw if str(t).strip()]
    return Manifest(
        division_id=div,
        display_name=str(data.get("display_name", div)),
        port_base=port_base,
        docs_dir=str(data.get("docs_dir", "")),
        residency_mode=str(data.get("residency_mode", "external")),
        trusted_peers=list(peers),
        seed_viewer=str(data.get("seed_viewer", "")),
        seed_approval=str(data.get("seed_approval", "")),
        local_tools=local_tools,
        cross_grants=[g for g in (data.get("cross_grants") or []) if isinstance(g, dict)],
    )


def derive_ports(port_base: int) -> dict[str, int]:
    return {name: port_base + off for name, off in PORT_OFFSETS.items()}


# ── Co-resident project's reserved ports ────────────────────────────────────────
# Another project on this host computes its ports from a slot N (1..8). A division's
# OpenFGA port is port_base+1, which lands exactly on that project's BACKEND
# (8000+N*100+1 = 8101/8201/...) — silently binding the wrong service. We MUST keep
# division ports clear of the whole reserved set. Per slot N (1..8):
#   BACKEND=8000+N*100+1   PROXY=8000+N*100+80   POSTGRES=5433+N*100
#   NEO4J_BOLT=7687+N*100  NEO4J_HTTP=7474+N*100  REDIS=6379+N*100
#   FRONTEND_DEBUG=9229+N*100  BACKEND_DEBUG=5678+N*100
#   QDRANT_HTTP=6335+N*100  QDRANT_GRPC=6336+N*100
def _reserved_ports() -> set[int]:
    out: set[int] = set()
    for n in range(1, 9):
        out |= {8000 + n * 100 + 1, 8000 + n * 100 + 80, 5433 + n * 100,
                7687 + n * 100, 7474 + n * 100, 6379 + n * 100, 9229 + n * 100,
                5678 + n * 100, 6335 + n * 100, 6336 + n * 100}
    return out


RESERVED_PORTS = _reserved_ports()


def assert_port_base_clean(port_base: int) -> None:
    """Refuse a port_base whose derived ports collide with the co-resident project's
    reserved ports — clean bands are e.g. 8900/9000/9100/9200 (below FRONTEND_DEBUG@9329)."""
    clash = sorted(p for p in derive_ports(port_base).values() if p in RESERVED_PORTS)
    if clash:
        raise ValueError(
            f"port_base {port_base}: derived ports {clash} collide with the co-resident "
            f"project's reserved ports (slots N=1..8). Choose a clean port_base such as "
            f"9000/9100/9200."
        )


def compose_project(division_id: str) -> str:
    return f"agt-div-{division_id}"


def generated_dir(division_id: str) -> Path:
    return GENERATED_DIR / division_id


def discover_manifests(directory: str | Path = DIVISIONS_DIR) -> list[Path]:
    d = Path(directory)
    return sorted([*d.glob("*.yml"), *d.glob("*.yaml")]) if d.is_dir() else []


def render_stack_env(manifest: Manifest, ports: dict[str, int], secretz: dict[str, str]) -> str:
    """The --env-file passed to `docker compose` for this division's stack template."""
    return (
        f"DIV_ID={manifest.division_id}\n"
        f"DIV_OPENFGA_PORT={ports['openfga']}\n"
        f"DIV_KEYCLOAK_PORT={ports['keycloak']}\n"
        f"DIV_TEMPORAL_PORT={ports['temporal']}\n"
        f"DIV_TEMPORAL_UI_PORT={ports['temporal_ui']}\n"
        f"DIV_QDRANT_PORT={ports['qdrant']}\n"
        f"DIV_REDIS_PORT={ports['redis']}\n"
        f"POSTGRES_USER=openfga\n"
        f"POSTGRES_PASSWORD={secretz['postgres_password']}\n"
        f"OPENFGA_API_TOKEN={secretz['openfga_api_token']}\n"
        f"KEYCLOAK_ADMIN=admin\n"
        f"KEYCLOAK_ADMIN_PASSWORD={secretz['keycloak_admin_password']}\n"
    )


def render_agent_env(
    manifest: Manifest, ports: dict[str, int], secretz: dict[str, str],
    store_id: str, model_id: str, nvidia_key: str,
) -> str:
    """The per-division agent process env (config.Settings). Points every dependency
    at THIS division's own stack ports + store — that is the physical isolation."""
    kc = f"http://localhost:{ports['keycloak']}/realms/{REALM}"
    peers = ",".join(manifest.trusted_peers)
    # Governed local tools (compose parity with the k8s base ConfigMap). Only emit the
    # var when the manifest declares local_tools — absent (None) leaves it unset so
    # tools.local_tools keeps its serve-ALL default; an explicit [] writes the empty
    # value (serve none -> this division delegates). PEER_TOOL_MAP is added separately
    # by federate_divisions.py once the peers' provider DIDs are known.
    local_tools_line = (
        "" if manifest.local_tools is None
        else f"AGT_LOCAL_TOOLS={','.join(manifest.local_tools)}\n"
    )
    return (
        f"CLUSTER_ID={manifest.division_id}\n"
        f"DIVISION_ID={manifest.division_id}\n"
        f"TRUSTED_PEERS={peers}\n"
        f"RESIDENCY_MODE={manifest.residency_mode}\n"
        f"AGENT_NAME=AGT RAG - {manifest.display_name}\n"
        f"AGENT_URL=http://localhost:{ports['agent']}\nPORT={ports['agent']}\nHOST=127.0.0.1\n"
        f"OPENAI_API_BASE=https://integrate.api.nvidia.com/v1\n"
        f"OPENAI_API_KEY={nvidia_key}\n"
        f"LLM_MODEL=meta/llama-3.3-70b-instruct\nEMBEDDING_MODEL=nvidia/nv-embedqa-e5-v5\n"
        f"QDRANT_URL=http://localhost:{ports['qdrant']}\n"
        f"QDRANT_COLLECTION=knowledge_base\n"
        # Neo4j/GraphRAG is optional + inert in --no-neo4j mode (retrieval degrades to
        # Qdrant-only); config still requires the fields, so set harmless defaults.
        f"NEO4J_URI=bolt://localhost:7687\nNEO4J_USER=neo4j\nNEO4J_PASSWORD=none\n"
        f"REDIS_URL=redis://localhost:{ports['redis']}/0\n"
        f"OPENFGA_API_URL=http://localhost:{ports['openfga']}\n"
        f"OPENFGA_STORE_ID={store_id}\nOPENFGA_MODEL_ID={model_id}\n"
        f"OPENFGA_API_TOKEN={secretz['openfga_api_token']}\n"
        f"TEMPORAL_ADDRESS=localhost:{ports['temporal']}\nTEMPORAL_NAMESPACE=default\n"
        f"TEMPORAL_TASK_QUEUE=approval-{manifest.division_id}\n"
        f"OIDC_ISSUER={kc}\n"
        f"OIDC_JWKS_URI={kc}/protocol/openid-connect/certs\n"
        f"OIDC_TOKEN_ENDPOINT={kc}/protocol/openid-connect/token\n"
        f"ALLOWED_JWT_ALGORITHMS=RS256\n"
        f"AGENT_CLIENT_ID=agent-{manifest.division_id}\n"
        f"AGENT_CLIENT_SECRET={secretz['agent_client_secret']}\n"
        f"AGENT_SPONSOR_EMAIL=admin@example.com\n"
        f"APPROVAL_HMAC_SECRET={secretz['approval_hmac_secret']}\n"
        f"APPROVAL_UI_BASE_URL=http://localhost:{ports['agent']}\n"
        f"AGENT_IDENTITY_PATH=./agent_identity_{manifest.division_id}.json\n"
        f"AGENT_TRUST_THRESHOLD=0.6\nSRE_ENABLED=true\nLOG_LEVEL=info\n"
        f"CORS_ORIGINS=http://localhost:5173\n"
        f"{local_tools_line}"
    )


def make_division_secrets() -> dict[str, str]:
    """Fresh per-division secrets — each division has its OWN; none are shared (NFR-4)."""
    return {
        "postgres_password": secrets.token_hex(16),
        "openfga_api_token": secrets.token_urlsafe(24),
        "keycloak_admin_password": secrets.token_urlsafe(18),
        "agent_client_secret": secrets.token_urlsafe(24),
        "approval_hmac_secret": secrets.token_hex(32),
        # Per-division seed-user (alice/bob) password — random, persisted, NOT a
        # hardcoded constant (sec F2). Printed at onboard end; _repro_div reads it
        # from secrets.json. RAG_SEED_PASSWORD overrides for a known dev value.
        "seed_user_password": os.environ.get("RAG_SEED_PASSWORD") or secrets.token_urlsafe(16),
    }


def _write_secret(path: Path, data: str) -> None:
    """Write a secret-bearing file owner-only (0o600), with no world-readable window.

    Uses os.open(O_CREAT, 0o600) so the mode is applied atomically at creation
    (closing the gap a write-then-chmod leaves). On POSIX the mode is enforced; on
    Windows the mode arg is largely ignored (NTFS ACLs govern) but the call is safe.
    The per-division .env / stack-env / identity files hold Postgres + OpenFGA +
    agent + HMAC secrets and the Ed25519 private key — they must never be group/
    world-readable (NFR-4).
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)


def _load_or_make_secrets(division_id: str, force: bool = False) -> dict[str, str]:
    """Per-division secrets persisted at infra/generated/<id>/secrets.json so a
    re-run REUSES them (idempotency, prod B-1 / sec F1): the durable Postgres volume
    was initialised with the original password, so minting a fresh one would lock
    OpenFGA out of its datastore -> never healthy. force=True rotates (only safe
    after `--teardown`, which wipes the volumes too)."""
    gdir = generated_dir(division_id)
    gdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    sp = gdir / "secrets.json"
    if sp.exists() and not force:
        existing = json.loads(sp.read_text(encoding="utf-8"))
        # BACKFILL newly-added secret keys (schema evolution) WITHOUT rotating the
        # existing ones — rotating postgres_password would desync the durable volume.
        missing = {k: v for k, v in make_division_secrets().items() if k not in existing}
        if missing:
            existing.update(missing)
            _write_secret(sp, json.dumps(existing))
        return existing
    sec = make_division_secrets()
    _write_secret(sp, json.dumps(sec))
    return sec


def _state_path(division_id: str) -> Path:
    return generated_dir(division_id) / "state.json"


def _load_state(division_id: str) -> dict:
    p = _state_path(division_id)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _save_state(division_id: str, **kv) -> None:
    st = _load_state(division_id)
    st.update(kv)
    _write_secret(_state_path(division_id), json.dumps(st))


# ── Live orchestration (docker + network) ────────────────────────────────────


def compose_up(env_file: Path, project: str) -> None:
    subprocess.run(
        ["docker", "compose", "-p", project, "--env-file", str(env_file),
         "-f", str(TEMPLATE), "up", "-d"],
        check=True, cwd=str(ROOT),
    )


async def _wait(c, url: str, name: str) -> None:
    for _ in range(60):
        try:
            if (await c.get(url, timeout=3)).status_code < 500:
                log(f"{name} healthy")
                return
        except Exception:
            pass
        await asyncio.sleep(3)
    raise RuntimeError(f"{name} not healthy ({url})")


async def _wait_tcp(host: str, port: int, name: str) -> None:
    """Readiness for a non-HTTP service (Redis): a successful TCP connect (M-2)."""
    import socket
    for _ in range(60):
        try:
            with socket.create_connection((host, port), timeout=3):
                log(f"{name} healthy")
                return
        except OSError:
            await asyncio.sleep(3)
    raise RuntimeError(f"{name} not reachable ({host}:{port})")


async def provision(manifest: Manifest, ports: dict[str, int], secretz: dict[str, str],
                    no_neo4j: bool, force: bool = False) -> None:
    import httpx
    nvidia_key = (load_root_env(ROOT).get("NVIDIA_API_KEY") or os.environ.get("NVIDIA_API_KEY", ""))
    if not nvidia_key:
        raise SystemExit("NVIDIA_API_KEY not in ./.env or environment.")
    ofga = f"http://localhost:{ports['openfga']}"
    kc = f"http://localhost:{ports['keycloak']}"
    ofga_h = {"Authorization": f"Bearer {secretz['openfga_api_token']}"}

    async with httpx.AsyncClient(timeout=30) as c:
        await _wait(c, f"{ofga}/healthz", f"{manifest.division_id} OpenFGA")
        await _wait(c, f"{kc}/realms/master", f"{manifest.division_id} Keycloak")
        await _wait(c, f"http://localhost:{ports['qdrant']}/collections", f"{manifest.division_id} Qdrant")
        # M-2: gate on ALL stateful deps before provisioning, incl. Temporal (Web UI
        # HTTP) and Redis (TCP) — otherwise approval/worker wiring can race startup.
        await _wait(c, f"http://localhost:{ports['temporal_ui']}/", f"{manifest.division_id} Temporal")
        await _wait_tcp("localhost", ports["redis"], f"{manifest.division_id} Redis")

        # OpenFGA store + model (this division's OWN store). Reuse the persisted
        # store on re-run (idempotency) — create fresh only if missing or forced —
        # so we don't orphan a new store every run and the agent .env store_id stays
        # stable.
        st = _load_state(manifest.division_id)
        store_id = st.get("store_id")
        model_id = st.get("model_id")
        reuse = False
        if store_id and model_id and not force:
            sr = await c.get(f"{ofga}/stores/{store_id}", headers=ofga_h)
            reuse = sr.status_code == 200
        if reuse:
            log(f"OpenFGA store reused={store_id}")
        else:
            r = await c.post(f"{ofga}/stores", json={"name": f"div-{manifest.division_id}"}, headers=ofga_h)
            r.raise_for_status()
            store_id = r.json()["id"]
            r = await c.post(f"{ofga}/stores/{store_id}/authorization-models", json=AUTH_MODEL, headers=ofga_h)
            r.raise_for_status()
            model_id = r.json()["authorization_model_id"]
            _save_state(manifest.division_id, store_id=store_id, model_id=model_id)
            log(f"OpenFGA store={store_id}")
        # Both branches guarantee str here; narrow for the typed render_* below.
        assert isinstance(store_id, str) and isinstance(model_id, str)

        # Keycloak realm + clients + users (this division's OWN Keycloak).
        tr = await c.post(f"{kc}/realms/master/protocol/openid-connect/token",
                          data={"grant_type": "password", "client_id": "admin-cli",
                                "username": "admin", "password": secretz["keycloak_admin_password"]})
        tr.raise_for_status()
        h = {"Authorization": f"Bearer {tr.json()['access_token']}", "Content-Type": "application/json"}
        await c.post(f"{kc}/admin/realms", json={"realm": REALM, "enabled": True}, headers=h)
        await c.post(f"{kc}/admin/realms/{REALM}/clients",
                     json={"clientId": f"agent-{manifest.division_id}", "enabled": True,
                           "publicClient": False, "secret": secretz["agent_client_secret"],
                           "serviceAccountsEnabled": True, "directAccessGrantsEnabled": True}, headers=h)
        await c.post(f"{kc}/admin/realms/{REALM}/clients",
                     json={"clientId": "rag-ui", "enabled": True, "publicClient": True,
                           "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
                           "redirectUris": ["http://localhost:5173/*"]}, headers=h)
        # rag-ui browser tokens must carry THIS division's agent client_id in `aud`
        # (the agent's token_validator enforces audience). Single-division audience
        # only — NO cross-division mapper (that was AUD-1; M1 keeps it single).
        await _kc_add_ui_audience(c, kc, h, f"agent-{manifest.division_id}")
        for u, em in [("alice", "alice@example.com"), ("bob", "bob@example.com")]:
            await _kc_ensure_user(c, kc, h, u, em, secretz["seed_user_password"])
        # M1: division RBAC realm roles + assignments (FR-2.3). data-owner approves
        # access to data they own; division-admin manages the division (revoke/audit,
        # enforced in M5/M8); member is a regular querying user.
        await _kc_setup_roles(c, kc, h, {"alice": ["member"], "bob": ["data-owner", "division-admin"]})
        # FR-2.2: the agent's own service account may manage users in THIS realm only
        # (realm-management manage/view/query-users), backing the /admin/users API.
        await _kc().grant_user_admin_to_service_account(c, kc, REALM, h, f"agent-{manifest.division_id}")
        log("Keycloak realm + clients + users + roles ready")

    # DID identity (per division) + agent .env.
    did = ensure_identity(AGT / f"agent_identity_{manifest.division_id}.json",
                          f"rag-agent-{manifest.division_id}", manifest.division_id)
    gdir = generated_dir(manifest.division_id)
    gdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    agent_env = render_agent_env(manifest, ports, secretz, store_id, model_id, nvidia_key)
    env_path = AGT / f".env.{manifest.division_id}"
    _write_secret(env_path, agent_env)                         # holds NVIDIA key + secrets
    _write_secret(gdir / "did.json", json.dumps(did))          # DID + public JWK (kept owner-only for uniformity)
    log(f"wrote {env_path.relative_to(ROOT)} + DID {did['did']}")

    # Make the division FUNCTIONAL: ingest its docs into its own Qdrant + seed the
    # default authz tuples (alice may view one doc; the other needs bob's approval),
    # so the demo flows work immediately after onboarding.
    if manifest.docs_dir and (AGT / manifest.docs_dir).is_dir():
        _run_division_ingest(env_path.name, manifest.docs_dir)
        async with httpx.AsyncClient(timeout=30) as c2:
            await _seed_division_tuples(c2, manifest, ports, secretz, store_id)
        log(f"ingested docs + seeded authz for '{manifest.division_id}'")
    log(f"division '{manifest.division_id}' onboarded. Launch: RAG_ENV_FILE=.env.{manifest.division_id} -> :{ports['agent']}")


def ensure_identity(path: Path, name: str, org: str) -> dict:
    sys.path.insert(0, str(AGT))
    from agentmesh import AgentIdentity  # type: ignore[import]
    if path.exists():
        identity = AgentIdentity.from_jwks(json.loads(path.read_text(encoding="utf-8")))
    else:
        identity = AgentIdentity.create(name=name, sponsor="admin@example.com",
                                        capabilities=["rag.query", "a2a.federate"],
                                        organization=org, description=f"AGT RAG agent for {org}")
        # Ed25519 PRIVATE key — atomically owner-only (no write-then-chmod window).
        _write_secret(path, json.dumps(identity.to_jwks(include_private=True)))
    return {"did": str(identity.did), "jwk": json.dumps(identity.to_jwk(include_private=False))}


def _run_division_ingest(env_file: str, docs_dir: str) -> None:
    """Ingest docs_dir into THIS division's Qdrant (selected by RAG_ENV_FILE=.env.<id>)."""
    env = {**os.environ, "RAG_ENV_FILE": env_file}
    r = subprocess.run([str(VENV_PY), "-c", QDRANT_INGEST_SNIPPET, docs_dir],
                       cwd=str(AGT), env=env, capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        raise RuntimeError("division ingest failed")
    log(f"ingest: {r.stdout.strip().splitlines()[-1] if r.stdout.strip() else 'done'}")


async def _kc_add_ui_audience(c, kc: str, h: dict, agent_client_id: str) -> None:
    """Add an oidc-audience-mapper to rag-ui so its access tokens include
    agent_client_id in `aud` (the agent's token_validator requires it). Idempotent."""
    q = await c.get(f"{kc}/admin/realms/{REALM}/clients", params={"clientId": "rag-ui"}, headers=h)
    rows = q.json() if q.status_code == 200 else []
    if not rows:
        return
    uuid = rows[0]["id"]
    existing = await c.get(f"{kc}/admin/realms/{REALM}/clients/{uuid}/protocol-mappers/models", headers=h)
    names = {m["name"] for m in (existing.json() if existing.status_code == 200 else [])}
    name = f"aud-{agent_client_id}"
    if name in names:
        return
    await c.post(f"{kc}/admin/realms/{REALM}/clients/{uuid}/protocol-mappers/models",
                 json={"name": name, "protocol": "openid-connect",
                       "protocolMapper": "oidc-audience-mapper",
                       "config": {"included.client.audience": agent_client_id,
                                  "id.token.claim": "false", "access.token.claim": "true"}},
                 headers=h)


def _kc():
    """The shared Keycloak admin helpers (agt-federated-rag/auth/keycloak_admin.py) — the
    ONE Keycloak admin client, also used by the agent's FR-2.2 user-lifecycle API."""
    if str(AGT) not in sys.path:
        sys.path.insert(0, str(AGT))
    from auth import keycloak_admin  # type: ignore[import]
    return keycloak_admin


async def _kc_setup_roles(c, kc: str, h: dict, assignments: dict[str, list[str]]) -> None:
    """Create the division RBAC realm roles and assign them to seeded users (FR-2.3).
    Idempotent: role create 409s are fine; assignment is additive."""
    ka = _kc()
    await ka.ensure_realm_roles(c, kc, REALM, h, ka.DIVISION_ROLES)
    await ka.assign_realm_roles_by_username(c, kc, REALM, h, assignments)


async def _kc_ensure_user(c, kc: str, h: dict, username: str, email: str, password: str) -> None:
    """Create a realm user and RELIABLY set its password (create + lookup + force
    reset + clear required actions), so the direct-access-grant login works — a
    bare create can leave a required-action that 400s the password grant."""
    await _kc().ensure_user(c, kc, REALM, h, username, email, password)


def _seed_principal(email: str, issuer: str) -> str:
    """The OpenFGA authorization principal for a seeded user — MUST be byte-identical
    to auth.token_validator.principal() so seed-time tuples match runtime lookups.
    Format: ``<email-lower>|<sha256(issuer)[:16]>``, namespaced by the issuer so a
    division only authorizes its OWN users (test_principal_parity guards the drift)."""
    ns = hashlib.sha256(issuer.rstrip("/").encode("utf-8")).hexdigest()[:16]
    return f"{email.strip().lower()}|{ns}"


async def _ofga_write(c, ofga: str, store_id: str, headers: dict, tuple_key: dict) -> None:
    """Write ONE OpenFGA tuple, idempotently but NOT silently (quality finding M1).

    Mirrors auth/openfga.py: an existing tuple (HTTP 400 'already exists') is a no-op
    on re-provisioning, but EVERY other failure (bad token, wrong store_id, auth-model
    drift, malformed tuple) is raised — so a provisioning/federation run can never print
    'done' having written zero tuples and leave authorization to fail closed at query
    time with no signal."""
    r = await c.post(f"{ofga}/stores/{store_id}/write",
                     json={"writes": {"tuple_keys": [tuple_key]}}, headers=headers)
    if r.status_code == 400 and "already exist" in r.text.lower():
        return
    r.raise_for_status()


async def _seed_division_tuples(c, manifest: Manifest, ports: dict[str, int],
                                secretz: dict[str, str], store_id: str) -> None:
    """Seed default per-chunk authz: alice viewer on seed_viewer doc; alice
    pending_approval + bob owner on seed_approval doc (the local-answer and
    needs-approval flows). Tuples land in THIS division's OWN OpenFGA store and are
    keyed by the namespaced (issuer,email) principal — matching what the agent
    derives from a validated token at runtime."""
    ofga = f"http://localhost:{ports['openfga']}"
    ofga_h = {"Authorization": f"Bearer {secretz['openfga_api_token']}"}
    issuer = f"http://localhost:{ports['keycloak']}/realms/{REALM}"
    alice = _seed_principal("alice@example.com", issuer)
    bob = _seed_principal("bob@example.com", issuer)

    # chunk ids grouped by doc title, from this division's Qdrant.
    qd = f"http://localhost:{ports['qdrant']}"
    r = await c.post(f"{qd}/collections/knowledge_base/points/scroll",
                     json={"limit": 256, "with_payload": True, "with_vector": False})
    r.raise_for_status()
    by_title: dict[str, list[str]] = {}
    for pt in r.json()["result"]["points"]:
        pl = pt["payload"]
        title = pl.get("title") or (pl.get("metadata") or {}).get("title", "")
        cid = pl.get("chunk_id", "")
        if title and cid:
            by_title.setdefault(title, []).append(cid)

    async def grant(user: str, rel: str, title: str) -> None:
        for cid in by_title.get(title, []):
            await _ofga_write(c, ofga, store_id, ofga_h,
                              {"user": user, "relation": rel, "object": f"chunk:{cid}"})

    if manifest.seed_viewer:
        await grant(f"user:{alice}", "viewer", manifest.seed_viewer)
    if manifest.seed_approval:
        await grant(f"user:{alice}", "pending_approval", manifest.seed_approval)
        await grant(f"user:{bob}", "owner", manifest.seed_approval)


def onboard(manifest_path: str | Path, no_neo4j: bool = False, dry_run: bool = False,
            force: bool = False) -> dict:
    """Render (+ optionally stand up & provision) a division. Returns the render plan.

    IDEMPOTENT: secrets persist under infra/generated/<id>/ and are reused on re-run
    (so the durable Postgres volume password matches); the OpenFGA store is reused.
    dry_run=True does ONLY pure rendering (no docker/network) — safe in CI/tests.
    force=True rotates secrets + recreates the store (use after --teardown)."""
    manifest = load_manifest(manifest_path)
    ports = derive_ports(manifest.port_base)
    secretz = _load_or_make_secrets(manifest.division_id, force=force)
    gdir = generated_dir(manifest.division_id)
    gdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    stack_env = render_stack_env(manifest, ports, secretz)
    stack_env_path = gdir / f"div-{manifest.division_id}.env"
    _write_secret(stack_env_path, stack_env)   # Postgres/OpenFGA/Keycloak secrets — owner-only
    plan = {"division_id": manifest.division_id, "project": compose_project(manifest.division_id),
            "ports": ports, "stack_env": str(stack_env_path), "generated_dir": str(gdir)}
    if dry_run:
        log(f"[dry-run] rendered stack env for '{manifest.division_id}' -> {stack_env_path.relative_to(ROOT)}")
        return plan
    log(f"=== onboarding division '{manifest.division_id}' (ports {ports['agent']}..{ports['redis']}) ===")
    compose_up(stack_env_path, compose_project(manifest.division_id))
    asyncio.run(provision(manifest, ports, secretz, no_neo4j, force=force))
    return plan


def teardown(manifest_path: str | Path) -> None:
    """Offboard a division: docker compose down -v (containers + volumes) + remove
    generated artifacts, agent .env, and identity (prod B-2)."""
    import shutil
    manifest = load_manifest(manifest_path)
    project = compose_project(manifest.division_id)
    log(f"=== tearing down division '{manifest.division_id}' (project {project}) ===")
    cmd = ["docker", "compose", "-p", project]
    senv = generated_dir(manifest.division_id) / f"div-{manifest.division_id}.env"
    if senv.exists():
        cmd += ["--env-file", str(senv)]   # satisfy ${VAR:?} substitution during down
    cmd += ["-f", str(TEMPLATE), "down", "-v"]
    subprocess.run(cmd, cwd=str(ROOT), check=False)
    shutil.rmtree(generated_dir(manifest.division_id), ignore_errors=True)
    for p in (AGT / f".env.{manifest.division_id}",
              AGT / f"agent_identity_{manifest.division_id}.json"):
        p.unlink(missing_ok=True)
    log(f"division '{manifest.division_id}' torn down (containers, volumes, generated artifacts removed)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Onboard (or tear down) a division as an isolated stack.")
    ap.add_argument("manifest", help="path to a division manifest (infra/divisions/<id>.yml)")
    ap.add_argument("--no-neo4j", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="render configs only; no docker/network")
    ap.add_argument("--force", action="store_true",
                    help="rotate secrets + recreate the OpenFGA store (use after --teardown)")
    ap.add_argument("--teardown", action="store_true",
                    help="docker compose down -v + remove this division's generated artifacts")
    args = ap.parse_args()
    t0 = time.time()
    if args.teardown:
        teardown(args.manifest)
    else:
        onboard(args.manifest, no_neo4j=args.no_neo4j, dry_run=args.dry_run, force=args.force)
    log(f"done in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
