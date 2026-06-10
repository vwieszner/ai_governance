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
SEED_USER_PASSWORD = os.environ.get("RAG_SEED_PASSWORD", "Rag-User-2026!")

AUTH_MODEL = {
    "schema_version": "1.1",
    "type_definitions": [
        {"type": "user"},
        {
            "type": "group",
            "relations": {"member": {"this": {}}},
            "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}},
        },
        {
            "type": "chunk",
            "relations": {
                "owner": {"this": {}},
                "editor": {"union": {"child": [{"this": {}}, {"computedUserset": {"relation": "owner"}}]}},
                "viewer": {"union": {"child": [{"this": {}}, {"computedUserset": {"relation": "editor"}}]}},
                "pending_approval": {"this": {}},
            },
            "metadata": {
                "relations": {
                    "owner": {"directly_related_user_types": [{"type": "user"}]},
                    "editor": {"directly_related_user_types": [{"type": "user"}]},
                    "viewer": {"directly_related_user_types": [{"type": "user"}]},
                    "pending_approval": {"directly_related_user_types": [{"type": "user"}]},
                }
            },
        },
    ],
}


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


def _parse_simple_yaml(text: str) -> dict:
    """Tiny YAML subset parser for the flat division manifest (key: value + [list]).

    Avoids a hard PyYAML dependency for a trivially-simple manifest format. Supports
    `key: scalar`, `key: [a, b]`, and ignores blank/comment lines.
    """
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
    data = _parse_simple_yaml(Path(path).read_text(encoding="utf-8"))
    div = str(data.get("division_id", "")).strip()
    if not div:
        raise ValueError(f"{path}: manifest missing required 'division_id'")
    if not div.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"{path}: division_id '{div}' must be alphanumeric (+-/_)")
    try:
        port_base = int(str(data.get("port_base", "")).strip())
    except ValueError as exc:
        raise ValueError(f"{path}: manifest needs an integer 'port_base'") from exc
    peers = data.get("trusted_peers") or []
    if isinstance(peers, str):
        peers = [p.strip() for p in peers.split(",") if p.strip()]
    return Manifest(
        division_id=div,
        display_name=str(data.get("display_name", div)),
        port_base=port_base,
        docs_dir=str(data.get("docs_dir", "")),
        residency_mode=str(data.get("residency_mode", "external")),
        trusted_peers=list(peers),
    )


def derive_ports(port_base: int) -> dict[str, int]:
    return {name: port_base + off for name, off in PORT_OFFSETS.items()}


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
    )


def make_division_secrets() -> dict[str, str]:
    """Fresh per-division secrets — each division has its OWN; none are shared (NFR-4)."""
    return {
        "postgres_password": secrets.token_hex(16),
        "openfga_api_token": secrets.token_urlsafe(24),
        "keycloak_admin_password": secrets.token_urlsafe(18),
        "agent_client_secret": secrets.token_urlsafe(24),
        "approval_hmac_secret": secrets.token_hex(32),
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


def _load_root_env() -> dict[str, str]:
    env: dict[str, str] = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


# ── Live orchestration (docker + network) ────────────────────────────────────


def compose_up(env_file: Path, project: str) -> None:
    subprocess.run(
        ["docker", "compose", "-p", project, "--env-file", str(env_file),
         "-f", str(TEMPLATE), "up", "-d"],
        check=True, cwd=str(ROOT),
    )


async def _wait(c, url: str, name: str) -> None:
    import httpx  # local import so --dry-run / unit tests need no httpx
    for _ in range(60):
        try:
            if (await c.get(url, timeout=3)).status_code < 500:
                log(f"{name} healthy"); return
        except Exception:
            pass
        await asyncio.sleep(3)
    raise RuntimeError(f"{name} not healthy ({url})")


async def provision(manifest: Manifest, ports: dict[str, int], secretz: dict[str, str],
                    no_neo4j: bool) -> None:
    import httpx
    nvidia_key = (_load_root_env().get("NVIDIA_API_KEY") or os.environ.get("NVIDIA_API_KEY", ""))
    if not nvidia_key:
        raise SystemExit("NVIDIA_API_KEY not in ./.env or environment.")
    ofga = f"http://localhost:{ports['openfga']}"
    kc = f"http://localhost:{ports['keycloak']}"
    ofga_h = {"Authorization": f"Bearer {secretz['openfga_api_token']}"}

    async with httpx.AsyncClient(timeout=30) as c:
        await _wait(c, f"{ofga}/healthz", f"{manifest.division_id} OpenFGA")
        await _wait(c, f"{kc}/realms/master", f"{manifest.division_id} Keycloak")
        await _wait(c, f"http://localhost:{ports['qdrant']}/collections", f"{manifest.division_id} Qdrant")

        # OpenFGA store + model (this division's OWN store).
        r = await c.post(f"{ofga}/stores", json={"name": f"div-{manifest.division_id}"}, headers=ofga_h)
        r.raise_for_status(); store_id = r.json()["id"]
        r = await c.post(f"{ofga}/stores/{store_id}/authorization-models", json=AUTH_MODEL, headers=ofga_h)
        r.raise_for_status(); model_id = r.json()["authorization_model_id"]
        log(f"OpenFGA store={store_id}")

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
        for u, em in [("alice", "alice@example.com"), ("bob", "bob@example.com")]:
            await c.post(f"{kc}/admin/realms/{REALM}/users",
                         json={"username": u, "enabled": True, "email": em, "emailVerified": True,
                               "credentials": [{"type": "password", "value": SEED_USER_PASSWORD,
                                                "temporary": False}]}, headers=h)
        log("Keycloak realm + clients + users ready")

    # DID identity (per division) + agent .env.
    did = ensure_identity(AGT / f"agent_identity_{manifest.division_id}.json",
                          f"rag-agent-{manifest.division_id}", manifest.division_id)
    gdir = generated_dir(manifest.division_id); gdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    agent_env = render_agent_env(manifest, ports, secretz, store_id, model_id, nvidia_key)
    env_path = AGT / f".env.{manifest.division_id}"
    _write_secret(env_path, agent_env)                         # holds NVIDIA key + secrets
    _write_secret(gdir / "did.json", json.dumps(did))          # DID + public JWK (kept owner-only for uniformity)
    log(f"wrote {env_path.relative_to(ROOT)} + DID {did['did']}")
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


def onboard(manifest_path: str | Path, no_neo4j: bool = False, dry_run: bool = False) -> dict:
    """Render (+ optionally stand up & provision) a division. Returns the render plan.

    dry_run=True does ONLY pure rendering to infra/generated/<id>/ (no docker/network)
    — safe in CI / tests; proves the generator never edits source."""
    manifest = load_manifest(manifest_path)
    ports = derive_ports(manifest.port_base)
    secretz = make_division_secrets()
    gdir = generated_dir(manifest.division_id); gdir.mkdir(parents=True, exist_ok=True, mode=0o700)
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
    asyncio.run(provision(manifest, ports, secretz, no_neo4j))
    return plan


def main() -> None:
    ap = argparse.ArgumentParser(description="Onboard a division as an isolated stack.")
    ap.add_argument("manifest", help="path to a division manifest (infra/divisions/<id>.yml)")
    ap.add_argument("--no-neo4j", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="render configs only; no docker/network")
    args = ap.parse_args()
    t0 = time.time()
    onboard(args.manifest, no_neo4j=args.no_neo4j, dry_run=args.dry_run)
    log(f"done in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
