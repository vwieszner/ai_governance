"""
Idempotent end-to-end setup for the AGT federation: two agt-federated-rag clusters
(AGT / AgentMesh DID governance) that federate with each other.

Self-contained: provisions the shared Keycloak realm + rag-ui client + alice/bob
users AND the AgentMesh DID bootstrap. Each cluster gets a persistent Ed25519 DID
identity, and each cluster's .env is cross-wired with the PEER's DID + public JWK
so the trust handshake succeeds.

Run from the repo root with the project venv (NVIDIA_API_KEY must be in ./.env):
    .venv\\Scripts\\python.exe setup_agt.py            # Qdrant + Neo4j
    .venv\\Scripts\\python.exe setup_agt.py --no-neo4j  # Qdrant only (faster)

Ports/resources are DISTINCT from the A2A federation so both can run at once:
    AGT cluster-a: 8010   AGT cluster-b: 8012
    Redis db /3 (a) /4 (b)   Temporal queues agt-approval-a/-b
    Qdrant collections knowledge_base_agt_a / _b
    Keycloak clients agent-agt-a / agent-agt-b
Shared infra (OpenFGA, Keycloak, Temporal, Qdrant, Neo4j) is reused, partitioned.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).parent
VENV_PY = ROOT / ".venv" / "Scripts" / "python.exe"
AGT = ROOT / "agt-federated-rag"

# Shared single-source-of-truth provisioning bits (quality B-1) — same OpenFGA auth
# model + ingest snippet + root-.env loader used by scripts/onboard_division.py.
sys.path.insert(0, str(ROOT))
from scripts._provisioning import (  # noqa: E402
    AUTH_MODEL,
    QDRANT_INGEST_SNIPPET,
    load_root_env,
)

OPENFGA = "http://localhost:8089"
KEYCLOAK = "http://localhost:8087"
QDRANT = "http://localhost:16333"
REALM = "rag"

# Seeded user password. Override with RAG_SEED_PASSWORD.
SEED_USER_PASSWORD = os.environ.get("RAG_SEED_PASSWORD", "Rag-User-2026!")

# Documents (bundled in this repo at agt-federated-rag/tests/docs/).
DOCS_A = AGT / "tests" / "docs" / "cluster-a"
DOCS_B = AGT / "tests" / "docs" / "cluster-b"
ALICE_VIEW_A = "data_retention_policy"
ALICE_PEND_A = "hr_compensation_data"
ALICE_VIEW_B = "technical_architecture"
ALICE_PEND_B = "q4_financial_results"

ID_PATH_A = AGT / "agent_identity_agt_a.json"
ID_PATH_B = AGT / "agent_identity_agt_b.json"

# AUTH_MODEL now imported from scripts._provisioning (single source of truth).


def log(msg: str) -> None:
    print(f"[setup-agt] {msg}", flush=True)


_ENV = load_root_env(ROOT)


def _need(key: str) -> str:
    val = _ENV.get(key) or os.environ.get(key, "")
    if not val:
        print(f"ERROR: {key} not in ./.env or environment. Run `python init_secrets.py` first.",
              file=sys.stderr)
        raise SystemExit(2)
    return val


NVIDIA_KEY = _need("NVIDIA_API_KEY")
HMAC_A = _need("APPROVAL_HMAC_SECRET_A")
HMAC_B = _need("APPROVAL_HMAC_SECRET_B")
AGENT_SECRET_A = _need("AGENT_CLIENT_SECRET_A")
AGENT_SECRET_B = _need("AGENT_CLIENT_SECRET_B")
OPENFGA_TOKEN = _need("OPENFGA_API_TOKEN")
OFGA_HEADERS = {"Authorization": f"Bearer {OPENFGA_TOKEN}"}


# ── AgentMesh DID identities ────────────────────────────────────────────────

def ensure_identity(path: Path, name: str, org: str) -> dict:
    """Create (or load) a persistent AgentMesh DID identity. Returns its public JWK.

    Writes the full JWKS (incl. private key) to `path` so the backend reloads the
    SAME identity (stable DID across restarts), and returns the PUBLIC JWK plus DID
    for cross-wiring into the peer's config.
    """
    sys.path.insert(0, str(AGT))
    from agentmesh import AgentIdentity  # type: ignore[import]

    if path.exists():
        identity = AgentIdentity.from_jwks(json.loads(path.read_text(encoding="utf-8")))
    else:
        identity = AgentIdentity.create(
            name=name, sponsor="admin@example.com",
            capabilities=["rag.query", "a2a.federate"],
            organization=org, description=f"AGT federated RAG agent for {org}",
        )
        path.write_text(json.dumps(identity.to_jwks(include_private=True)), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return {"did": str(identity.did), "jwk": json.dumps(identity.to_jwk(include_private=False))}


# ── Infra helpers ───────────────────────────────────────────────────────────

async def wait_healthy(c: httpx.AsyncClient) -> None:
    for name, url in {"OpenFGA": f"{OPENFGA}/healthz", "Keycloak": f"{KEYCLOAK}/realms/master",
                      "Qdrant": f"{QDRANT}/collections"}.items():
        for _ in range(40):
            try:
                if (await c.get(url, timeout=3)).status_code == 200:
                    log(f"{name} healthy"); break
            except Exception:
                pass
            await asyncio.sleep(3)
        else:
            raise RuntimeError(f"{name} not healthy ({url})")


async def create_openfga_store(c: httpx.AsyncClient) -> tuple[str, str]:
    r = await c.post(f"{OPENFGA}/stores", json={"name": "agt-federated-rag"}, headers=OFGA_HEADERS)
    r.raise_for_status()
    sid = r.json()["id"]
    r = await c.post(f"{OPENFGA}/stores/{sid}/authorization-models", json=AUTH_MODEL, headers=OFGA_HEADERS)
    r.raise_for_status()
    mid = r.json()["authorization_model_id"]
    log(f"OpenFGA store={sid} model={mid}")
    return sid, mid


async def kc_admin_token(c: httpx.AsyncClient) -> str:
    r = await c.post(f"{KEYCLOAK}/realms/master/protocol/openid-connect/token",
                     data={"grant_type": "password", "client_id": "admin-cli",
                           "username": _ENV.get("KEYCLOAK_ADMIN", "admin"),
                           "password": _need("KEYCLOAK_ADMIN_PASSWORD")})
    r.raise_for_status()
    return r.json()["access_token"]


async def kc_ensure_agent_client(c: httpx.AsyncClient, h: dict, cid: str, secret: str) -> None:
    body = {"clientId": cid, "enabled": True, "publicClient": False, "secret": secret,
            "standardFlowEnabled": False, "serviceAccountsEnabled": True,
            "directAccessGrantsEnabled": True}
    r = await c.post(f"{KEYCLOAK}/admin/realms/{REALM}/clients", json=body, headers=h)
    if r.status_code == 409:
        log(f"client {cid} exists")
    else:
        r.raise_for_status(); log(f"client {cid} created")


async def kc_ensure_realm(c: httpx.AsyncClient, h: dict) -> None:
    r = await c.post(f"{KEYCLOAK}/admin/realms",
                     json={"realm": REALM, "enabled": True, "displayName": "Federated RAG"}, headers=h)
    log("realm exists" if r.status_code == 409 else "realm created")


async def kc_ensure_ui_client(c: httpx.AsyncClient, h: dict) -> None:
    """Create the public browser-login client (rag-ui) + audience mappers.

    The AGT backends validate that the token `aud` contains their own client_id
    (agent-agt-a / agent-agt-b). A browser rag-ui token defaults to aud=account,
    so attach hardcoded-audience mappers that add both AGT agent client_ids.
    """
    body = {
        "clientId": "rag-ui", "enabled": True, "publicClient": True,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
        "redirectUris": ["http://localhost:5173/*"], "webOrigins": ["http://localhost:5173"],
    }
    r = await c.post(f"{KEYCLOAK}/admin/realms/{REALM}/clients", json=body, headers=h)
    log("rag-ui exists" if r.status_code == 409 else "rag-ui created")

    q = await c.get(f"{KEYCLOAK}/admin/realms/{REALM}/clients",
                    params={"clientId": "rag-ui"}, headers=h)
    client_uuid = q.json()[0]["id"]
    existing = await c.get(
        f"{KEYCLOAK}/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
        headers=h,
    )
    existing_names = {m["name"] for m in existing.json()}
    for aud in ("agent-agt-a", "agent-agt-b"):
        name = f"aud-{aud}"
        if name in existing_names:
            continue
        mapper = {
            "name": name,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.client.audience": aud,
                "id.token.claim": "false",
                "access.token.claim": "true",
            },
        }
        mr = await c.post(
            f"{KEYCLOAK}/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
            json=mapper, headers=h,
        )
        log(f"rag-ui audience mapper {aud}: {'ok' if mr.status_code in (201,204) else mr.status_code}")


async def kc_ensure_user(c: httpx.AsyncClient, h: dict, username: str, email: str) -> None:
    body = {
        "username": username, "enabled": True, "email": email, "emailVerified": True,
        "firstName": username.capitalize(), "lastName": "User",
        "credentials": [{"type": "password", "value": SEED_USER_PASSWORD, "temporary": False}],
    }
    r = await c.post(f"{KEYCLOAK}/admin/realms/{REALM}/users", json=body, headers=h)
    log(f"user {username} exists" if r.status_code == 409 else f"user {username} created")
    # Idempotently (re)set the password so an existing user always matches.
    lookup = await c.get(f"{KEYCLOAK}/admin/realms/{REALM}/users",
                         params={"username": username, "exact": "true"}, headers=h)
    lookup.raise_for_status()
    users = lookup.json()
    if users:
        uid = users[0]["id"]
        await c.put(
            f"{KEYCLOAK}/admin/realms/{REALM}/users/{uid}/reset-password",
            json={"type": "password", "value": SEED_USER_PASSWORD, "temporary": False},
            headers=h,
        )


async def kc_sub(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token",
                     data={"grant_type": "password", "client_id": "rag-ui",
                           "username": username, "password": SEED_USER_PASSWORD})
    r.raise_for_status()
    import base64
    p = r.json()["access_token"].split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))["sub"]


def write_env(store_id: str, model_id: str, a_id: dict, b_id: dict) -> None:
    common = (
        f"OPENAI_API_BASE=https://integrate.api.nvidia.com/v1\n"
        f"OPENAI_API_KEY={NVIDIA_KEY}\n"
        f"LLM_MODEL=meta/llama-3.3-70b-instruct\n"
        f"EMBEDDING_MODEL=nvidia/nv-embedqa-e5-v5\n"
        f"QDRANT_URL=http://localhost:16333\n"
        f"NEO4J_URI=bolt://localhost:17687\nNEO4J_USER=neo4j\nNEO4J_PASSWORD=none\n"
        f"OPENFGA_API_URL=http://localhost:8089\n"
        f"OPENFGA_STORE_ID={store_id}\nOPENFGA_MODEL_ID={model_id}\n"
        f"OPENFGA_API_TOKEN={OPENFGA_TOKEN}\n"
        f"TEMPORAL_ADDRESS=localhost:7233\nTEMPORAL_NAMESPACE=default\n"
        f"OIDC_ISSUER=http://localhost:8087/realms/rag\n"
        f"OIDC_JWKS_URI=http://localhost:8087/realms/rag/protocol/openid-connect/certs\n"
        f"OIDC_TOKEN_ENDPOINT=http://localhost:8087/realms/rag/protocol/openid-connect/token\n"
        f"ALLOWED_JWT_ALGORITHMS=RS256\n"
        f"AGENT_SPONSOR_EMAIL=admin@example.com\n"
        f"AGENT_TRUST_THRESHOLD=0.0\nSRE_ENABLED=true\nLOG_LEVEL=info\nDOCS_ENABLED=true\n"
        f"CORS_ORIGINS=http://localhost:5173\n"
    )
    a = (
        f"CLUSTER_ID=cluster-a\nAGENT_NAME=AGT Federated RAG - Cluster A\n"
        f"AGENT_URL=http://localhost:8010\nPORT=8010\nHOST=127.0.0.1\n"
        f"QDRANT_COLLECTION=knowledge_base_agt_a\nREDIS_URL=redis://localhost:6379/3\n"
        f"TEMPORAL_TASK_QUEUE=agt-approval-a\n"
        f"AGENT_CLIENT_ID=agent-agt-a\nAGENT_CLIENT_SECRET={AGENT_SECRET_A}\n"
        f"APPROVAL_HMAC_SECRET={HMAC_A}\nAPPROVAL_UI_BASE_URL=http://localhost:8010\n"
        f"AGENT_IDENTITY_PATH=./agent_identity_agt_a.json\n"
        f"PEER_AGENT_URL=http://localhost:8012\n"
        f"PEER_AGENT_CARD_URL=http://localhost:8012/.well-known/agent-card.json\n"
        f"PEER_AGENT_CLIENT_IDS=agent-agt-b\n"
        f"PEER_AGENT_DID={b_id['did']}\n"
        f"PEER_AGENT_PUBLIC_JWK={b_id['jwk']}\n"
        + common
    )
    b = (
        f"CLUSTER_ID=cluster-b\nAGENT_NAME=AGT Federated RAG - Cluster B\n"
        f"AGENT_URL=http://localhost:8012\nPORT=8012\nHOST=127.0.0.1\n"
        f"QDRANT_COLLECTION=knowledge_base_agt_b\nREDIS_URL=redis://localhost:6379/4\n"
        f"TEMPORAL_TASK_QUEUE=agt-approval-b\n"
        f"AGENT_CLIENT_ID=agent-agt-b\nAGENT_CLIENT_SECRET={AGENT_SECRET_B}\n"
        f"APPROVAL_HMAC_SECRET={HMAC_B}\nAPPROVAL_UI_BASE_URL=http://localhost:8012\n"
        f"AGENT_IDENTITY_PATH=./agent_identity_agt_b.json\n"
        f"PEER_AGENT_URL=http://localhost:8010\n"
        f"PEER_AGENT_CARD_URL=http://localhost:8010/.well-known/agent-card.json\n"
        f"PEER_AGENT_CLIENT_IDS=agent-agt-a\n"
        f"PEER_AGENT_DID={a_id['did']}\n"
        f"PEER_AGENT_PUBLIC_JWK={a_id['jwk']}\n"
        + common
    )
    (AGT / ".env").write_text(a, encoding="utf-8")
    (AGT / ".env.cluster-b").write_text(b, encoding="utf-8")
    log("wrote agt-federated-rag/.env and .env.cluster-b (peer DID+JWK cross-wired)")


def run_ingest(label: str, docs: Path, no_neo4j: bool, env_file: str) -> None:
    args = [str(VENV_PY), "-c", QDRANT_INGEST_SNIPPET, str(docs)] if no_neo4j else \
           [str(VENV_PY), "-m", "rag.ingest", "--path", str(docs)]
    env = {**os.environ, "RAG_ENV_FILE": env_file}
    log(f"ingest {label} ({env_file}) ...")
    r = subprocess.run(args, cwd=str(AGT), env=env, capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        print(r.stdout[-2000:]); print(r.stderr[-2000:])
        raise RuntimeError(f"ingest failed for {label}")
    log(f"ingest {label} OK: {r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ''}")


async def qdrant_chunks(c: httpx.AsyncClient, collection: str) -> dict[str, list[str]]:
    r = await c.post(f"{QDRANT}/collections/{collection}/points/scroll",
                     json={"limit": 100, "with_payload": True, "with_vector": False})
    r.raise_for_status()
    out: dict[str, list[str]] = {}
    for pt in r.json()["result"]["points"]:
        pl = pt["payload"]
        title = pl.get("title") or (pl.get("metadata") or {}).get("title", "")
        cid = pl.get("chunk_id", "")
        if title and cid:
            out.setdefault(title, []).append(cid)
    return out


async def write_tuple(c, store, user, rel, obj):
    r = await c.post(f"{OPENFGA}/stores/{store}/write",
                     json={"writes": {"tuple_keys": [{"user": user, "relation": rel, "object": obj}]}},
                     headers=OFGA_HEADERS)
    if not (r.status_code in (200, 201) or "already exists" in r.text):
        log(f"tuple ERR {r.status_code}: {r.text[:150]}")


async def check(c, store, user, rel, obj) -> bool:
    r = await c.post(f"{OPENFGA}/stores/{store}/check",
                     json={"tuple_key": {"user": user, "relation": rel, "object": obj}},
                     headers=OFGA_HEADERS)
    return bool(r.json().get("allowed"))


async def main(no_neo4j: bool) -> None:
    async with httpx.AsyncClient(timeout=30) as c:
        log("=== Phase 1: wait for services ==="); await wait_healthy(c)
        log("=== Phase 2: OpenFGA store ==="); store_id, model_id = await create_openfga_store(c)
        log("=== Phase 3: AgentMesh DID identities ===")
        a_id = ensure_identity(ID_PATH_A, "rag-agent-agt-cluster-a", "cluster-a")
        b_id = ensure_identity(ID_PATH_B, "rag-agent-agt-cluster-b", "cluster-b")
        log(f"cluster-a DID={a_id['did']}")
        log(f"cluster-b DID={b_id['did']}")
        log("=== Phase 4: Keycloak (realm, agent clients, rag-ui, users) ===")
        tok = await kc_admin_token(c)
        h = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
        await kc_ensure_realm(c, h)
        await kc_ensure_agent_client(c, h, "agent-agt-a", AGENT_SECRET_A)
        await kc_ensure_agent_client(c, h, "agent-agt-b", AGENT_SECRET_B)
        await kc_ensure_ui_client(c, h)
        await kc_ensure_user(c, h, "alice", "alice@example.com")
        await kc_ensure_user(c, h, "bob", "bob@example.com")
        alice = await kc_sub(c, "alice"); bob = await kc_sub(c, "bob")
        log(f"alice={alice} bob={bob}")
        log("=== Phase 5: write .env files ==="); write_env(store_id, model_id, a_id, b_id)
        log("=== Phase 6: ingest ===")
        run_ingest("cluster-a", DOCS_A, no_neo4j, ".env")
        run_ingest("cluster-b", DOCS_B, no_neo4j, ".env.cluster-b")
        log("=== Phase 7: chunk ids ===")
        ca = await qdrant_chunks(c, "knowledge_base_agt_a")
        cb = await qdrant_chunks(c, "knowledge_base_agt_b")
        for need, coll in [(ALICE_VIEW_A, ca), (ALICE_PEND_A, ca), (ALICE_VIEW_B, cb), (ALICE_PEND_B, cb)]:
            if need not in coll:
                raise RuntimeError(f"doc '{need}' not in Qdrant ({list(coll)})")
        log("=== Phase 8: OpenFGA tuples ===")
        au, bu = f"user:{alice}", f"user:{bob}"

        async def grant_all(u, rel, ids):
            for cid in ids:
                await write_tuple(c, store_id, u, rel, f"chunk:{cid}")

        await grant_all(au, "viewer", ca[ALICE_VIEW_A])
        await grant_all(au, "pending_approval", ca[ALICE_PEND_A])
        await grant_all(bu, "owner", ca[ALICE_PEND_A])
        await grant_all(au, "viewer", cb[ALICE_VIEW_B])
        await grant_all(au, "pending_approval", cb[ALICE_PEND_B])
        await grant_all(bu, "owner", cb[ALICE_PEND_B])

        async def all_ok(u, rel, ids):
            for cid in ids:
                if not await check(c, store_id, u, rel, f"chunk:{cid}"):
                    return False
            return True

        async def none_ok(u, rel, ids):
            for cid in ids:
                if await check(c, store_id, u, rel, f"chunk:{cid}"):
                    return False
            return True

        results = {
            "A alice viewer data_retention": await all_ok(au, "viewer", ca[ALICE_VIEW_A]),
            "B alice pending hr":            await all_ok(au, "pending_approval", ca[ALICE_PEND_A]),
            "B alice NOT viewer hr":         await none_ok(au, "viewer", ca[ALICE_PEND_A]),
            "C alice viewer tech_arch":      await all_ok(au, "viewer", cb[ALICE_VIEW_B]),
            "D alice pending q4":            await all_ok(au, "pending_approval", cb[ALICE_PEND_B]),
        }
        print("\n============ AGT SETUP SUMMARY ============")
        ok = True
        for k, v in results.items():
            print(f"  [{'PASS' if v else 'FAIL'}] {k}"); ok = ok and v
        print(f"  OpenFGA store: {store_id}")
        print(f"  cluster-a DID: {a_id['did']}")
        print(f"  cluster-b DID: {b_id['did']}")
        print(f"  alice={alice}  bob={bob}")
        print("==========================================")
        print("Next: launch the AGT clusters (ports 8010 / 8012).")
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-neo4j", action="store_true")
    args = ap.parse_args()
    t0 = time.time()
    asyncio.run(main(args.no_neo4j))
    log(f"done in {time.time()-t0:.0f}s")
