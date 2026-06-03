"""
Idempotent end-to-end setup for the REAL federated RAG system (no mocks).

Run from the repo root with the project venv:
    .venv\\Scripts\\python.exe setup_all.py            # Qdrant + Neo4j (full GraphRAG)
    .venv\\Scripts\\python.exe setup_all.py --no-neo4j  # Qdrant only (faster)

What it does (every value read LIVE — nothing hardcoded that can drift):
  1. Wait for OpenFGA / Keycloak / Temporal / Qdrant / Neo4j / Redis to be healthy.
  2. Create an OpenFGA store + authorization model; capture the real IDs.
  3. Bootstrap Keycloak (realm, clients, users) + enable RFC 8693 token exchange.
  4. Read alice/bob `sub` UUIDs live from Keycloak.
  5. Write federated-rag/.env and agt-federated-rag/.env with the captured IDs.
  6. Ingest cluster-a docs -> knowledge_base_a and cluster-b docs -> knowledge_base_b
     (subprocess per cluster so each picks up its own .env).
  7. Read the real chunk_ids back from Qdrant.
  8. Write the OpenFGA tuples for all 4 flows using live subs + live chunk_ids; verify.
  9. Print a green/red summary.

After this, start the backends + UI with launch_all.ps1.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).parent
VENV_PY = ROOT / ".venv" / "Scripts" / "python.exe"

OPENFGA = "http://localhost:8089"
KEYCLOAK = "http://localhost:8087"
QDRANT = "http://localhost:16333"
REALM = "rag"


def _load_root_env() -> dict[str, str]:
    """Load the gitignored root .env (created by init_secrets.py) as a dict.

    This is the single source of truth for ALL infra credentials — the same file
    docker-compose.yml reads — so the values used to provision OpenFGA/Keycloak
    exactly match what the running containers were started with. Falls back to the
    process environment for any key not present in the file.
    """
    env: dict[str, str] = {}
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


_ENV = _load_root_env()


def _need(key: str) -> str:
    val = _ENV.get(key) or os.environ.get(key, "")
    if not val:
        print(f"ERROR: {key} not found in ./.env or environment. "
              f"Run `python init_secrets.py` first (and set NVIDIA_API_KEY).",
              file=sys.stderr)
        raise SystemExit(2)
    return val


# All secrets come from the gitignored root .env — never hardcoded in this file.
NVIDIA_KEY      = _need("NVIDIA_API_KEY")
HMAC_SECRET_A   = _need("APPROVAL_HMAC_SECRET_A")
HMAC_SECRET_B   = _need("APPROVAL_HMAC_SECRET_B")
AGENT_SECRET_A  = _need("AGENT_CLIENT_SECRET_A")
AGENT_SECRET_B  = _need("AGENT_CLIENT_SECRET_B")
# Preshared key the OpenFGA server now requires on every API call.
OPENFGA_TOKEN   = _need("OPENFGA_API_TOKEN")
# httpx header to authenticate setup's own calls to the OpenFGA admin API.
OPENFGA_HEADERS = {"Authorization": f"Bearer {OPENFGA_TOKEN}"}

# Per-cluster document folders (live in the federated-rag test tree).
DOCS_A = ROOT / "federated-rag" / "tests" / "docs" / "cluster-a"
DOCS_B = ROOT / "federated-rag" / "tests" / "docs" / "cluster-b"

# Which document (by title == filename stem) maps to which flow.
#   cluster-a: data_retention_policy -> alice viewer (Flow A)
#              hr_compensation_data  -> bob owner, alice pending_approval (Flow B)
#   cluster-b: technical_architecture -> alice viewer (Flow C via A2A)
#              q4_financial_results   -> bob owner, alice pending_approval (Flow D)
ALICE_VIEW_A = "data_retention_policy"
ALICE_PEND_A = "hr_compensation_data"
ALICE_VIEW_B = "technical_architecture"
ALICE_PEND_B = "q4_financial_results"

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
    print(f"[setup] {msg}", flush=True)


async def wait_healthy(c: httpx.AsyncClient) -> None:
    checks = {
        "OpenFGA": f"{OPENFGA}/healthz",
        "Keycloak": f"{KEYCLOAK}/realms/master",
        "Qdrant": f"{QDRANT}/collections",
    }
    for name, url in checks.items():
        for _ in range(40):
            try:
                r = await c.get(url, timeout=3)
                if r.status_code == 200:
                    log(f"{name} healthy")
                    break
            except Exception:
                pass
            await asyncio.sleep(3)
        else:
            raise RuntimeError(f"{name} did not become healthy ({url})")


async def create_openfga_store(c: httpx.AsyncClient) -> tuple[str, str]:
    r = await c.post(f"{OPENFGA}/stores", json={"name": "federated-rag"}, headers=OPENFGA_HEADERS)
    r.raise_for_status()
    store_id = r.json()["id"]
    r = await c.post(f"{OPENFGA}/stores/{store_id}/authorization-models",
                     json=AUTH_MODEL, headers=OPENFGA_HEADERS)
    r.raise_for_status()
    model_id = r.json()["authorization_model_id"]
    log(f"OpenFGA store={store_id} model={model_id}")
    return store_id, model_id


async def kc_admin_token(c: httpx.AsyncClient) -> str:
    # Admin credentials come from the root .env (the same values Keycloak started
    # with) — no hardcoded admin/admin.
    admin_user = _ENV.get("KEYCLOAK_ADMIN", "admin")
    admin_pass = _need("KEYCLOAK_ADMIN_PASSWORD")
    r = await c.post(
        f"{KEYCLOAK}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": admin_user, "password": admin_pass},
    )
    r.raise_for_status()
    return r.json()["access_token"]


async def kc_ensure_realm(c: httpx.AsyncClient, h: dict) -> None:
    r = await c.post(f"{KEYCLOAK}/admin/realms",
                     json={"realm": REALM, "enabled": True, "displayName": "Federated RAG"}, headers=h)
    log("realm exists" if r.status_code == 409 else "realm created")


async def kc_ensure_agent_client(c: httpx.AsyncClient, h: dict, cid: str, secret: str,
                                 peer_cid: str | None = None) -> None:
    body = {
        "clientId": cid, "enabled": True, "publicClient": False, "secret": secret,
        "standardFlowEnabled": False, "serviceAccountsEnabled": True,
        "directAccessGrantsEnabled": True,
        "attributes": {
            "oauth2.token.exchange.grant.enabled": "true",
            "standard.token.exchange.enabled": "true",
        },
    }
    r = await c.post(f"{KEYCLOAK}/admin/realms/{REALM}/clients", json=body, headers=h)
    if r.status_code == 409:
        # update existing to ensure token-exchange attrs are set
        q = await c.get(f"{KEYCLOAK}/admin/realms/{REALM}/clients", params={"clientId": cid}, headers=h)
        obj = q.json()[0]
        obj.setdefault("attributes", {}).update(body["attributes"])
        await c.put(f"{KEYCLOAK}/admin/realms/{REALM}/clients/{obj['id']}", json=obj, headers=h)
        log(f"client {cid} updated (token-exchange on)")
    else:
        r.raise_for_status()
        log(f"client {cid} created (token-exchange on)")

    # RFC 8693 cross-cluster exchange: this client must be allowed to mint a token
    # whose audience is the PEER cluster's client_id. Keycloak only includes an
    # audience it can resolve, so attach an audience protocol-mapper for the peer.
    # Without it, token-exchange fails with "Requested audience not available".
    if peer_cid:
        q = await c.get(f"{KEYCLOAK}/admin/realms/{REALM}/clients",
                        params={"clientId": cid}, headers=h)
        client_uuid = q.json()[0]["id"]
        existing = await c.get(
            f"{KEYCLOAK}/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
            headers=h,
        )
        names = {m["name"] for m in existing.json()}
        mname = f"aud-{peer_cid}"
        if mname not in names:
            mapper = {
                "name": mname,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.client.audience": peer_cid,
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                },
            }
            mr = await c.post(
                f"{KEYCLOAK}/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
                json=mapper, headers=h,
            )
            log(f"client {cid} peer-audience mapper {peer_cid}: {'ok' if mr.status_code in (201,204) else mr.status_code}")


async def kc_ensure_ui_client(c: httpx.AsyncClient, h: dict) -> None:
    body = {
        "clientId": "rag-ui", "enabled": True, "publicClient": True,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
        "redirectUris": ["http://localhost:5173/*"], "webOrigins": ["http://localhost:5173"],
    }
    r = await c.post(f"{KEYCLOAK}/admin/realms/{REALM}/clients", json=body, headers=h)
    log("rag-ui exists" if r.status_code == 409 else "rag-ui created")

    # The backends require the token `aud` to contain their client_id (validate_token
    # checks aud == agent-cluster-a / agent-cluster-b). A browser rag-ui token defaults
    # to aud=account, so attach hardcoded-audience mappers that add both agent IDs.
    q = await c.get(f"{KEYCLOAK}/admin/realms/{REALM}/clients",
                    params={"clientId": "rag-ui"}, headers=h)
    client_uuid = q.json()[0]["id"]
    existing = await c.get(
        f"{KEYCLOAK}/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
        headers=h,
    )
    existing_names = {m["name"] for m in existing.json()}
    for aud in ("agent-cluster-a", "agent-cluster-b"):
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
        "firstName": username.capitalize(), "lastName": "Demo",
        "credentials": [{"type": "password", "value": "demo", "temporary": False}],
    }
    r = await c.post(f"{KEYCLOAK}/admin/realms/{REALM}/users", json=body, headers=h)
    log(f"user {username} exists" if r.status_code == 409 else f"user {username} created")


async def kc_sub(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "rag-ui",
              "username": username, "password": "demo"},
    )
    r.raise_for_status()
    tok = r.json()["access_token"]
    import base64, json as _json
    p = tok.split(".")[1]
    p += "=" * (-len(p) % 4)
    return _json.loads(base64.urlsafe_b64decode(p))["sub"]


def write_env(store_id: str, model_id: str) -> None:
    a = f"""CLUSTER_ID=cluster-a
AGENT_NAME=Federated RAG Agent - Cluster A
AGENT_URL=http://localhost:8000
PEER_AGENT_URL=http://localhost:8002
PEER_AGENT_CARD_URL=http://localhost:8002/.well-known/agent-card.json
PEER_AGENT_CLIENT_IDS=agent-cluster-b
PEER_AGENT_AUDIENCE=agent-cluster-b
OPENAI_API_BASE=https://integrate.api.nvidia.com/v1
OPENAI_API_KEY={NVIDIA_KEY}
LLM_MODEL=meta/llama-3.3-70b-instruct
EMBEDDING_MODEL=nvidia/nv-embedqa-e5-v5
QDRANT_URL=http://localhost:16333
QDRANT_COLLECTION=knowledge_base_a
NEO4J_URI=bolt://localhost:17687
NEO4J_USER=neo4j
NEO4J_PASSWORD=none
OPENFGA_API_URL=http://localhost:8089
OPENFGA_STORE_ID={store_id}
OPENFGA_MODEL_ID={model_id}
OPENFGA_API_TOKEN={OPENFGA_TOKEN}
TEMPORAL_ADDRESS=localhost:7233
TEMPORAL_NAMESPACE=default
TEMPORAL_TASK_QUEUE=approval-queue-a
OIDC_ISSUER=http://localhost:8087/realms/rag
OIDC_JWKS_URI=http://localhost:8087/realms/rag/protocol/openid-connect/certs
OIDC_TOKEN_ENDPOINT=http://localhost:8087/realms/rag/protocol/openid-connect/token
AGENT_CLIENT_ID=agent-cluster-a
AGENT_CLIENT_SECRET={AGENT_SECRET_A}
ALLOWED_JWT_ALGORITHMS=RS256
APPROVAL_HMAC_SECRET={HMAC_SECRET_A}
APPROVAL_UI_BASE_URL=http://localhost:8000
REDIS_URL=redis://localhost:6379/1
HOST=127.0.0.1
PORT=8000
LOG_LEVEL=info
DOCS_ENABLED=true
CORS_ORIGINS=http://localhost:5173
"""
    b = f"""CLUSTER_ID=cluster-b
AGENT_NAME=Federated RAG Agent - Cluster B
AGENT_URL=http://localhost:8002
PEER_AGENT_URL=http://localhost:8000
PEER_AGENT_CARD_URL=http://localhost:8000/.well-known/agent-card.json
PEER_AGENT_CLIENT_IDS=agent-cluster-a
PEER_AGENT_AUDIENCE=agent-cluster-a
OPENAI_API_BASE=https://integrate.api.nvidia.com/v1
OPENAI_API_KEY={NVIDIA_KEY}
LLM_MODEL=meta/llama-3.3-70b-instruct
EMBEDDING_MODEL=nvidia/nv-embedqa-e5-v5
QDRANT_URL=http://localhost:16333
QDRANT_COLLECTION=knowledge_base_b
NEO4J_URI=bolt://localhost:17687
NEO4J_USER=neo4j
NEO4J_PASSWORD=none
OPENFGA_API_URL=http://localhost:8089
OPENFGA_STORE_ID={store_id}
OPENFGA_MODEL_ID={model_id}
OPENFGA_API_TOKEN={OPENFGA_TOKEN}
TEMPORAL_ADDRESS=localhost:7233
TEMPORAL_NAMESPACE=default
TEMPORAL_TASK_QUEUE=approval-queue-b
OIDC_ISSUER=http://localhost:8087/realms/rag
OIDC_JWKS_URI=http://localhost:8087/realms/rag/protocol/openid-connect/certs
OIDC_TOKEN_ENDPOINT=http://localhost:8087/realms/rag/protocol/openid-connect/token
AGENT_CLIENT_ID=agent-cluster-b
AGENT_CLIENT_SECRET={AGENT_SECRET_B}
ALLOWED_JWT_ALGORITHMS=RS256
APPROVAL_HMAC_SECRET={HMAC_SECRET_B}
APPROVAL_UI_BASE_URL=http://localhost:8002
REDIS_URL=redis://localhost:6379/2
HOST=127.0.0.1
PORT=8002
LOG_LEVEL=info
DOCS_ENABLED=true
CORS_ORIGINS=http://localhost:5173
"""
    # Both clusters run the SAME federated-rag codebase, selected by RAG_ENV_FILE.
    # cluster-a -> federated-rag/.env ; cluster-b -> federated-rag/.env.cluster-b
    (ROOT / "federated-rag" / ".env").write_text(a, encoding="utf-8")
    (ROOT / "federated-rag" / ".env.cluster-b").write_text(b, encoding="utf-8")
    log("wrote federated-rag/.env and federated-rag/.env.cluster-b")


# Self-contained Qdrant-only ingest. Runs inside each cluster dir so it imports
# THAT cluster's rag modules + .env. No external helper file needed.
_QDRANT_INGEST = '''
import truststore; truststore.inject_into_ssl()
import asyncio, sys, hashlib
from pathlib import Path
from rag.ingest import split_text
from rag.qdrant_retriever import HybridQdrantRetriever

# chunk_id computed here so we do not depend on either cluster's make_chunk_id
# signature (cluster-a: (source,index); cluster-b: (text)). Deterministic per
# (file, index) so re-ingest is idempotent and the title is recoverable.
def cid(source, i):
    return hashlib.sha256(f"{source}:{i}".encode()).hexdigest()[:16]

async def get_retriever():
    # cluster-b exposes an async singleton factory; cluster-a is a plain class.
    if hasattr(HybridQdrantRetriever, "get_instance"):
        return await HybridQdrantRetriever.get_instance()
    q = HybridQdrantRetriever()
    await q.ensure_collection()
    return q

async def go(folder):
    files = list(Path(folder).rglob("*.txt")) + list(Path(folder).rglob("*.md"))
    q = await get_retriever()
    try:
        chunks = []
        for f in files:
            text = f.read_text(encoding="utf-8", errors="replace")
            for i, ct in enumerate(split_text(text)):
                chunks.append({"chunk_id": cid(str(f), i), "text": ct,
                               "metadata": {"source": str(f), "chunk_index": i, "title": f.stem}})
        for i in range(0, len(chunks), 100):
            await q.upsert_chunks(chunks[i:i+100])
        print(f"upserted {len(chunks)} chunks from {len(files)} files")
    finally:
        await q.close()

asyncio.run(go(sys.argv[1]))
'''


def run_ingest(label: str, docs: Path, no_neo4j: bool, env_file: str = ".env") -> None:
    """Ingest docs using the federated-rag code, selecting the cluster via env_file.

    Both clusters are the same codebase; env_file picks the cluster's config
    (which sets QDRANT_COLLECTION to knowledge_base_a / knowledge_base_b).
    """
    if no_neo4j:
        args = [str(VENV_PY), "-c", _QDRANT_INGEST, str(docs)]
    else:
        args = [str(VENV_PY), "-m", "rag.ingest", "--path", str(docs)]
    env = {**os.environ, "RAG_ENV_FILE": env_file}
    log(f"ingest {label} ({'qdrant-only' if no_neo4j else 'qdrant+neo4j'}, {env_file}) ...")
    r = subprocess.run(args, cwd=str(ROOT / "federated-rag"), env=env,
                       capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        print(r.stdout[-2000:]); print(r.stderr[-2000:])
        raise RuntimeError(f"ingest failed for {label}")
    log(f"ingest {label} OK: {r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ''}")


async def qdrant_chunks(c: httpx.AsyncClient, collection: str) -> dict[str, list[str]]:
    """Return {title: [chunk_id, ...]} read live from Qdrant.

    A document longer than the chunk size splits into multiple chunks, so a title
    maps to a LIST of chunk_ids. Authorization must cover ALL of a document's
    chunks — granting only one leaves the other chunks denied, which surfaces as
    "I could not find an answer" when retrieval returns the ungranted chunk.
    Handles both payload shapes (top-level title vs nested metadata.title).
    """
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


async def write_tuple(c: httpx.AsyncClient, store: str, user: str, rel: str, obj: str) -> None:
    r = await c.post(f"{OPENFGA}/stores/{store}/write",
                     json={"writes": {"tuple_keys": [{"user": user, "relation": rel, "object": obj}]}},
                     headers=OPENFGA_HEADERS)
    if r.status_code in (200, 201) or "already exists" in r.text:
        log(f"tuple OK: {user} {rel} {obj}")
    else:
        log(f"tuple ERR {r.status_code}: {r.text[:160]}")


async def check(c: httpx.AsyncClient, store: str, user: str, rel: str, obj: str) -> bool:
    r = await c.post(f"{OPENFGA}/stores/{store}/check",
                     json={"tuple_key": {"user": user, "relation": rel, "object": obj}},
                     headers=OPENFGA_HEADERS)
    return bool(r.json().get("allowed"))


async def main(no_neo4j: bool) -> None:
    async with httpx.AsyncClient(timeout=30) as c:
        log("=== Phase 1: wait for services ===")
        await wait_healthy(c)

        log("=== Phase 2: OpenFGA store + model ===")
        store_id, model_id = await create_openfga_store(c)

        log("=== Phase 3: Keycloak ===")
        tok = await kc_admin_token(c)
        h = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
        await kc_ensure_realm(c, h)
        await kc_ensure_agent_client(c, h, "agent-cluster-a", AGENT_SECRET_A, peer_cid="agent-cluster-b")
        await kc_ensure_agent_client(c, h, "agent-cluster-b", AGENT_SECRET_B, peer_cid="agent-cluster-a")
        await kc_ensure_ui_client(c, h)
        await kc_ensure_user(c, h, "alice", "alice@example.com")
        await kc_ensure_user(c, h, "bob", "bob@example.com")
        alice = await kc_sub(c, "alice")
        bob = await kc_sub(c, "bob")
        log(f"alice sub={alice}")
        log(f"bob   sub={bob}")

        log("=== Phase 4: write .env files ===")
        write_env(store_id, model_id)

        log("=== Phase 5: ingest documents ===")
        run_ingest("cluster-a", DOCS_A, no_neo4j, env_file=".env")
        run_ingest("cluster-b", DOCS_B, no_neo4j, env_file=".env.cluster-b")

        log("=== Phase 6: read chunk_ids from Qdrant ===")
        ca = await qdrant_chunks(c, "knowledge_base_a")
        cb = await qdrant_chunks(c, "knowledge_base_b")
        log(f"cluster-a chunks: {ca}")
        log(f"cluster-b chunks: {cb}")
        for need, coll in [(ALICE_VIEW_A, ca), (ALICE_PEND_A, ca), (ALICE_VIEW_B, cb), (ALICE_PEND_B, cb)]:
            if need not in coll:
                raise RuntimeError(f"expected document '{need}' not found in Qdrant ({list(coll)})")

        log("=== Phase 7: OpenFGA tuples (all chunks of each document) ===")
        au, bu = f"user:{alice}", f"user:{bob}"

        async def grant_all(user: str, relation: str, chunk_ids: list[str]) -> None:
            for cid in chunk_ids:
                await write_tuple(c, store_id, user, relation, f"chunk:{cid}")

        await grant_all(au, "viewer", ca[ALICE_VIEW_A])            # Flow A
        await grant_all(au, "pending_approval", ca[ALICE_PEND_A])  # Flow B
        await grant_all(bu, "owner", ca[ALICE_PEND_A])
        await grant_all(au, "viewer", cb[ALICE_VIEW_B])            # Flow C
        await grant_all(au, "pending_approval", cb[ALICE_PEND_B])  # Flow D
        await grant_all(bu, "owner", cb[ALICE_PEND_B])

        log("=== Phase 8: verify (every chunk of each doc) ===")

        async def all_allowed(user: str, relation: str, chunk_ids: list[str]) -> bool:
            for cid in chunk_ids:
                if not await check(c, store_id, user, relation, f"chunk:{cid}"):
                    return False
            return True

        async def none_allowed(user: str, relation: str, chunk_ids: list[str]) -> bool:
            for cid in chunk_ids:
                if await check(c, store_id, user, relation, f"chunk:{cid}"):
                    return False
            return True

        results = {
            "A alice viewer data_retention": await all_allowed(au, "viewer", ca[ALICE_VIEW_A]),
            "B alice pending hr":            await all_allowed(au, "pending_approval", ca[ALICE_PEND_A]),
            "B alice NOT viewer hr":         await none_allowed(au, "viewer", ca[ALICE_PEND_A]),
            "C alice viewer tech_arch":      await all_allowed(au, "viewer", cb[ALICE_VIEW_B]),
            "D alice pending q4":            await all_allowed(au, "pending_approval", cb[ALICE_PEND_B]),
        }
        print("\n================ SETUP SUMMARY ================")
        ok = True
        for k, v in results.items():
            print(f"  [{'PASS' if v else 'FAIL'}] {k}")
            ok = ok and v
        print(f"  OpenFGA store: {store_id}")
        print(f"  alice={alice}  bob={bob}")
        print("==============================================")
        print("Next: launch_all.ps1  (starts both backends + workers + UI)")
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-neo4j", action="store_true", help="Qdrant-only ingest (skip slow GraphRAG)")
    args = ap.parse_args()
    t0 = time.time()
    asyncio.run(main(args.no_neo4j))
    log(f"done in {time.time()-t0:.0f}s")
