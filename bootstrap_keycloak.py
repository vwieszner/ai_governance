"""
Bootstrap Keycloak for the real federated-rag demo (local Docker instance).

Targets the running container http://localhost:8087 (admin/admin) and creates:
  - realm 'rag'
  - confidential clients agent-cluster-a / agent-cluster-b (service accounts +
    direct-access + RFC 8693 token exchange) with fixed secrets
  - public client 'rag-ui' for the browser password-grant login
  - users alice and bob (password: demo)

Run with the project venv:
    .venv\\Scripts\\python.exe bootstrap_keycloak.py
"""
from __future__ import annotations

import asyncio
import sys

import httpx

KC = "http://localhost:8087"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
REALM = "rag"

AGENT_SECRET_A = "agent-cluster-a-secret"
AGENT_SECRET_B = "agent-cluster-b-secret"


async def admin_token(c: httpx.AsyncClient) -> str:
    r = await c.post(
        f"{KC}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
        },
    )
    r.raise_for_status()
    return r.json()["access_token"]


async def ensure_realm(c: httpx.AsyncClient, h: dict) -> None:
    r = await c.post(
        f"{KC}/admin/realms",
        json={"realm": REALM, "enabled": True, "displayName": "Federated RAG"},
        headers=h,
    )
    if r.status_code == 409:
        print(f"realm '{REALM}' already exists")
    else:
        r.raise_for_status()
        print(f"OK realm '{REALM}' created")


async def ensure_agent_client(c: httpx.AsyncClient, h: dict, client_id: str, secret: str) -> None:
    body = {
        "clientId": client_id,
        "enabled": True,
        "publicClient": False,
        "secret": secret,
        "standardFlowEnabled": False,
        "serviceAccountsEnabled": True,
        "directAccessGrantsEnabled": True,
        "attributes": {"oauth2.token.exchange.grant.enabled": "true"},
    }
    r = await c.post(f"{KC}/admin/realms/{REALM}/clients", json=body, headers=h)
    if r.status_code == 409:
        print(f"client '{client_id}' already exists")
    else:
        r.raise_for_status()
        print(f"OK client '{client_id}' created (secret={secret})")


async def ensure_ui_client(c: httpx.AsyncClient, h: dict) -> None:
    body = {
        "clientId": "rag-ui",
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "redirectUris": ["http://localhost:5173/*"],
        "webOrigins": ["http://localhost:5173"],
    }
    r = await c.post(f"{KC}/admin/realms/{REALM}/clients", json=body, headers=h)
    if r.status_code == 409:
        print("client 'rag-ui' already exists")
    else:
        r.raise_for_status()
        print("OK client 'rag-ui' created (public)")


async def ensure_user(c: httpx.AsyncClient, h: dict, username: str, email: str) -> None:
    body = {
        "username": username,
        "enabled": True,
        "email": email,
        "firstName": username.capitalize(),
        "lastName": "Demo",
        "emailVerified": True,
        "credentials": [{"type": "password", "value": "demo", "temporary": False}],
    }
    r = await c.post(f"{KC}/admin/realms/{REALM}/users", json=body, headers=h)
    if r.status_code == 409:
        print(f"user '{username}' already exists")
    else:
        r.raise_for_status()
        print(f"OK user '{username}' created (password: demo)")


async def main() -> None:
    async with httpx.AsyncClient(timeout=20) as c:
        tok = await admin_token(c)
        h = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
        await ensure_realm(c, h)
        await ensure_agent_client(c, h, "agent-cluster-a", AGENT_SECRET_A)
        await ensure_agent_client(c, h, "agent-cluster-b", AGENT_SECRET_B)
        await ensure_ui_client(c, h)
        await ensure_user(c, h, "alice", "alice@example.com")
        await ensure_user(c, h, "bob", "bob@example.com")
        print("\nKeycloak bootstrap complete.")
        print(f"OIDC_ISSUER={KC}/realms/{REALM}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except httpx.HTTPStatusError as e:
        print(f"HTTP {e.response.status_code}: {e.response.text}", file=sys.stderr)
        raise
