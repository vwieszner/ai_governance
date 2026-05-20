"""
Bootstrap Keycloak: create realm, users, and agent client with RFC 8693 token exchange.

Run once per cluster after Keycloak is up:
    python scripts/setup-keycloak.py

Port-forward first:
    kubectl port-forward svc/keycloak 8180:80 -n federated-rag
"""
from __future__ import annotations

import asyncio
import httpx

KEYCLOAK_URL = "http://localhost:8180"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "change-me-in-production"
REALM = "rag"
CLUSTER_ID = "cluster-a"          # change to cluster-b on the other cluster
PEER_AGENT_URL = "https://agent-b.your-domain.com"


async def get_admin_token(client: httpx.AsyncClient) -> str:
    resp = await client.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


async def setup() -> None:
    async with httpx.AsyncClient() as client:
        token = await get_admin_token(client)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # 1. Create realm
        resp = await client.post(
            f"{KEYCLOAK_URL}/admin/realms",
            json={"realm": REALM, "enabled": True, "displayName": "RAG System"},
            headers=headers,
        )
        if resp.status_code == 409:
            print(f"Realm '{REALM}' already exists, skipping.")
        else:
            resp.raise_for_status()
            print(f"✓ Realm '{REALM}' created")

        # 2. Create agent client (for RFC 8693 token exchange)
        agent_client = {
            "clientId": f"agent-{CLUSTER_ID}",
            "enabled": True,
            "publicClient": False,
            "secret": "agent-client-secret-change-me",
            "standardFlowEnabled": False,
            "serviceAccountsEnabled": True,          # client_credentials grant
            "directAccessGrantsEnabled": False,
            "attributes": {
                "oauth2.token.exchange.grant.enabled": "true",   # RFC 8693
            },
        }
        resp = await client.post(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
            json=agent_client,
            headers=headers,
        )
        if resp.status_code == 409:
            print(f"Agent client already exists, skipping.")
        else:
            resp.raise_for_status()
            print(f"✓ Agent client 'agent-{CLUSTER_ID}' created")

        # 3. Create a test user
        test_user = {
            "username": "alice",
            "enabled": True,
            "email": "alice@example.com",
            "firstName": "Alice",
            "lastName": "Test",
            "credentials": [{"type": "password", "value": "alice123", "temporary": False}],
        }
        resp = await client.post(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
            json=test_user,
            headers=headers,
        )
        if resp.status_code == 409:
            print("User 'alice' already exists, skipping.")
        else:
            resp.raise_for_status()
            print("✓ Test user 'alice' created (password: alice123)")

        print(f"""
Setup complete. Add to your .env / ConfigMap:

OIDC_ISSUER={KEYCLOAK_URL}/realms/{REALM}
OIDC_JWKS_URI={KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs
OIDC_TOKEN_ENDPOINT={KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token
AGENT_CLIENT_ID=agent-{CLUSTER_ID}
AGENT_CLIENT_SECRET=agent-client-secret-change-me

To get a user token for testing:
  curl -X POST {KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token \\
    -d 'grant_type=password&client_id=agent-{CLUSTER_ID}&client_secret=agent-client-secret-change-me&username=alice&password=alice123'
""")


if __name__ == "__main__":
    asyncio.run(setup())
