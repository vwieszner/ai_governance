"""
Bootstrap OpenFGA: create the store + authorization model.

Run once per cluster:
    python scripts/setup-openfga.py

Writes OPENFGA_STORE_ID and OPENFGA_MODEL_ID to stdout.
Update your ConfigMap / Secret with these values.
"""
from __future__ import annotations

import asyncio
import json

import httpx

OPENFGA_URL = "http://localhost:8080"   # port-forward: kubectl port-forward svc/openfga 8080:8080

AUTH_MODEL = {
    "schema_version": "1.1",
    "type_definitions": [
        {"type": "user"},
        {
            "type": "group",
            "relations": {
                "member": {
                    "this": {},
                    "metadata": {"relation": "member", "directly_related_user_types": [{"type": "user"}]},
                }
            },
            "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}},
        },
        {
            "type": "chunk",
            "relations": {
                "owner": {
                    "this": {},
                    "metadata": {
                        "directly_related_user_types": [
                            {"type": "user"},
                            {"type": "group", "relation": "member"},
                        ]
                    },
                },
                "editor": {
                    "union": {
                        "child": [
                            {"this": {}},
                            {"computedUserset": {"object": "", "relation": "owner"}},
                        ]
                    },
                    "metadata": {
                        "directly_related_user_types": [
                            {"type": "user"},
                            {"type": "group", "relation": "member"},
                        ]
                    },
                },
                "viewer": {
                    "union": {
                        "child": [
                            {"this": {}},
                            {"computedUserset": {"object": "", "relation": "editor"}},
                        ]
                    },
                    "metadata": {
                        "directly_related_user_types": [
                            {"type": "user"},
                            {"type": "group", "relation": "member"},
                        ]
                    },
                },
                "pending_approval": {
                    "this": {},
                    "metadata": {"directly_related_user_types": [{"type": "user"}]},
                },
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


async def setup() -> None:
    async with httpx.AsyncClient(base_url=OPENFGA_URL) as client:
        # Create store
        resp = await client.post("/stores", json={"name": "federated-rag"})
        resp.raise_for_status()
        store_id = resp.json()["id"]
        print(f"OPENFGA_STORE_ID={store_id}")

        # Write authorization model
        resp = await client.post(
            f"/stores/{store_id}/authorization-models",
            json=AUTH_MODEL,
        )
        resp.raise_for_status()
        model_id = resp.json()["authorization_model_id"]
        print(f"OPENFGA_MODEL_ID={model_id}")

        print("\nAdd these to your ConfigMap/Secret, then restart the agent deployment.")


if __name__ == "__main__":
    asyncio.run(setup())
