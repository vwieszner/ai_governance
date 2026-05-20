"""
Seed test data for all 4 authorization flows.

Run on EACH cluster after Keycloak + OpenFGA + Qdrant + Neo4j are up:

    # On Cluster A:
    python scripts/seed-test-data.py --cluster a

    # On Cluster B:
    python scripts/seed-test-data.py --cluster b

What this does:
  1. Ingests the test documents into Qdrant + Neo4j
  2. Sets up OpenFGA tuples so the 4 flows work correctly:

     Flow A — alice queries "data retention policy"
               → data on cluster A, alice has viewer access → answer returned

     Flow B — alice queries "employee salary bands"
               → data on cluster A, alice has NO access → approval workflow started

     Flow C — alice queries "platform technical architecture"
               → data on cluster B, alice has viewer access there → A2A call → answer

     Flow D — alice queries "Q4 financial results"
               → data on cluster B, alice has NO access there → cross-cluster approval

  3. Prints test curl commands for each flow
"""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

import httpx
import structlog

log = structlog.get_logger()

OPENFGA_URL = "http://localhost:8080"    # port-forward: kubectl port-forward svc/openfga 8080:8080
STORE_ID = ""                            # filled from env or --store-id arg

# Chunk IDs are derived deterministically from source+index during ingest.
# After ingestion, look them up with the helper below, or use the wildcard approach.
# For seeding we write object-level grants on the document source name.
# The actual chunk_ids are sha256(source:index)[:16] — we seed by source prefix.

DOCS_ROOT = Path(__file__).parent.parent / "tests" / "docs"


# ── OpenFGA helpers ────────────────────────────────────────────────────────────

async def write_tuple(
    client: httpx.AsyncClient,
    store_id: str,
    user: str,
    relation: str,
    object_: str,
) -> None:
    resp = await client.post(
        f"{OPENFGA_URL}/stores/{store_id}/write",
        json={
            "writes": {
                "tuple_keys": [{"user": user, "relation": relation, "object": object_}]
            }
        },
    )
    if resp.status_code not in (200, 204):
        # 400 with "already exists" is fine
        body = resp.json()
        if "already exists" not in str(body):
            log.warning("tuple_write_failed", status=resp.status_code, body=body)
    else:
        log.info("tuple_written", user=user, relation=relation, object=object_)


async def seed_openfga_cluster_a(client: httpx.AsyncClient, store_id: str) -> None:
    """
    Cluster A OpenFGA tuples:

    Flow A — alice can read data_retention_policy chunks
    Flow B — bob owns hr_compensation_data; alice has NO viewer tuple (triggers approval)
    """
    # Flow A: alice → viewer on policy doc chunks
    # We seed a group-level grant for simplicity; real ingest would use per-chunk IDs
    await write_tuple(client, store_id, "user:alice", "viewer", "chunk:pol-001-*")
    await write_tuple(client, store_id, "user:alice", "viewer", "chunk:data-retention-*")

    # Flow B: bob owns the HR doc; alice has no viewer tuple at all
    await write_tuple(client, store_id, "user:bob", "owner", "chunk:hr-conf-042-*")
    await write_tuple(client, store_id, "user:bob", "owner", "chunk:hr-compensation-*")
    # (alice intentionally has NO tuple → will trigger approval workflow)

    log.info("cluster_a_openfga_seeded")


async def seed_openfga_cluster_b(client: httpx.AsyncClient, store_id: str) -> None:
    """
    Cluster B OpenFGA tuples:

    Flow C — alice has viewer on technical_architecture chunks
    Flow D — carol owns q4_financial_results; alice has NO viewer tuple
    """
    # Flow C: alice → viewer on architecture doc
    await write_tuple(client, store_id, "user:alice", "viewer", "chunk:eng-arch-009-*")
    await write_tuple(client, store_id, "user:alice", "viewer", "chunk:technical-arch-*")

    # Flow D: carol owns the financials; alice has no viewer tuple
    await write_tuple(client, store_id, "user:carol", "owner", "chunk:fin-conf-2025-*")
    await write_tuple(client, store_id, "user:carol", "owner", "chunk:q4-financial-*")
    # (alice intentionally has NO tuple → will trigger cross-cluster approval)

    log.info("cluster_b_openfga_seeded")


# ── Ingest helpers ─────────────────────────────────────────────────────────────

async def ingest_docs(paths: list[Path]) -> None:
    """Run the ingest pipeline for a list of document paths."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from rag.ingest import ingest_documents
    await ingest_documents(paths)


# ── Main ───────────────────────────────────────────────────────────────────────

async def main(cluster: str, store_id: str) -> None:
    log.info("seeding_test_data", cluster=cluster)

    # 1. Ingest documents for this cluster
    doc_dir = DOCS_ROOT / f"cluster-{cluster}"
    doc_paths = list(doc_dir.glob("*.txt")) + list(doc_dir.glob("*.md"))
    if not doc_paths:
        log.error("no_docs_found", path=str(doc_dir))
        return

    log.info("ingesting_documents", count=len(doc_paths), paths=[p.name for p in doc_paths])
    await ingest_docs(doc_paths)

    # 2. Seed OpenFGA tuples
    async with httpx.AsyncClient() as client:
        if cluster == "a":
            await seed_openfga_cluster_a(client, store_id)
        else:
            await seed_openfga_cluster_b(client, store_id)

    # 3. Print test queries
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║  Test data seeded for Cluster {cluster.upper()}                                ║
╚══════════════════════════════════════════════════════════════════╝

Get alice's token first:
  TOKEN=$(curl -s -X POST http://localhost:8180/realms/rag/protocol/openid-connect/token \\
    -d 'grant_type=password&client_id=agent-cluster-{cluster}&client_secret=agent-client-secret-change-me&username=alice&password=alice123' \\
    | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

── Flow A: Local + Authorized ──────────────────────────────────────
(expects: immediate answer about data retention)

  curl -s -X POST http://localhost:8000/tasks/send \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{{"message": {{"role": "user", "parts": [{{"type": "text", "text": "What is our data retention policy for customer records?"}}]}}}}'

── Flow B: Local + Needs Approval ─────────────────────────────────
(expects: pending approval message, Slack notification to bob)

  curl -s -X POST http://localhost:8000/tasks/send \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{{"message": {{"role": "user", "parts": [{{"type": "text", "text": "What are the salary bands for senior engineers?"}}]}}}}'

── Flow C: Remote + Authorized ─────────────────────────────────────
(expects: answer about architecture fetched from cluster B via A2A)

  curl -s -X POST http://localhost:8000/tasks/send \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{{"message": {{"role": "user", "parts": [{{"type": "text", "text": "What Kubernetes version are we running and what is the cluster topology?"}}]}}}}'

── Flow D: Remote + Needs Approval ─────────────────────────────────
(expects: cross-cluster pending approval, notification to carol on cluster B)

  curl -s -X POST http://localhost:8000/tasks/send \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{{"message": {{"role": "user", "parts": [{{"type": "text", "text": "What was our Q4 revenue and ARR growth?"}}]}}}}'

── Approve a pending request ────────────────────────────────────────
(replace REQUEST_ID with the ID returned in the pending response)

  curl "http://localhost:8000/approve/REQUEST_ID?decision=approve"
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cluster", choices=["a", "b"], required=True)
    parser.add_argument("--store-id", default="", help="OpenFGA store ID (or set OPENFGA_STORE_ID in .env)")
    args = parser.parse_args()

    import os
    sid = args.store_id or os.getenv("OPENFGA_STORE_ID", "")
    if not sid:
        print("ERROR: provide --store-id or set OPENFGA_STORE_ID in .env")
        raise SystemExit(1)

    asyncio.run(main(args.cluster, sid))
