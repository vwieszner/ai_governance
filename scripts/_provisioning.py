"""Shared provisioning constants/helpers (IMPLEMENTATION_PLAN.md M0, quality B-1).

setup_agt.py (the single-host AGT setup) and scripts/onboard_division.py (the
multi-division onboarding generator) previously each carried a BYTE-IDENTICAL copy
of the OpenFGA authorization model, the Qdrant ingest snippet, and the root-.env
loader. A divergent edit to one (e.g. the ReBAC schema) would silently desync the
two — an authorization-drift hazard. They now both import from here, so there is a
single source of truth.

Deliberately NOT shared: the Keycloak audience-mapper helpers. setup_agt's
kc_ensure_ui_client adds BOTH agent audiences (the dual mapper that IS AUD-1, which
M1 removes); onboard's _kc_add_ui_audience adds a SINGLE division audience (the
correct post-AUD-1 shape). That difference is security-load-bearing and must stay
per-caller.
"""
from __future__ import annotations

from pathlib import Path

# OpenFGA per-chunk ReBAC authorization model. Single source of truth — both the
# single-host setup and the per-division onboarding create their store from this,
# so every division's ReBAC schema is provably identical.
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
                    # M5/FR-7.1: a viewer grant may be UNCONDITIONED (permanent) OR carry
                    # the non_expired condition (a time-bound grant). OpenFGA stops
                    # treating a conditioned tuple as granting access once current_time
                    # >= expiry — expiry is enforced at check time, no sweeper needed.
                    "viewer": {"directly_related_user_types": [
                        {"type": "user"},
                        {"type": "user", "condition": "non_expired"},
                    ]},
                    "pending_approval": {"directly_related_user_types": [{"type": "user"}]},
                }
            },
        },
    ],
    # M5/FR-7.1: time-bound access. grant_viewer_until() writes a viewer tuple with this
    # condition + an `expiry`; check() passes `current_time`, so OpenFGA evaluates
    # current_time < expiry per request. Unconditioned viewer tuples ignore the context.
    "conditions": {
        "non_expired": {
            "name": "non_expired",
            "expression": "current_time < expiry",
            "parameters": {
                "current_time": {"type_name": "TYPE_NAME_TIMESTAMP"},
                "expiry": {"type_name": "TYPE_NAME_TIMESTAMP"},
            },
        },
    },
}

# Qdrant-only ingest, run as a subprocess with RAG_ENV_FILE pointing at the target
# agent env (so it targets that cluster's/division's own Qdrant). argv[1] = docs dir.
QDRANT_INGEST_SNIPPET = '''
import truststore; truststore.inject_into_ssl()
import asyncio, sys, hashlib
from pathlib import Path
from rag.ingest import split_text
from rag.qdrant_retriever import HybridQdrantRetriever
def cid(src,i): return hashlib.sha256(f"{src}:{i}".encode()).hexdigest()[:16]
async def get_ret():
    if hasattr(HybridQdrantRetriever,"get_instance"): return await HybridQdrantRetriever.get_instance()
    q=HybridQdrantRetriever(); await q.ensure_collection(); return q
async def go(folder):
    files=list(Path(folder).rglob("*.txt"))+list(Path(folder).rglob("*.md"))
    q=await get_ret()
    try:
        chunks=[]
        for f in files:
            for i,ct in enumerate(split_text(f.read_text(encoding="utf-8",errors="replace"))):
                chunks.append({"chunk_id":cid(str(f),i),"text":ct,"metadata":{"source":str(f),"chunk_index":i,"title":f.stem}})
        for i in range(0,len(chunks),100): await q.upsert_chunks(chunks[i:i+100])
        print(f"upserted {len(chunks)} chunks from {len(files)} files")
    finally:
        await q.close()
asyncio.run(go(sys.argv[1]))
'''


def load_root_env(root: Path) -> dict[str, str]:
    """Parse the gitignored root .env (KEY=VALUE lines) into a dict."""
    env: dict[str, str] = {}
    p = root / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env
