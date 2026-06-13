"""Connector contract + generic ingest engine (Phase-1 item 10).

A Connector exposes two async generators:

    chunks()  -> DocumentChunk   # retrievable content (text + metadata, stable chunk_id)
    grants()  -> AccessGrant     # the source's permissions, mapped to OpenFGA relations

The generic :func:`ingest` engine upserts the chunks into Qdrant and writes the grants into
OpenFGA. Because emitting grants is part of the interface, a connector cannot land content
without also declaring who may see it — the per-chunk authorization model is preserved by
construction. Connectors for sources that can't enforce per-user themselves use the
ACL-mirroring pattern: a service account reads everything, and grants() maps the source's
(usually group-based) permissions to `group#member viewer` tuples, which the agent then
filters per-user at query time.

This module has NO source-specific logic; folder.py is the reference implementation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Protocol, runtime_checkable

import structlog

log = structlog.get_logger(__name__)


@dataclass
class DocumentChunk:
    chunk_id: str                 # STABLE id (re-ingest must reproduce it) — keys the tuples
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)   # source, title, chunk_index, …


@dataclass
class AccessGrant:
    """One ACL fact mapped from the source. `subject_kind` selects the OpenFGA relation:
      - 'user'  : a direct user grant            -> user:<subject> <relation> chunk:<id>
      - 'group' : a group userset grant          -> group:<subject>#member viewer chunk:<id>
    `relation` is one of viewer | owner | pending_approval (group only supports viewer).
    Target is by chunk_id, or by doc title (resolved against the connector's chunks)."""
    subject: str
    relation: str = "viewer"
    subject_kind: str = "user"             # "user" | "group"
    chunk_id: str | None = None
    doc_title: str | None = None


@runtime_checkable
class Connector(Protocol):
    name: str
    async def chunks(self) -> AsyncIterator[DocumentChunk]: ...
    async def grants(self) -> AsyncIterator[AccessGrant]: ...


async def _acollect(agen) -> list:
    return [x async for x in agen]


async def ingest(connector: Connector, qdrant: Any, openfga: Any, *, batch: int = 100) -> dict:
    """Run a connector: upsert its chunks to Qdrant and write its grants to OpenFGA.

    Returns a summary {chunks, grants}. Grants targeting a doc_title fan out to every
    chunk of that title. Idempotent at the tuple level (the openfga helpers swallow
    'already exists'); chunk ids are stable so re-ingest overwrites in place.
    """
    chunks = await _acollect(connector.chunks())
    title_to_ids: dict[str, list[str]] = {}
    for c in chunks:
        t = c.metadata.get("title")
        if t:
            title_to_ids.setdefault(t, []).append(c.chunk_id)

    # Upsert content in batches (dict shape matches HybridQdrantRetriever.upsert_chunks).
    payload = [{"chunk_id": c.chunk_id, "text": c.text, "metadata": c.metadata} for c in chunks]
    for i in range(0, len(payload), batch):
        await qdrant.upsert_chunks(payload[i:i + batch])

    # Write ACL grants.
    n_grants = 0
    for g in await _acollect(connector.grants()):
        targets = [g.chunk_id] if g.chunk_id else title_to_ids.get(g.doc_title or "", [])
        for cid in targets:
            if g.subject_kind == "group":
                await openfga.grant_group_viewer(g.subject, cid)        # group viewer only
            elif g.relation == "owner":
                await openfga._write_tuple(g.subject, cid, _rel("owner"))
            elif g.relation == "pending_approval":
                await openfga.set_pending_approval(g.subject, cid)
            else:
                await openfga.grant_viewer(g.subject, cid)
            n_grants += 1

    log.info("connector_ingested", connector=connector.name, chunks=len(chunks), grants=n_grants)
    return {"chunks": len(chunks), "grants": n_grants}


def _rel(name: str):
    from auth.openfga import Relation
    return Relation(name)
