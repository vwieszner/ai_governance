"""Pluggable, multi-retriever layer — fan out across N retrievers, RRF-fused.

WHY THIS EXISTS
    The agent must not be welded to one vector store. This module defines a small
    uniform retriever interface and a config-driven registry so a division can run
    Qdrant, the Neo4j seam, and/or any number of external retrieval-as-a-service
    (RaaS) backends together, fused by Reciprocal Rank Fusion (rag/fusion.py).

GOVERNANCE CONTRACT (Pattern A — the load-bearing rule)
    A retriever only FINDS candidate chunks. It is NEVER trusted to filter by user.
    Every retriever returns chunks with STABLE ``chunk_id``s that key this
    division's OpenFGA per-chunk tuples, and the agent's ``check_auth`` node decides
    each returned chunk_id against OpenFGA (deny-by-default, 3-way). Consequently
    adding retrievers — including external ones — can never widen what a user sees;
    the per-chunk ReBAC guarantee holds no matter how many backends are configured.

    To onboard a source's permissions, mirror its ACLs into OpenFGA via the
    connector SDK (connectors/base.py: chunks() + grants()). A RaaS that returns
    chunk_ids absent from OpenFGA simply yields nothing authorized — fail-closed.

RESIDENCY
    An external RaaS endpoint is refused when ``residency_mode == "local"`` (the
    query text may echo authorized context and must stay in-boundary), reusing the
    M6 guard (residency.assert_inference_allowed).

The result-dict shape every retriever emits matches HybridQdrantRetriever.retrieve:
    {"chunk_id": str, "text": str, "metadata": dict, "score": float}
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

import structlog

from config import RaasEndpoint, settings
# Egress-safety SSRF denylist (A2-SSRF): moved verbatim to rag/egress_guard.py (dependency-free,
# so transport/ocsp.py can reuse it without importing config); re-exported under the old names.
from rag.egress_guard import METADATA_HOSTNAMES as _METADATA_HOSTNAMES  # noqa: F401
from rag.egress_guard import is_egress_unsafe_host as _is_egress_unsafe_raas_host

log = structlog.get_logger(__name__)


@runtime_checkable
class Retriever(Protocol):
    """Uniform query-side retriever. Implementations FIND chunks; they do not authorize."""

    name: str
    # TRUST CLASS (content-integrity / A2d): a ``trusted`` retriever is THIS division's
    # store of record (built-in qdrant/neo4j) — the authoritative source for the TEXT
    # served into the LLM context. ``trusted=False`` (HttpRetriever / external RaaS) means
    # the backend may contribute candidate chunk_ids + ranking ONLY; its text is NEVER
    # used. check_auth re-sources served text from a trusted backend so a compromised RaaS
    # cannot poison the content of an authorized chunk.
    trusted: bool

    async def setup(self) -> None:
        """One-time initialisation (collection/index/egress check). Idempotent."""
        ...

    async def retrieve(
        self,
        query: str,
        allowed_chunk_ids: list[str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return ranked candidate chunks (chunk_id, text, metadata, score)."""
        ...


class _QdrantBackend:
    """Built-in: the hybrid dense+sparse Qdrant retriever — this division's store of record."""

    name = "qdrant"
    trusted = True   # store of record: authoritative for served chunk TEXT (A2d)

    def __init__(self) -> None:
        from rag.qdrant_retriever import HybridQdrantRetriever

        self._r = HybridQdrantRetriever()

    async def setup(self) -> None:
        await self._r.ensure_collection()

    async def retrieve(
        self, query: str, allowed_chunk_ids: list[str] | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
        return await self._r.retrieve(query, allowed_chunk_ids=allowed_chunk_ids, limit=limit)

    async def fetch_by_chunk_ids(self, chunk_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Trusted text/metadata for specific chunk_ids (content-integrity re-sourcing)."""
        return await self._r.fetch_by_chunk_ids(chunk_ids)


class _Neo4jBackend:
    """Built-in: the Neo4j graph-retrieval seam (inert until a Neo4j ingest exists)."""

    name = "neo4j"
    trusted = True   # built-in store of record (inert seam, but in-boundary if populated)

    def __init__(self) -> None:
        from rag.neo4j_retriever import GraphRAGRetriever

        self._r = GraphRAGRetriever()

    async def setup(self) -> None:
        await self._r._ensure_init()

    async def retrieve(
        self, query: str, allowed_chunk_ids: list[str] | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
        # The graph seam does plain vector lookup and ignores the ACL pre-filter;
        # check_auth authorizes every returned chunk_id downstream.
        return await self._r.retrieve_context(query)


class HttpRetriever:
    """External retrieval-as-a-service adapter.

    POSTs ``{"query", "top_k", "allowed_chunk_ids"?}`` to ``<url>/retrieve`` and maps
    the JSON response (``{"results": [{chunk_id, text, metadata, score}, ...]}`` or a
    bare list) to the uniform chunk shape. A failing/slow RaaS DEGRADES to an empty
    list rather than breaking the query — the other configured retrievers still serve.

    EXTERNAL / UNTRUSTED (A2d): ``trusted = False``. This adapter may contribute candidate
    chunk_ids + ranking, but the TEXT it returns is NEVER served into the LLM context —
    check_auth re-sources served text from a trusted (store-of-record) backend. So even a
    compromised RaaS that returns an authorized chunk_id cannot poison its content.
    """

    trusted = False

    def __init__(self, endpoint: RaasEndpoint) -> None:
        self.name = endpoint.name
        self._url = endpoint.url.rstrip("/")
        self._api_key = endpoint.api_key
        self._top_k = endpoint.top_k

    async def setup(self) -> None:
        # SSRF denylist (A2-SSRF): refuse cloud-metadata / link-local / loopback targets
        # for a RaaS endpoint REGARDLESS of residency_mode. The default external mode
        # disables the residency guard below, so this is the only thing stopping a RaaS
        # URL pointing at 169.254.169.254 (cloud metadata) from being contacted.
        if _is_egress_unsafe_raas_host(self._url):
            host = urlparse(self._url).hostname or self._url
            raise RuntimeError(
                f"refusing RaaS endpoint {self.name!r}: host {host!r} is a cloud-metadata / "
                f"link-local / loopback address and is never a valid retrieval target (SSRF)."
            )
        # Fail closed if local residency would egress the query to an external service.
        from residency import assert_inference_allowed

        assert_inference_allowed(self._url, f"retrieval[{self.name}]")

    async def retrieve(
        self, query: str, allowed_chunk_ids: list[str] | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
        import httpx

        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        body: dict[str, Any] = {"query": query, "top_k": limit or self._top_k}
        if allowed_chunk_ids is not None:
            body["allowed_chunk_ids"] = allowed_chunk_ids
        try:
            async with httpx.AsyncClient(timeout=settings.raas_timeout_seconds) as client:
                resp = await client.post(f"{self._url}/retrieve", json=body, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001 — degrade, never crash the query
            log.warning("raas_retrieve_failed", name=self.name, error=str(exc))
            return []

        raw = data.get("results", data) if isinstance(data, dict) else data
        out: list[dict[str, Any]] = []
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict):
                continue
            cid = item.get("chunk_id")
            if not cid:
                continue  # no stable id => unauthorizable => drop (fail-closed)
            out.append(
                {
                    "chunk_id": cid,
                    "text": item.get("text", ""),
                    "metadata": item.get("metadata", {}) or {},
                    "score": float(item.get("score", 0.0) or 0.0),
                }
            )
        log.debug("raas_retrieve_done", name=self.name, returned=len(out))
        return out


async def fetch_trusted_text(
    retrievers: list[Retriever], chunk_ids: list[str]
) -> dict[str, dict[str, Any]]:
    """Re-source the authoritative TEXT/metadata for ``chunk_ids`` from the TRUSTED
    store-of-record retrievers only (content-integrity / A2d).

    Only ``trusted`` backends that expose ``fetch_by_chunk_ids`` (the built-in qdrant
    store) contribute. External retrievers (HttpRetriever, ``trusted=False``) are never
    consulted for text. The returned ``{chunk_id: {text, metadata}}`` covers only ids the
    trusted store actually holds; a chunk_id surfaced ONLY by an external RaaS is absent,
    so its attacker-controlled text is excluded from the served context (fail-closed).
    """
    if not chunk_ids:
        return {}
    merged: dict[str, dict[str, Any]] = {}
    for r in retrievers:
        if not getattr(r, "trusted", False):
            continue
        fetch = getattr(r, "fetch_by_chunk_ids", None)
        if fetch is None:
            continue
        try:
            found = await fetch(chunk_ids)
        except Exception as exc:  # noqa: BLE001 — a trusted-store hiccup must fail closed, not poison
            log.warning("trusted_text_fetch_failed", retriever=getattr(r, "name", "?"), error=str(exc))
            continue
        # First trusted backend that holds an id wins (store-of-record precedence).
        for cid, payload in found.items():
            merged.setdefault(cid, payload)
    return merged


_BUILTINS: dict[str, type] = {"qdrant": _QdrantBackend, "neo4j": _Neo4jBackend}


def build_retrievers() -> list[Retriever]:
    """Instantiate the configured retrievers: built-ins (``settings.retriever_backends``)
    then each external RaaS (``settings.raas_endpoints``). Order affects only RRF
    tie-breaking; results are fused, never short-circuited."""
    retrievers: list[Retriever] = []
    for name in settings.retriever_backends:
        factory = _BUILTINS.get(name)
        if factory is None:
            log.warning("unknown_retriever_backend", name=name, known=list(_BUILTINS))
            continue
        retrievers.append(factory())
    for ep in settings.raas_endpoints:
        retrievers.append(HttpRetriever(ep))
    if not retrievers:
        log.warning("no_retrievers_configured")
    log.info("retrievers_built", names=[r.name for r in retrievers])
    return retrievers
