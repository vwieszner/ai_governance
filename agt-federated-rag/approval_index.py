"""Redis-backed approval inbox index.

The authenticated approver inbox (/approvals/pending) originally enumerated Temporal
workflows via `list_workflows(... ExecutionStatus='Running')`. On Temporal's bundled
`start-dev` server that advanced-visibility query is eventually-consistent (SQLite) and
also O(open requests) — so the inbox lagged or stalled under load. This index records each
pending request in Redis when the approval workflow starts and removes it on decision, so
the inbox is a fast, consistent point read keyed by the approver's namespaced principal.
Temporal remains the source of truth for the DECISION (the index is just the inbox view).

Per-division by construction: each division's agent points at its OWN Redis (settings.redis_url).
"""
from __future__ import annotations

import json
from typing import Any

import structlog

from config import settings

log = structlog.get_logger(__name__)

_redis: Any = None


async def _get_redis() -> Any:
    global _redis
    if _redis is None:
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


def _key(approver: str) -> str:
    # namespaced by division so a shared Redis (if ever) can't cross divisions
    return f"approvals:pending:{settings.division_id}:{approver}"


async def record(approver: str, request_id: str, requester_id: str, query: str,
                 sources: list[str] | None = None) -> None:
    """Add a pending request to the approver's inbox set (called from start_approval).

    ``sources`` are the contributing source NAMES / labels (never content) the approver is
    shown — for a mosaic clearance, the local documents and peer divisions + labels whose
    combination needs approval. Bounded so a pathological list can't bloat the index."""
    try:
        r = await _get_redis()
        payload = json.dumps({"request_id": request_id, "requester_id": requester_id,
                              "query": query[:500],
                              "sources": [str(s)[:300] for s in (sources or [])[:20]]})
        await r.hset(_key(approver), request_id, payload)
        # bound the lifetime so an abandoned entry can't linger forever
        await r.expire(_key(approver), settings.approval_timeout_seconds + 3600)
    except Exception as exc:  # inbox indexing must never break the approval workflow start
        log.warning("approval_index_record_failed", error=str(exc))


async def list_for(approver: str) -> list[dict]:
    """Pending requests this approver may decide — fast point read, no Temporal scan."""
    try:
        r = await _get_redis()
        raw = await r.hgetall(_key(approver))
    except Exception as exc:
        log.warning("approval_index_list_failed", error=str(exc))
        return []
    out = []
    for v in raw.values():
        try:
            out.append(json.loads(v))
        except Exception:
            continue
    return out


async def remove(approver: str, request_id: str) -> None:
    """Drop a request from the inbox once decided (approve/deny)."""
    try:
        r = await _get_redis()
        await r.hdel(_key(approver), request_id)
    except Exception as exc:
        log.warning("approval_index_remove_failed", error=str(exc))


async def by_requester(requester: str) -> list[tuple[str, str]]:
    """FR-2.2 disable cascade: every pending ``(approver, request_id)`` in THIS division
    whose requester is ``requester``. A SCAN over this division's inbox keys — an admin
    operation (rare), never on the request path. Raises on a store error so the caller
    can report the cascade as incomplete rather than silently skipping it."""
    r = await _get_redis()
    prefix = f"approvals:pending:{settings.division_id}:"
    out: list[tuple[str, str]] = []
    async for key in r.scan_iter(match=f"{prefix}*"):
        approver = key[len(prefix):]
        for rid, v in (await r.hgetall(key)).items():
            try:
                if json.loads(v).get("requester_id") == requester:
                    out.append((approver, rid))
            except Exception:
                continue
    return out


async def count_for(approver: str) -> int:
    """How many requests currently await ``approver`` (0 on a store error)."""
    try:
        r = await _get_redis()
        return int(await r.hlen(_key(approver)))
    except Exception as exc:
        log.warning("approval_index_count_failed", error=str(exc))
        return 0
