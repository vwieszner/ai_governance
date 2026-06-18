"""Durable, identity-bound per-user outcome inbox (FR-6.1 / 6.4).

The PRD's headline gap: when an approval resolves, the outcome must reach the
requester's ACCOUNT even if they are offline at that moment — surfaced on next
login, with NO short TTL and NO dependence on a browser tab / client poll loop.

This module is that durable destination. It is the requester-side analogue of
``approval_index`` (the OWNER-side pending inbox): a Redis hash keyed by the
requester's NAMESPACED principal (``email|issuer-ns`` — the SAME identity used by
/approvals, /tasks/{id}/result and OpenFGA, never the raw Keycloak ``sub``), one
field per outcome record.

Record shape (FR-6.1)::

    {
      "task_id":          str,   # the requester-side task to regenerate at delivery
      "question":         str,   # the original question, shown against the outcome
      "status":           str,   # "completed" | "denied" | "pending"
      "answer_or_message": str,  # denial/declined text; "" for completed (see below)
      "decided_at":       float, # epoch seconds the outcome was recorded
      "acknowledged":     bool,  # cleared by the requester via /inbox/{id}/ack
    }

FAIL-CLOSED / no stale data: a "completed" record deliberately stores NO answer.
The answer is (re)generated server-side through the full governed pipeline at
DELIVERY time (GET /inbox), so a revoked/expired grant between decision and login
cannot leak stale data (FR-6.2). The store records only that an answer is waiting
and the question to re-run — never the cleartext answer.

Retention (FR-6.4): records are retained for a LONG window (see
``OUTCOME_RETENTION_SECONDS``) — far longer than the approval window — and ideally
until acknowledged. This is a module constant, NOT a config field, by design: it is
a retention floor, not an operator knob, and adding a config field is out of scope
for this change. The TTL is (re)set on every write and on acknowledge, so an
inbox that keeps receiving outcomes never lapses.

Per-division by construction: each division's agent points at its OWN Redis
(``settings.redis_url``) and the key carries ``settings.division_id``, so a shared
Redis (if ever) can never cross a division boundary. For a cross-division approval
the outcome is written to the REQUESTER's HOME-division store by that division's
callback handler (FR-6.6) — see api/main.py::task_callback.
"""
from __future__ import annotations

import json
import time
from typing import Any

import structlog

from config import settings

log = structlog.get_logger(__name__)

# Retention floor for a waiting outcome (FR-6.4). 30 days — far longer than the
# default 24 h approval window — so "next login" can be days later and the outcome is
# still present. NOT a config field by design (a retention floor, not an operator knob).
# Refreshed on every write and on acknowledge so an active inbox never lapses; an
# acknowledged-and-then-abandoned record still ages out eventually rather than living
# forever. Redis is the durable store (AOF/RDB persistence survives restarts — NFR-5).
OUTCOME_RETENTION_SECONDS = 30 * 24 * 3600

_VALID_STATUSES = ("completed", "denied", "pending")

_redis: Any = None


async def _get_redis() -> Any:
    global _redis
    if _redis is None:
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


def _key(principal_id: str) -> str:
    """Inbox key — namespaced by division so a shared Redis can't cross divisions."""
    return f"outcome:inbox:{settings.division_id}:{principal_id}"


def _badge_key(principal_id: str) -> str:
    """In-app badge key (FR-6.5) — the count of unseen waiting outcomes for this user."""
    return f"outcome:badge:{settings.division_id}:{principal_id}"


async def put(
    principal_id: str,
    task_id: str,
    question: str,
    status: str,
    answer_or_message: str = "",
) -> None:
    """Write (or overwrite) a durable outcome record for ``principal_id``.

    Keyed by ``task_id`` as the field, so a redelivery for the same task (e.g. a
    Temporal activity retry) is idempotent — it overwrites, never duplicates. Raises
    on a store failure so the caller (a Temporal activity) can surface/retry it:
    silently dropping the outcome would defeat FR-6's durability guarantee. The
    retention TTL is (re)set on every write (FR-6.4).
    """
    if status not in _VALID_STATUSES:
        raise ValueError(f"invalid outcome status {status!r}; expected one of {_VALID_STATUSES}")
    # A "completed" outcome stores NO answer — the answer is regenerated at delivery
    # (FR-6.2). Only denial/declined/timeout text is persisted, capped to bound the record.
    stored_message = "" if status == "completed" else str(answer_or_message)[:1000]
    record = {
        "task_id": task_id,
        "question": str(question)[:1000],
        "status": status,
        "answer_or_message": stored_message,
        "decided_at": time.time(),
        "acknowledged": False,
    }
    r = await _get_redis()
    key = _key(principal_id)
    await r.hset(key, task_id, json.dumps(record))
    # Refresh the retention floor on the whole inbox so an active inbox never lapses.
    await r.expire(key, OUTCOME_RETENTION_SECONDS)
    log.info(
        "outcome_stored",
        principal=principal_id,
        task_id=task_id,
        status=status,
        division_id=settings.division_id,
        agt_audit=True,
    )


async def list_outcomes(principal_id: str, include_acknowledged: bool = False) -> list[dict]:
    """Return ``principal_id``'s waiting outcomes (newest first).

    Fail-soft: a Redis error returns [] (an unavailable store must not 500 the login
    inbox view; the durable records reappear when it recovers). By default only
    un-acknowledged records are returned — the next-login "what's waiting" view.
    """
    try:
        r = await _get_redis()
        raw = await r.hgetall(_key(principal_id))
    except Exception as exc:
        log.warning("outcome_list_failed", principal=principal_id, error=str(exc))
        return []
    out: list[dict] = []
    for v in raw.values():
        try:
            rec = json.loads(v)
        except Exception:
            continue
        if include_acknowledged or not rec.get("acknowledged"):
            out.append(rec)
    out.sort(key=lambda rec: rec.get("decided_at", 0), reverse=True)
    return out


async def get(principal_id: str, task_id: str) -> dict | None:
    """Return a single outcome record by task_id, or None if absent."""
    try:
        r = await _get_redis()
        raw = await r.hget(_key(principal_id), task_id)
    except Exception as exc:
        log.warning("outcome_get_failed", principal=principal_id, task_id=task_id, error=str(exc))
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


async def acknowledge(principal_id: str, task_id: str) -> bool:
    """Mark an outcome acknowledged (clears it from the default inbox view).

    Returns True if a record was found and updated, False otherwise. The record is
    retained (marked, not deleted) so the acknowledgement is itself durable and a
    double-ack is idempotent; the retention TTL is refreshed.
    """
    try:
        r = await _get_redis()
        key = _key(principal_id)
        raw = await r.hget(key, task_id)
        if not raw:
            return False
        rec = json.loads(raw)
        rec["acknowledged"] = True
        await r.hset(key, task_id, json.dumps(rec))
        await r.expire(key, OUTCOME_RETENTION_SECONDS)
    except Exception as exc:
        log.warning("outcome_ack_failed", principal=principal_id, task_id=task_id, error=str(exc))
        return False
    # Acknowledging clears one item from the unseen-badge count (FR-6.5). Best-effort.
    try:
        r = await _get_redis()
        bkey = _badge_key(principal_id)
        if int(await r.get(bkey) or 0) > 0:
            await r.decr(bkey)
    except Exception as exc:
        log.warning("outcome_badge_decr_failed", principal=principal_id, error=str(exc))
    log.info("outcome_acknowledged", principal=principal_id, task_id=task_id, agt_audit=True)
    return True


# ── In-app notification badge (FR-6.5) ─────────────────────────────────────────
# The out-of-band, in-app-channel-only notification: a per-user unseen-outcome count
# the SPA reads on next login (e.g. an inbox badge) so the requester learns an answer
# is waiting WITHOUT re-asking. No email/push (out of scope) — in-app only.


async def bump_badge(principal_id: str) -> None:
    """Increment the unseen-outcome badge for a user. Best-effort (never raises).

    Called when a NEW outcome lands so the next login shows "you have N waiting".
    Fail-soft: a badge is a convenience signal, not the durable outcome itself (which
    is the inbox record) — a Redis hiccup here must not fail the delivery.
    """
    try:
        r = await _get_redis()
        key = _badge_key(principal_id)
        await r.incr(key)
        await r.expire(key, OUTCOME_RETENTION_SECONDS)
    except Exception as exc:
        log.warning("outcome_badge_bump_failed", principal=principal_id, error=str(exc))


async def read_badge(principal_id: str) -> int:
    """Return the current unseen-outcome badge count (0 on absence/error).

    DERIVED from the durable records — the count of UNACKNOWLEDGED outcomes — NOT from the
    free-running ``bump_badge`` counter. The counter is bumped on park, on same-division
    resolution, and on each cross-division callback, while ``acknowledge`` decrements once,
    so a single outcome can be bumped several times and leave a phantom positive count with
    an empty inbox view. The records are the source of truth (list_outcomes already filters
    to unacknowledged), so the badge is exactly the number of items the user would see on
    next login. Fail-soft: 0 on a store error.
    """
    try:
        return len(await list_outcomes(principal_id))
    except Exception as exc:
        log.warning("outcome_badge_read_failed", principal=principal_id, error=str(exc))
        return 0
