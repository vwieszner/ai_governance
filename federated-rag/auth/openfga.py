"""
OpenFGA client — per-chunk ReBAC authorization.

Authorization model (write once at startup):
  type user
  type group
    relations
      define member: [user]
  type chunk
    relations
      define owner:            [user, group#member]
      define editor:           [user, group#member] or owner
      define viewer:           [user, group#member] or editor
      define pending_approval: [user]              # approval in-flight
"""
from __future__ import annotations

import asyncio
from enum import Enum
from typing import Any

import structlog
from openfga_sdk import (
    ClientConfiguration,
    OpenFgaClient,
)
from openfga_sdk.client.models import (
    ClientCheckRequest,
    ClientReadRequest,
    ClientTupleKey,
    ClientWriteRequest,
)

from config import settings

log = structlog.get_logger(__name__)


class Relation(str, Enum):
    VIEWER = "viewer"
    EDITOR = "editor"
    OWNER = "owner"
    PENDING_APPROVAL = "pending_approval"


class AuthzDecision(str, Enum):
    ALLOWED = "allowed"
    NEEDS_APPROVAL = "needs_approval"
    DENIED = "denied"


class OpenFGAAuth:
    """Async wrapper around the OpenFGA SDK."""

    def __init__(self) -> None:
        self._client: OpenFgaClient | None = None
        # S-11: lock prevents check-then-set race when multiple coroutines
        # call _get_client() simultaneously at cold-start.
        self._lock: asyncio.Lock = asyncio.Lock()

    async def _get_client(self) -> OpenFgaClient:
        # Fast path — no lock needed once initialised
        if self._client is not None:
            return self._client
        async with self._lock:
            # Double-check after acquiring the lock
            if self._client is None:
                config = ClientConfiguration(
                    api_url=settings.openfga_api_url,
                    store_id=settings.openfga_store_id,
                    authorization_model_id=settings.openfga_model_id or None,
                )
                self._client = OpenFgaClient(config)
        return self._client

    # ── Check ─────────────────────────────────────────────────────────────────

    async def check(self, user_id: str, chunk_id: str, relation: Relation = Relation.VIEWER) -> bool:
        """Return True if user has `relation` on chunk."""
        client = await self._get_client()
        body = ClientCheckRequest(
            user=f"user:{user_id}",
            relation=relation.value,
            object=f"chunk:{chunk_id}",
        )
        resp = await client.check(body)
        return bool(resp.allowed)

    async def decide(self, user_id: str, chunk_id: str) -> AuthzDecision:
        """
        Full authorization decision for a chunk:
          - ALLOWED          → user has viewer relation
          - NEEDS_APPROVAL   → user has pending_approval tuple (approval in-flight)
          - DENIED           → no relation
        """
        if await self.check(user_id, chunk_id, Relation.VIEWER):
            return AuthzDecision.ALLOWED
        if await self.check(user_id, chunk_id, Relation.PENDING_APPROVAL):
            return AuthzDecision.NEEDS_APPROVAL
        return AuthzDecision.DENIED

    async def batch_decide(
        self, user_id: str, chunk_ids: list[str]
    ) -> dict[str, AuthzDecision]:
        """Decide for a list of chunks. Returns {chunk_id: decision}."""
        import asyncio
        tasks = [self.decide(user_id, cid) for cid in chunk_ids]
        results = await asyncio.gather(*tasks)
        return dict(zip(chunk_ids, results))

    async def get_allowed_chunks(self, user_id: str, chunk_ids: list[str]) -> list[str]:
        """Return the subset of chunk_ids the user is allowed to see."""
        decisions = await self.batch_decide(user_id, chunk_ids)
        return [cid for cid, dec in decisions.items() if dec == AuthzDecision.ALLOWED]

    # ── Owner lookup (for approval routing) ──────────────────────────────────

    async def get_chunk_owner(self, chunk_id: str) -> str | None:
        """Return the user ID of the owner of a chunk, if any."""
        client = await self._get_client()
        body = ClientReadRequest(
            object=f"chunk:{chunk_id}",
            relation="owner",
        )
        resp = await client.read(body)
        tuples = resp.tuples or []
        if tuples:
            user_str: str = tuples[0].key.user
            return user_str.removeprefix("user:")
        return None

    # ── Write tuples ──────────────────────────────────────────────────────────

    async def grant_viewer(self, user_id: str, chunk_id: str) -> None:
        """Grant a user viewer access to a chunk (called after approval)."""
        client = await self._get_client()
        body = ClientWriteRequest(
            writes=[
                ClientTupleKey(
                    user=f"user:{user_id}",
                    relation=Relation.VIEWER.value,
                    object=f"chunk:{chunk_id}",
                )
            ]
        )
        await client.write(body)
        log.info("openfga_grant_viewer", user_id=user_id, chunk_id=chunk_id)

    async def set_pending_approval(self, user_id: str, chunk_id: str) -> None:
        """Mark that a user's access to a chunk is pending approval."""
        client = await self._get_client()
        body = ClientWriteRequest(
            writes=[
                ClientTupleKey(
                    user=f"user:{user_id}",
                    relation=Relation.PENDING_APPROVAL.value,
                    object=f"chunk:{chunk_id}",
                )
            ]
        )
        await client.write(body)
        log.info("openfga_set_pending", user_id=user_id, chunk_id=chunk_id)

    async def revoke_pending_approval(self, user_id: str, chunk_id: str) -> None:
        """Remove the pending_approval tuple after a decision is made."""
        client = await self._get_client()
        body = ClientWriteRequest(
            deletes=[
                ClientTupleKey(
                    user=f"user:{user_id}",
                    relation=Relation.PENDING_APPROVAL.value,
                    object=f"chunk:{chunk_id}",
                )
            ]
        )
        await client.write(body)

    async def close(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None
