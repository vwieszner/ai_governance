"""Per-chunk ReBAC (Relationship-Based Access Control) via OpenFGA.

Design decisions:
- Relation enum: typed relations prevent typo-bugs when constructing tuples.
  PENDING_APPROVAL is a first-class relation so approval state lives in the
  authorisation store rather than a separate DB table.
- AuthzDecision enum: the decide() method returns a three-way decision
  (ALLOWED / NEEDS_APPROVAL / DENIED) rather than a boolean, giving the
  agent layer a clear signal to trigger the Temporal approval workflow.
- asyncio.Lock double-checked locking: the OpenFGA client is created once and
  reused across requests.  Lazy init avoids startup coupling — the agent can
  boot even if OpenFGA is momentarily unavailable.
- revoke_pending_approval idempotency: OpenFGA returns 404 when a tuple to
  delete does not exist.  We catch ApiException and check exc.status == 404
  explicitly rather than matching on string content, which would be fragile.
- AGT audit logging: every check() call emits a structured log event tagged
  with user_id, chunk_id, relation, and decision.  These events can be
  collected by the AGT audit sink (e.g., shipped to an SIEM via fluentd).
"""
from __future__ import annotations

import asyncio
from enum import Enum
from typing import Any

import structlog
from openfga_sdk.exceptions import ApiException  # type: ignore[import]

from config import settings

log = structlog.get_logger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────────────


class Relation(str, Enum):
    VIEWER = "viewer"
    EDITOR = "editor"
    OWNER = "owner"
    PENDING_APPROVAL = "pending_approval"


class AuthzDecision(str, Enum):
    ALLOWED = "allowed"
    NEEDS_APPROVAL = "needs_approval"
    DENIED = "denied"


# ── Client singleton ───────────────────────────────────────────────────────────


class OpenFGAAuth:
    """Per-chunk ReBAC client with AGT-compatible audit logging.

    Usage::

        auth = await OpenFGAAuth.get_instance()
        decision = await auth.decide(user_id="u:alice", chunk_id="abc123")
    """

    _instance: "OpenFGAAuth | None" = None
    _lock: asyncio.Lock = asyncio.Lock()

    def __init__(self) -> None:
        self._client: Any = None

    # ── Singleton factory ──────────────────────────────────────────────────────

    @classmethod
    async def get_instance(cls) -> "OpenFGAAuth":
        """Return the shared OpenFGA client (double-checked async locking)."""
        if cls._instance is not None:
            return cls._instance
        async with cls._lock:
            if cls._instance is None:
                inst = cls()
                await inst._init()
                cls._instance = inst
        return cls._instance

    async def _init(self) -> None:
        """Create and open the async OpenFGA client."""
        try:
            from openfga_sdk import ClientConfiguration, OpenFgaClient  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "openfga_sdk is required. Install: pip install openfga-sdk"
            ) from exc

        # OpenFGA server runs with preshared-key auth — authenticate every call.
        credentials = None
        if settings.openfga_api_token:
            from openfga_sdk.credentials import CredentialConfiguration, Credentials
            credentials = Credentials(
                method="api_token",
                configuration=CredentialConfiguration(api_token=settings.openfga_api_token),
            )
        config = ClientConfiguration(
            api_url=settings.openfga_api_url,
            store_id=settings.openfga_store_id,
            authorization_model_id=settings.openfga_model_id,
            credentials=credentials,
        )
        self._client = OpenFgaClient(config)
        await self._client.__aenter__()
        log.info("openfga.init", api_url=settings.openfga_api_url)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _object_id(self, chunk_id: str) -> str:
        """Format a chunk_id as an OpenFGA object reference."""
        return f"chunk:{chunk_id}"

    def _user_id(self, user_id: str) -> str:
        """Ensure the user reference has the required 'user:' prefix."""
        return user_id if user_id.startswith("user:") else f"user:{user_id}"

    # ── Core check ────────────────────────────────────────────────────────────

    async def check(
        self,
        user_id: str,
        chunk_id: str,
        relation: Relation,
    ) -> bool:
        """Check whether *user_id* has *relation* on *chunk_id*.

        Emits a structured audit log event for every check (AGT audit hook).
        """
        assert self._client is not None
        # openfga-sdk 0.10: OpenFgaClient.check() takes a ClientCheckRequest with
        # flat user/relation/object fields — NOT the protocol-level CheckRequest
        # wrapping a TupleKey (the SDK reads body.user directly, which a
        # CheckRequest does not expose -> "'CheckRequest' object has no attribute 'user'").
        from openfga_sdk.client.models import ClientCheckRequest  # type: ignore[import]

        body = ClientCheckRequest(
            user=self._user_id(user_id),
            relation=relation.value,
            object=self._object_id(chunk_id),
        )
        try:
            resp = await self._client.check(body)
            allowed: bool = bool(resp.allowed)
        except ApiException:
            log.exception(
                "openfga.check.error",
                user_id=user_id,
                chunk_id=chunk_id,
                relation=relation.value,
            )
            allowed = False

        log.info(
            "openfga.check",
            user_id=user_id,
            chunk_id=chunk_id,
            relation=relation.value,
            allowed=allowed,
            # AGT audit tag — collected by the audit event sink
            agt_audit=True,
        )
        return allowed

    # ── Decision logic ────────────────────────────────────────────────────────

    async def decide(self, user_id: str, chunk_id: str) -> AuthzDecision:
        """Return a three-way AuthzDecision for user_id on chunk_id.

        Decision priority:
            1. ALLOWED   — user has viewer, editor, or owner relation.
            2. NEEDS_APPROVAL — user has pending_approval relation only.
            3. DENIED    — no relation found.
        """
        # Fan out the two most common checks concurrently.
        viewer_ok, pending_ok = await asyncio.gather(
            self.check(user_id, chunk_id, Relation.VIEWER),
            self.check(user_id, chunk_id, Relation.PENDING_APPROVAL),
        )
        if viewer_ok:
            return AuthzDecision.ALLOWED
        if pending_ok:
            return AuthzDecision.NEEDS_APPROVAL
        return AuthzDecision.DENIED

    async def batch_decide(
        self, user_id: str, chunk_ids: list[str]
    ) -> dict[str, AuthzDecision]:
        """Return AuthzDecision for each chunk_id, evaluated concurrently."""
        decisions = await asyncio.gather(
            *(self.decide(user_id, cid) for cid in chunk_ids)
        )
        return dict(zip(chunk_ids, decisions))

    # ── Convenience helpers ────────────────────────────────────────────────────

    async def get_allowed_chunks(
        self, user_id: str, chunk_ids: list[str]
    ) -> list[str]:
        """Return the subset of chunk_ids for which user_id has ALLOWED decision."""
        decisions = await self.batch_decide(user_id, chunk_ids)
        return [cid for cid, d in decisions.items() if d == AuthzDecision.ALLOWED]

    async def get_chunk_owner(self, chunk_id: str) -> str | None:
        """Look up the owner of *chunk_id*.

        Returns the user_id string (without 'user:' prefix) or None if not found.
        Note: OpenFGA v1 ListObjects is used to find who has owner relation.
        """
        assert self._client is not None
        try:
            # openfga-sdk 0.10: OpenFgaClient.read() takes a ReadRequestTupleKey
            # (user=None matches any user with the relation) — not a protocol
            # ReadRequest wrapping a TupleKey.
            from openfga_sdk.models.read_request_tuple_key import (  # type: ignore[import]
                ReadRequestTupleKey,
            )

            resp = await self._client.read(
                ReadRequestTupleKey(
                    user=None,
                    relation=Relation.OWNER.value,
                    object=self._object_id(chunk_id),
                )
            )
            tuples = getattr(resp, "tuples", [])
            if not tuples:
                return None
            raw_user: str = tuples[0].key.user
            # Strip the 'user:' prefix for callers.
            return raw_user.removeprefix("user:")
        except ApiException:
            log.exception("openfga.get_chunk_owner.error", chunk_id=chunk_id)
            return None

    # ── Tuple write helpers ────────────────────────────────────────────────────

    async def _write_tuple(self, user_id: str, chunk_id: str, relation: Relation) -> None:
        """Write a single authorisation tuple to OpenFGA (idempotent on "already exists").

        OpenFGA returns HTTP 400 when writing a tuple that already exists. That
        happens when a chunk was pre-seeded (setup seeds alice→pending_approval on
        the q4 chunk) or when an approval write is retried. Re-asserting an
        existing tuple is a no-op, so we swallow *only* the "already exists" 400
        and let every other 400 (malformed tuple, etc.) propagate.
        """
        assert self._client is not None
        from openfga_sdk.client.models import ClientTuple, ClientWriteRequest  # type: ignore[import]

        try:
            await self._client.write(
                ClientWriteRequest(
                    writes=[
                        ClientTuple(
                            user=self._user_id(user_id),
                            relation=relation.value,
                            object=self._object_id(chunk_id),
                        )
                    ]
                )
            )
        except ApiException as exc:
            detail = (getattr(exc, "body", "") or str(exc)).lower()
            if exc.status == 400 and "already exist" in detail:
                log.warning(
                    "openfga.write_tuple.exists",
                    user_id=user_id,
                    chunk_id=chunk_id,
                    relation=relation.value,
                    reason="tuple already exists (400)",
                )
                return
            raise
        log.info(
            "openfga.write_tuple",
            user_id=user_id,
            chunk_id=chunk_id,
            relation=relation.value,
            agt_audit=True,
        )

    async def _delete_tuple(self, user_id: str, chunk_id: str, relation: Relation) -> None:
        """Delete a single authorisation tuple from OpenFGA (idempotent on 404)."""
        assert self._client is not None
        from openfga_sdk.client.models import ClientTuple, ClientWriteRequest  # type: ignore[import]

        try:
            await self._client.write(
                ClientWriteRequest(
                    deletes=[
                        ClientTuple(
                            user=self._user_id(user_id),
                            relation=relation.value,
                            object=self._object_id(chunk_id),
                        )
                    ]
                )
            )
            log.info(
                "openfga.delete_tuple",
                user_id=user_id,
                chunk_id=chunk_id,
                relation=relation.value,
                agt_audit=True,
            )
        except ApiException as exc:
            if exc.status == 404:
                # Tuple did not exist — idempotent, not an error.
                log.debug(
                    "openfga.delete_tuple.not_found",
                    user_id=user_id,
                    chunk_id=chunk_id,
                    relation=relation.value,
                )
            else:
                raise

    # ── Public tuple helpers ───────────────────────────────────────────────────

    async def grant_viewer(self, user_id: str, chunk_id: str) -> None:
        """Grant VIEWER relation to user_id on chunk_id."""
        await self._write_tuple(user_id, chunk_id, Relation.VIEWER)

    async def set_pending_approval(self, user_id: str, chunk_id: str) -> None:
        """Set PENDING_APPROVAL relation for user_id on chunk_id."""
        await self._write_tuple(user_id, chunk_id, Relation.PENDING_APPROVAL)

    async def revoke_pending_approval(self, user_id: str, chunk_id: str) -> None:
        """Remove PENDING_APPROVAL relation (idempotent — 404 is silently ignored).

        ApiException with status == 404 is caught and ignored for idempotency.
        Any other ApiException is re-raised.  Broad string matching on the error
        message is intentionally avoided (M-3 fix).
        """
        await self._delete_tuple(user_id, chunk_id, Relation.PENDING_APPROVAL)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def close(self) -> None:
        """Close the OpenFGA async client."""
        if self._client is not None:
            try:
                await self._client.__aexit__(None, None, None)
            except Exception:
                log.exception("openfga.close.error")
            finally:
                self._client = None
                log.info("openfga.closed")
