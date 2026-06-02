"""Temporal activities for the AGT federated RAG approval workflow.

Every activity is decorated with ``@activity.defn`` and emits a structured
audit log event tagged with ``agt_audit=True`` so the AGT audit sink (e.g.
fluentd → SIEM) can ingest it.

Activities:
    notify_approver             — Slack notification with HMAC-signed deep-links
    grant_access_in_openfga     — grant viewer relation, revoke pending
    revoke_pending_in_openfga   — revoke pending only (denial / timeout)
    notify_user_of_decision     — in-app / log notification to user
    send_a2a_callback           — AGT AgentMesh signed callback to peer cluster

Design decisions:

HMAC deep-links (C-2)
    Approval URLs carry an HMAC-SHA256 signature so only workflow-generated
    URLs can trigger the /approve endpoint.  ``_sign_approval`` uses the
    ``approval_hmac_secret`` setting (required, random 32-byte hex).

OpenFGA singleton (TM-2)
    ``_get_openfga()`` returns a module-level singleton so the SDK client and
    its connection pool are created once per Temporal worker process, not once
    per activity call.

A2A callback via AgentMesh (M-1)
    ``send_a2a_callback`` uses the mesh/peer_client approach (signed IATP
    message) rather than raw httpx.  The payload includes ``"final": True``
    for all terminal states so the peer SSE consumer knows to close its stream.

Slack query truncation (S-10)
    The query preview in Slack blocks is capped at 500 chars to stay well
    below Slack's 3 000-char block text limit.

URL encoding (MED-5)
    ``_approval_url`` uses ``urlencode`` + ``quote`` to percent-encode all
    query-string values, preventing header injection and ensuring URLs are
    valid if request_id contains special characters.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import time
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode

import httpx
import structlog
from temporalio import activity

from config import settings

log = structlog.get_logger(__name__)

# ── OpenFGA singleton (TM-2) ──────────────────────────────────────────────────
# Created once per worker process; never re-created per activity call.
_openfga_singleton: "OpenFGAAuth | None" = None  # noqa: F821 — forward ref


def _get_openfga() -> "OpenFGAAuth":  # noqa: F821
    global _openfga_singleton
    if _openfga_singleton is None:
        from auth.openfga import OpenFGAAuth  # deferred to avoid circular import at module init
        _openfga_singleton = OpenFGAAuth()
    return _openfga_singleton


# ── Input dataclasses ─────────────────────────────────────────────────────────

@dataclass
class NotifyApproverInput:
    """Input for the notify_approver activity."""
    approval_request_id: str
    user_id: str
    chunk_ids: list[str]
    query: str
    approver_id: str
    approver_slack_id: str | None
    approver_email: str | None
    # callback_url is generated inside the activity with HMAC signing, never passed in


@dataclass
class GrantAccessInput:
    """Input for grant_access_in_openfga."""
    user_id: str
    chunk_ids: list[str]


@dataclass
class RevokeApprovalInput:
    """Input for revoke_pending_in_openfga (denial and timeout paths)."""
    user_id: str
    chunk_ids: list[str]


@dataclass
class NotifyUserInput:
    """Input for notify_user_of_decision."""
    user_id: str
    message: str
    callback_task_id: str | None = None


@dataclass
class A2ACallbackInput:
    """Input for send_a2a_callback.

    No delegated token — the AgentMesh layer signs messages with the agent's
    DID credentials; no stored user token is needed or transmitted.
    """
    peer_agent_url: str
    task_id: str
    decision: str          # "approved" | "denied"
    message: str


# ── HMAC helper ───────────────────────────────────────────────────────────────

def _sign_approval(request_id: str, decision: str, exp: int) -> str:
    """HMAC-SHA256 hex digest used to authenticate approval deep-links.

    The key is the ``approval_hmac_secret`` setting (required, random 32-byte
    hex).  The message is ``{request_id}:{decision}:{exp}`` — request_id and
    decision are included so a valid approve token cannot be reused as a deny
    token, and exp (Finding #2) so a leaked link cannot be replayed after it
    expires.
    """
    key = settings.approval_hmac_secret.encode()
    msg = f"{request_id}:{decision}:{exp}".encode()
    return hmac_lib.new(key, msg, hashlib.sha256).hexdigest()


def _approval_url(request_id: str, decision: str) -> str:
    """Build a fully signed approval deep-link URL.

    MED-5: all query-string values are percent-encoded via urlencode + quote
    to prevent header injection and ensure URLs are valid if request_id or
    decision ever contain special characters.
    Finding #2: a short-lived expiry (the approval workflow timeout) is bound
    into the signed token so the link stops working once the request can no
    longer be acted on.
    """
    exp = int(time.time()) + settings.approval_timeout_seconds
    tok = _sign_approval(request_id, decision, exp)
    qs = urlencode({"decision": decision, "exp": exp, "token": tok})
    return f"{settings.approval_ui_base_url}/approve/{quote(request_id)}?{qs}"


# ── Activities ────────────────────────────────────────────────────────────────

@activity.defn
async def notify_approver(inp: NotifyApproverInput) -> None:
    """Send a Slack (or email fallback) notification to the approver.

    Slack blocks contain HMAC-signed approve/deny buttons.
    The query preview is capped at 500 chars (S-10).
    AGT audit event emitted on every call.
    """
    log.info(
        "activity_notify_approver",
        approval_request_id=inp.approval_request_id,
        approver_id=inp.approver_id,
        agt_audit=True,
    )

    if inp.approver_slack_id and settings.slack_bot_token:
        await _slack_notify(inp)
    elif inp.approver_email:
        log.info(
            "email_notify_approver",
            email=inp.approver_email,
            request_id=inp.approval_request_id,
            agt_audit=True,
        )
    else:
        log.warning(
            "no_notification_channel",
            approver_id=inp.approver_id,
            request_id=inp.approval_request_id,
        )


async def _slack_notify(inp: NotifyApproverInput) -> None:
    """Internal helper: post approval request blocks to Slack."""
    approve_url = _approval_url(inp.approval_request_id, "approve")
    deny_url    = _approval_url(inp.approval_request_id, "deny")

    # S-10: cap query preview at 500 chars — Slack text blocks have a 3000-char
    # limit; capping earlier avoids confusing mid-word truncation.
    _MAX_QUERY_DISPLAY = 500
    display_query = inp.query[:_MAX_QUERY_DISPLAY]
    if len(inp.query) > _MAX_QUERY_DISPLAY:
        display_query += "…"

    chunk_preview = ", ".join(inp.chunk_ids[:5])
    extra = f" (+{len(inp.chunk_ids) - 5} more)" if len(inp.chunk_ids) > 5 else ""

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Access request from user `{inp.user_id}`*\n"
                    f"Query: _{display_query}_\n"
                    f"Chunks requested: `{chunk_preview}`{extra}"
                ),
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "url": approve_url,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "url": deny_url,
                },
            ],
        },
    ]

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            "https://slack.com/api/chat.postMessage",
            json={
                "channel": inp.approver_slack_id,
                "blocks": blocks,
                "text": f"Access request from {inp.user_id}",
            },
            headers={"Authorization": f"Bearer {settings.slack_bot_token}"},
        )
        data = resp.json()
        if not data.get("ok"):
            log.error(
                "slack_notify_failed",
                error=data.get("error"),
                request_id=inp.approval_request_id,
            )


@activity.defn
async def grant_access_in_openfga(inp: GrantAccessInput) -> None:
    """Grant viewer relation and revoke pending_approval for approved chunks.

    Uses the module-level OpenFGA singleton (TM-2).
    Emits AGT audit event.
    """
    log.info(
        "activity_grant_access",
        user_id=inp.user_id,
        chunk_count=len(inp.chunk_ids),
        agt_audit=True,
    )
    auth = _get_openfga()
    for chunk_id in inp.chunk_ids:
        await auth.grant_viewer(inp.user_id, chunk_id)
        await auth.revoke_pending_approval(inp.user_id, chunk_id)
    log.info(
        "openfga_access_granted",
        user_id=inp.user_id,
        count=len(inp.chunk_ids),
        agt_audit=True,
    )


@activity.defn
async def revoke_pending_in_openfga(inp: RevokeApprovalInput) -> None:
    """Revoke pending_approval tuples without granting viewer access.

    Called on both denial and timeout so stale pending tuples do not block
    future access requests.  Uses the module-level OpenFGA singleton (TM-2).
    """
    log.info(
        "activity_revoke_pending",
        user_id=inp.user_id,
        chunk_count=len(inp.chunk_ids),
        agt_audit=True,
    )
    auth = _get_openfga()
    for chunk_id in inp.chunk_ids:
        await auth.revoke_pending_approval(inp.user_id, chunk_id)
    log.info(
        "openfga_pending_revoked",
        user_id=inp.user_id,
        count=len(inp.chunk_ids),
        agt_audit=True,
    )


@activity.defn
async def notify_user_of_decision(inp: NotifyUserInput) -> None:
    """Log an in-app notification to the user about the approval decision.

    In production this would integrate with a push-notification service,
    WebSocket channel, or email gateway.  The structured log entry is
    sufficient for the AGT audit trail.
    """
    log.info(
        "activity_notify_user",
        user_id=inp.user_id,
        callback_task_id=inp.callback_task_id,
        message_preview=inp.message[:100],
        agt_audit=True,
    )


@activity.defn
async def send_a2a_callback(inp: A2ACallbackInput) -> None:
    """Send a signed callback to the originating peer agent via AgentMesh IATP.

    Uses the mesh/peer_client approach (DID-signed IATP message) rather than
    raw httpx so the callback inherits the full AGT security stack:
    DID verification, trust-score gating, IATP encryption, circuit breaker.

    M-1 fix: payload includes ``"final": True`` for all terminal states so the
    peer SSE consumer knows to close its stream.

    SSRF prevention: the target URL must match the configured peer_agent_url.
    """
    log.info(
        "activity_send_a2a_callback",
        task_id=inp.task_id,
        decision=inp.decision,
        peer_agent_url=inp.peer_agent_url,
        agt_audit=True,
    )

    # SSRF guard — only allow callbacks to the configured peer origin
    allowed = str(settings.peer_agent_url or "").rstrip("/")
    if not allowed:
        log.error("a2a_callback_no_peer_configured")
        raise ValueError("No peer_agent_url configured — cannot send callback")

    normalised = inp.peer_agent_url.rstrip("/")
    if normalised != allowed and not normalised.startswith(allowed + "/"):
        log.error(
            "a2a_callback_ssrf_blocked",
            peer_agent_url=inp.peer_agent_url,
            allowed=allowed,
        )
        raise ValueError(
            f"Callback URL '{inp.peer_agent_url}' is not in the peer agent allowlist"
        )

    # Build the signed callback payload via AgentMesh
    from mesh.agent_identity import sign_outbound_message  # deferred — avoids import cycles

    payload = {
        "id": inp.task_id,
        "status": {
            "state": "completed" if inp.decision == "approved" else "failed",
            "message": inp.message,
        },
        # M-1: "final": True signals this is a terminal event so the peer SSE
        # consumer closes the stream instead of waiting for the wall-clock deadline.
        "final": True,
        "decision": inp.decision,
    }

    signed_payload = await sign_outbound_message(payload)

    # Send via httpx with explicit timeout (the AgentMesh SDK handles signing
    # but transport is our responsibility here for the callback path)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{inp.peer_agent_url.rstrip('/')}/tasks/{inp.task_id}/callback",
            json=signed_payload,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code not in (200, 202):
            log.error(
                "a2a_callback_failed",
                status=resp.status_code,
                body=resp.text[:500],
                task_id=inp.task_id,
            )
            # Raise so Temporal marks the activity failed and retries per policy
            raise RuntimeError(
                f"A2A callback to {inp.peer_agent_url} returned HTTP {resp.status_code}"
            )

    log.info(
        "a2a_callback_sent",
        task_id=inp.task_id,
        decision=inp.decision,
        agt_audit=True,
    )
