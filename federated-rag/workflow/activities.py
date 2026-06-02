"""
Temporal activities: notification, OpenFGA writes, A2A callbacks.

Security fixes:
  C-2  — Slack approval deep-links now carry an HMAC-SHA256 signature so that
          only workflow-generated URLs can trigger the /approve endpoint.
  H-6  — revoke_pending_in_openfga activity added; called on denial AND timeout
          so stale pending_approval tuples are always cleaned up.
  H-7  — delegated_token removed from A2ACallbackInput.  The send_a2a_callback
          activity obtains a fresh short-lived token via client-credentials grant
          rather than storing a user-delegated token in Temporal's event history.
  S-3  — send_a2a_callback validates peer_agent_url against the configured
          peer_agent_url allowlist before making any HTTP call (SSRF prevention).
  S-4  — send_a2a_callback POST now carries an explicit httpx timeout.
  S-10 — inp.query truncated to 500 chars before insertion into Slack blocks
          to prevent oversized Slack API payloads.
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

# TM-2: module-level OpenFGA singleton so the SDK client (and its connection
# pool) is created once per Temporal worker process, not once per activity call.
# Temporal activities are short-lived coroutines sharing one event loop, so a
# single async client is safe and avoids per-call TCP handshake overhead.
_openfga_singleton: "OpenFGAAuth | None" = None


def _get_openfga() -> "OpenFGAAuth":
    global _openfga_singleton
    if _openfga_singleton is None:
        from auth.openfga import OpenFGAAuth  # noqa: PLC0415 — deferred to avoid circular import at module init
        _openfga_singleton = OpenFGAAuth()
    return _openfga_singleton


# ── Input dataclasses ─────────────────────────────────────────────────────────

@dataclass
class NotifyApproverInput:
    approval_request_id: str
    user_id: str
    chunk_ids: list[str]
    query: str
    approver_id: str
    approver_slack_id: str | None
    approver_email: str | None
    # C-2: callback_url is generated inside the activity with HMAC signing,
    # not passed as a plain URL from the workflow.


@dataclass
class GrantAccessInput:
    user_id: str
    chunk_ids: list[str]


@dataclass
class RevokeApprovalInput:
    """H-6: used on denial AND timeout to clean up pending_approval tuples."""
    user_id: str
    chunk_ids: list[str]


@dataclass
class NotifyUserInput:
    user_id: str
    message: str
    callback_task_id: str | None = None


@dataclass
class A2ACallbackInput:
    """
    H-7 FIX: delegated_token removed.
    The activity fetches a fresh client-credentials token at call time.
    """
    peer_agent_url: str
    task_id: str
    decision: str                        # "approved" | "denied"
    message: str


# ── HMAC helper (C-2) ─────────────────────────────────────────────────────────

def _sign_approval(request_id: str, decision: str, exp: int) -> str:
    """HMAC-SHA256 hex digest used to authenticate approval deep-links.

    Finding #2: the expiry timestamp is part of the signed message so a leaked
    deep-link cannot be replayed indefinitely after it expires.
    """
    key = settings.approval_hmac_secret.encode()
    msg = f"{request_id}:{decision}:{exp}".encode()
    return hmac_lib.new(key, msg, hashlib.sha256).hexdigest()


def _approval_url(request_id: str, decision: str) -> str:
    # MED-5: percent-encode all query-string values to prevent header injection
    # and ensure URLs remain valid if request_id or decision ever contain special chars.
    # Finding #2: bind a short-lived expiry (the approval workflow timeout) into
    # the signed token so the link stops working once the request can no longer
    # be acted on.
    exp = int(time.time()) + settings.approval_timeout_seconds
    tok = _sign_approval(request_id, decision, exp)
    qs = urlencode({"decision": decision, "exp": exp, "token": tok})
    return f"{settings.approval_ui_base_url}/approve/{quote(request_id)}?{qs}"


# ── Activities ────────────────────────────────────────────────────────────────

@activity.defn
async def notify_approver(inp: NotifyApproverInput) -> None:
    """Send Slack (or email) message to the approver with HMAC-signed links."""
    if inp.approver_slack_id and settings.slack_bot_token:  # GQ-8: slack_bot_token is now str | None
        await _slack_notify(inp)
    elif inp.approver_email:
        log.info(
            "email_notify_approver",
            email=inp.approver_email,
            request_id=inp.approval_request_id,
        )
    else:
        log.warning("no_notification_channel", approver_id=inp.approver_id)


async def _slack_notify(inp: NotifyApproverInput) -> None:
    # C-2: HMAC-signed deep-links so only workflow-generated URLs are accepted
    approve_url = _approval_url(inp.approval_request_id, "approve")
    deny_url    = _approval_url(inp.approval_request_id, "deny")

    # S-10: truncate query before insertion — Slack text blocks have a 3000-char
    # limit; cap earlier to avoid confusing truncation mid-word.
    _MAX_QUERY_DISPLAY = 500
    display_query = inp.query[:_MAX_QUERY_DISPLAY]
    if len(inp.query) > _MAX_QUERY_DISPLAY:
        display_query += "…"

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Access request from user `{inp.user_id}`*\n"
                    f"Query: _{display_query}_\n"
                    f"Chunks requested: `{', '.join(inp.chunk_ids[:5])}`"
                    + (f" (+{len(inp.chunk_ids) - 5} more)" if len(inp.chunk_ids) > 5 else "")
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
    # H3-2: explicit timeout — a hung Slack API must not stall the Temporal activity
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
            log.error("slack_notify_failed", error=data.get("error"))


@activity.defn
async def grant_access_in_openfga(inp: GrantAccessInput) -> None:
    """Write viewer tuples to OpenFGA for each approved chunk and revoke pending."""
    # TM-2: use module-level singleton — no new client per activity call
    auth = _get_openfga()
    for chunk_id in inp.chunk_ids:
        await auth.grant_viewer(inp.user_id, chunk_id)
        await auth.revoke_pending_approval(inp.user_id, chunk_id)
    log.info("openfga_access_granted", user_id=inp.user_id, count=len(inp.chunk_ids))


@activity.defn
async def revoke_pending_in_openfga(inp: RevokeApprovalInput) -> None:
    """
    H-6 FIX: Revoke pending_approval tuples without granting viewer access.
    Called on denial AND timeout so the user can submit a new request later.
    """
    # TM-2: use module-level singleton — no new client per activity call
    auth = _get_openfga()
    for chunk_id in inp.chunk_ids:
        await auth.revoke_pending_approval(inp.user_id, chunk_id)
    log.info("openfga_pending_revoked", user_id=inp.user_id, count=len(inp.chunk_ids))


@activity.defn
async def notify_user_of_decision(inp: NotifyUserInput) -> None:
    """In-app notification to user (stub — integrate with your notification system)."""
    log.info("user_notified", user_id=inp.user_id, message=inp.message)


def _is_allowed_peer_url(url: str) -> bool:
    """
    S-3: validate that the callback URL belongs to the configured peer agent.
    Only allow URLs that begin with the configured peer_agent_url origin so
    Temporal activities cannot be weaponised for SSRF.
    """
    allowed = str(settings.peer_agent_url or "").rstrip("/")
    if not allowed:
        return False
    # Normalise to origin comparison — strip trailing path from both sides
    url_stripped = url.rstrip("/")
    return url_stripped == allowed or url_stripped.startswith(allowed + "/")


@activity.defn
async def send_a2a_callback(inp: A2ACallbackInput) -> None:
    """
    Send an A2A task update to the originating agent (cross-cluster callback).

    H-7 FIX: obtains a fresh agent service-account token via client-credentials
    grant instead of using a stored user-delegated token.  This token is short-lived
    and never persisted in Temporal's event history.
    S-3 FIX: inp.peer_agent_url is validated against the configured allowlist
    before any HTTP call is made, preventing SSRF.
    S-4 FIX: explicit httpx timeout on the callback POST.
    """
    # S-3: SSRF guard — reject URLs not matching the configured peer origin
    if not _is_allowed_peer_url(inp.peer_agent_url):
        log.error(
            "a2a_callback_ssrf_blocked",
            peer_agent_url=inp.peer_agent_url,
            allowed=str(settings.peer_agent_url),
        )
        raise ValueError(
            f"Callback URL '{inp.peer_agent_url}' is not in the peer agent allowlist"
        )

    # Get a short-lived service account token for this agent
    agent_token = await _get_service_account_token()

    payload = {
        "id": inp.task_id,
        "status": {
            "state": "completed" if inp.decision == "approved" else "failed",
            "message": inp.message,
        },
        # M-1: set final=True so the peer SSE consumer knows this is a terminal
        # event and can close its stream.  Without this flag the peer's A2AClient
        # keeps the SSE connection open until the wall-clock deadline (HIGH-4 fix),
        # consuming a connection slot unnecessarily.
        "final": True,
    }
    # S-4: explicit timeout so a hung peer cannot stall the Temporal activity
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{inp.peer_agent_url}/tasks/{inp.task_id}/callback",
            json=payload,
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        if resp.status_code not in (200, 202):
            log.error("a2a_callback_failed", status=resp.status_code, body=resp.text[:500])
            # TM-3: raise so Temporal marks the activity as failed and retries
            # per the retry policy configured in the workflow.  Silently logging
            # and returning would make the callback appear successful even when
            # the peer never received it, defeating Temporal's durability guarantee.
            raise RuntimeError(
                f"A2A callback to {inp.peer_agent_url} returned HTTP {resp.status_code}"
            )
        log.info("a2a_callback_sent", task_id=inp.task_id, decision=inp.decision)


async def _get_service_account_token() -> str:
    """
    Fetch a short-lived access token for this agent using the client-credentials
    OAuth2 grant.  The token is used only for machine-to-machine callbacks and is
    obtained fresh each time — it is never persisted.

    H3-3: explicit client-level timeout in addition to the per-call timeout so a
    hung IdP cannot block the Temporal activity through connection-phase delays.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            settings.oidc_token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.agent_client_id,
                "client_secret": settings.agent_client_secret,
                "scope": "openid",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            # PY-16: timeout already set at the client level above; no need to repeat
        )
        resp.raise_for_status()
        return resp.json()["access_token"]
