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
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
from dataclasses import dataclass, field

import httpx
import structlog
from temporalio import activity

from config import settings

log = structlog.get_logger(__name__)


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

def _sign_approval(request_id: str, decision: str) -> str:
    """HMAC-SHA256 hex digest used to authenticate approval deep-links."""
    key = settings.approval_hmac_secret.encode()
    msg = f"{request_id}:{decision}".encode()
    return hmac_lib.new(key, msg, hashlib.sha256).hexdigest()


def _approval_url(request_id: str, decision: str) -> str:
    tok = _sign_approval(request_id, decision)
    return (
        f"{settings.approval_ui_base_url}/approve/{request_id}"
        f"?decision={decision}&token={tok}"
    )


# ── Activities ────────────────────────────────────────────────────────────────

@activity.defn
async def notify_approver(inp: NotifyApproverInput) -> None:
    """Send Slack (or email) message to the approver with HMAC-signed links."""
    if inp.approver_slack_id and settings.slack_bot_token:
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

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Access request from user `{inp.user_id}`*\n"
                    f"Query: _{inp.query}_\n"
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
    async with httpx.AsyncClient() as client:
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
    from auth.openfga import OpenFGAAuth
    auth = OpenFGAAuth()
    for chunk_id in inp.chunk_ids:
        await auth.grant_viewer(inp.user_id, chunk_id)
        await auth.revoke_pending_approval(inp.user_id, chunk_id)
    await auth.close()
    log.info("openfga_access_granted", user_id=inp.user_id, count=len(inp.chunk_ids))


@activity.defn
async def revoke_pending_in_openfga(inp: RevokeApprovalInput) -> None:
    """
    H-6 FIX: Revoke pending_approval tuples without granting viewer access.
    Called on denial AND timeout so the user can submit a new request later.
    """
    from auth.openfga import OpenFGAAuth
    auth = OpenFGAAuth()
    for chunk_id in inp.chunk_ids:
        await auth.revoke_pending_approval(inp.user_id, chunk_id)
    await auth.close()
    log.info("openfga_pending_revoked", user_id=inp.user_id, count=len(inp.chunk_ids))


@activity.defn
async def notify_user_of_decision(inp: NotifyUserInput) -> None:
    """In-app notification to user (stub — integrate with your notification system)."""
    log.info("user_notified", user_id=inp.user_id, message=inp.message)


@activity.defn
async def send_a2a_callback(inp: A2ACallbackInput) -> None:
    """
    Send an A2A task update to the originating agent (cross-cluster callback).

    H-7 FIX: obtains a fresh agent service-account token via client-credentials
    grant instead of using a stored user-delegated token.  This token is short-lived
    and never persisted in Temporal's event history.
    """
    # Get a short-lived service account token for this agent
    agent_token = await _get_service_account_token()

    payload = {
        "id": inp.task_id,
        "status": {
            "state": "completed" if inp.decision == "approved" else "failed",
            "message": inp.message,
        },
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{inp.peer_agent_url}/tasks/{inp.task_id}/callback",
            json=payload,
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        if resp.status_code not in (200, 202):
            log.error("a2a_callback_failed", status=resp.status_code, body=resp.text)
        else:
            log.info("a2a_callback_sent", task_id=inp.task_id, decision=inp.decision)


async def _get_service_account_token() -> str:
    """
    Fetch a short-lived access token for this agent using the client-credentials
    OAuth2 grant.  The token is used only for machine-to-machine callbacks and is
    obtained fresh each time — it is never persisted.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            settings.oidc_token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.agent_client_id,
                "client_secret": settings.agent_client_secret,
                "scope": "openid",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]
