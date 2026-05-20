"""Temporal activities: notification, OpenFGA writes, A2A callbacks."""
from __future__ import annotations

from dataclasses import dataclass

import httpx
import structlog
from temporalio import activity

from config import settings

log = structlog.get_logger(__name__)


@dataclass
class NotifyApproverInput:
    approval_request_id: str
    user_id: str
    chunk_ids: list[str]
    query: str
    approver_id: str
    approver_slack_id: str | None
    approver_email: str | None
    callback_url: str                    # deep-link for approve/deny


@dataclass
class GrantAccessInput:
    user_id: str
    chunk_ids: list[str]


@dataclass
class NotifyUserInput:
    user_id: str
    message: str
    callback_task_id: str | None = None  # A2A task to resume


@dataclass
class A2ACallbackInput:
    peer_agent_url: str
    task_id: str
    delegated_token: str
    decision: str                        # "approved" | "denied"
    message: str


# ── Activities ────────────────────────────────────────────────────────────────

@activity.defn
async def notify_approver(inp: NotifyApproverInput) -> None:
    """Send Slack (or email) message to the approver with approve/deny links."""
    if inp.approver_slack_id and settings.slack_bot_token:
        await _slack_notify(inp)
    elif inp.approver_email:
        log.info("email_notify_approver", email=inp.approver_email, request_id=inp.approval_request_id)
        # Email sending is left as an integration point (SMTP / SendGrid / SES)
    else:
        log.warning("no_notification_channel", approver_id=inp.approver_id)


async def _slack_notify(inp: NotifyApproverInput) -> None:
    approve_url = f"{settings.approval_ui_base_url}/approve/{inp.approval_request_id}?decision=approve"
    deny_url = f"{settings.approval_ui_base_url}/approve/{inp.approval_request_id}?decision=deny"
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
    """Write viewer tuples to OpenFGA for each approved chunk."""
    from auth.openfga import OpenFGAAuth, Relation
    auth = OpenFGAAuth()
    for chunk_id in inp.chunk_ids:
        await auth.grant_viewer(inp.user_id, chunk_id)
        await auth.revoke_pending_approval(inp.user_id, chunk_id)
    await auth.close()
    log.info("openfga_access_granted", user_id=inp.user_id, count=len(inp.chunk_ids))


@activity.defn
async def notify_user_of_decision(inp: NotifyUserInput) -> None:
    """In-app notification to user (stub — integrate with your notification system)."""
    log.info("user_notified", user_id=inp.user_id, message=inp.message)
    # TODO: integrate with your push notification / email system


@activity.defn
async def send_a2a_callback(inp: A2ACallbackInput) -> None:
    """
    Send an A2A task update to the originating agent (cross-cluster approval callback).
    This is called when approval is granted/denied on Cluster B and Cluster A needs to know.
    """
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
            headers={"Authorization": f"Bearer {inp.delegated_token}"},
        )
        if resp.status_code not in (200, 202):
            log.error("a2a_callback_failed", status=resp.status_code, body=resp.text)
        else:
            log.info("a2a_callback_sent", task_id=inp.task_id, decision=inp.decision)
