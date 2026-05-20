"""
Temporal approval workflow.

Flow:
  1. Agent detects NEEDS_APPROVAL chunks
  2. Starts this workflow with the request details
  3. Workflow writes pending_approval tuples to OpenFGA
  4. Notifies the approver (Slack/email) with approve/deny deep-link
  5. Waits up to 24h for an `approval_decision` signal
  6. On approve: writes viewer tuples, notifies user, optionally sends A2A callback
  7. On deny/timeout: revokes pending tuples, notifies user/originating agent

Usage (from the agent):
    handle = await temporal_client.start_workflow(
        ApprovalWorkflow.run,
        ApprovalInput(...),
        id=f"approval-{request_id}",
        task_queue=settings.temporal_task_queue,
    )
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

import structlog
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import TimeoutError as TemporalTimeoutError

with workflow.unsafe.imports_passed_through():
    from workflow.activities import (
        A2ACallbackInput,
        GrantAccessInput,
        NotifyApproverInput,
        NotifyUserInput,
        grant_access_in_openfga,
        notify_approver,
        notify_user_of_decision,
        send_a2a_callback,
    )
    from config import settings

log = structlog.get_logger(__name__)

NO_RETRY = RetryPolicy(maximum_attempts=1)
RETRY_3 = RetryPolicy(maximum_attempts=3, initial_interval=timedelta(seconds=5))


@dataclass
class ApprovalInput:
    approval_request_id: str
    user_id: str
    chunk_ids: list[str]
    query: str

    # Approver details (resolved from OpenFGA `owner` relation before starting)
    approver_id: str
    approver_slack_id: str | None = None
    approver_email: str | None = None

    # For cross-cluster flows: the originating A2A task and agent
    originating_task_id: str | None = None
    originating_agent_url: str | None = None
    originating_delegated_token: str | None = None


@dataclass
class ApprovalDecisionSignal:
    decision: str          # "approved" | "denied"
    reason: str = ""
    approver_id: str = ""


@dataclass
class ApprovalResult:
    decision: str          # "approved" | "denied" | "timeout"
    reason: str = ""


@workflow.defn
class ApprovalWorkflow:

    def __init__(self) -> None:
        self._decision: ApprovalDecisionSignal | None = None

    @workflow.signal
    async def approval_decision(self, signal: ApprovalDecisionSignal) -> None:
        """Receives the approve/deny signal from the approval UI."""
        self._decision = signal
        log.info(
            "approval_signal_received",
            decision=signal.decision,
            approver=signal.approver_id,
        )

    @workflow.run
    async def run(self, inp: ApprovalInput) -> ApprovalResult:
        log.info("approval_workflow_started", request_id=inp.approval_request_id, user=inp.user_id)

        # Step 1: Write pending_approval tuples to OpenFGA
        # (done by the agent before starting the workflow — see agent/nodes.py)

        # Step 2: Notify the approver
        callback_url = (
            f"{settings.approval_ui_base_url}/approve/{inp.approval_request_id}"
        )
        await workflow.execute_activity(
            notify_approver,
            NotifyApproverInput(
                approval_request_id=inp.approval_request_id,
                user_id=inp.user_id,
                chunk_ids=inp.chunk_ids,
                query=inp.query,
                approver_id=inp.approver_id,
                approver_slack_id=inp.approver_slack_id,
                approver_email=inp.approver_email,
                callback_url=callback_url,
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RETRY_3,
        )

        # Step 3: Wait for decision signal (up to approval_timeout_seconds)
        try:
            await workflow.wait_condition(
                lambda: self._decision is not None,
                timeout=timedelta(seconds=settings.approval_timeout_seconds),
            )
        except TemporalTimeoutError:
            await self._handle_timeout(inp)
            return ApprovalResult(decision="timeout", reason="No response from approver within timeout")

        decision = self._decision  # type: ignore[assignment]

        # Step 4: Handle decision
        if decision.decision == "approved":
            return await self._handle_approved(inp, decision)
        else:
            return await self._handle_denied(inp, decision)

    async def _handle_approved(
        self, inp: ApprovalInput, decision: ApprovalDecisionSignal
    ) -> ApprovalResult:
        # Write OpenFGA viewer tuples
        await workflow.execute_activity(
            grant_access_in_openfga,
            GrantAccessInput(user_id=inp.user_id, chunk_ids=inp.chunk_ids),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RETRY_3,
        )

        # Notify the user
        await workflow.execute_activity(
            notify_user_of_decision,
            NotifyUserInput(
                user_id=inp.user_id,
                message=f"Your access request has been approved. You can now query the requested data.",
                callback_task_id=inp.originating_task_id,
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=NO_RETRY,
        )

        # If this is a cross-cluster request, send A2A callback to originating agent
        if inp.originating_agent_url and inp.originating_task_id and inp.originating_delegated_token:
            await workflow.execute_activity(
                send_a2a_callback,
                A2ACallbackInput(
                    peer_agent_url=inp.originating_agent_url,
                    task_id=inp.originating_task_id,
                    delegated_token=inp.originating_delegated_token,
                    decision="approved",
                    message="Access approved. Re-send the original request to retrieve data.",
                ),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RETRY_3,
            )

        log.info("approval_workflow_approved", request_id=inp.approval_request_id)
        return ApprovalResult(decision="approved", reason=decision.reason)

    async def _handle_denied(
        self, inp: ApprovalInput, decision: ApprovalDecisionSignal
    ) -> ApprovalResult:
        await workflow.execute_activity(
            notify_user_of_decision,
            NotifyUserInput(
                user_id=inp.user_id,
                message=f"Your access request was denied. Reason: {decision.reason or 'Not specified'}",
                callback_task_id=inp.originating_task_id,
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=NO_RETRY,
        )

        if inp.originating_agent_url and inp.originating_task_id and inp.originating_delegated_token:
            await workflow.execute_activity(
                send_a2a_callback,
                A2ACallbackInput(
                    peer_agent_url=inp.originating_agent_url,
                    task_id=inp.originating_task_id,
                    delegated_token=inp.originating_delegated_token,
                    decision="denied",
                    message=f"Access denied. Reason: {decision.reason or 'Not specified'}",
                ),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RETRY_3,
            )

        return ApprovalResult(decision="denied", reason=decision.reason)

    async def _handle_timeout(self, inp: ApprovalInput) -> None:
        await workflow.execute_activity(
            notify_user_of_decision,
            NotifyUserInput(
                user_id=inp.user_id,
                message="Your access request timed out with no response from the approver.",
                callback_task_id=inp.originating_task_id,
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=NO_RETRY,
        )
