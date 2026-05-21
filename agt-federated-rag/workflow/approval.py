"""Temporal workflow for human-in-the-loop approval of restricted data access.

Flow:
  1. Agent detects LOCAL_NEEDS_APPROVAL chunks.
  2. nodes.start_approval writes pending_approval tuples to OpenFGA, then
     starts this workflow with the chunk list and approver details.
  3. Workflow notifies the approver via Slack/email (HMAC-signed deep-link).
  4. Workflow waits up to ``timeout_seconds`` for an ``approval_decision`` signal.
  5a. Approved  → grant viewer + revoke pending, notify user, optional A2A callback.
  5b. Denied    → revoke pending, notify user, optional A2A callback.
  5c. Timeout   → revoke pending, notify user, optional A2A callback.

Security decisions:

No delegated token in ApprovalInput (H-7 carried forward)
    Agent-to-agent identity is now handled by AGT AgentMesh DIDs, not by RFC
    8693 token exchange.  The ``send_a2a_callback`` activity uses
    ``mesh.agent_identity.sign_outbound_message`` instead of storing any token.

Timeout snapshot (Q-7 carried forward)
    ``timeout_seconds`` is snapshotted from ``settings.approval_timeout_seconds``
    by the caller (``nodes.start_approval``) before the workflow is started.
    Reading ``settings.*`` inside ``@workflow.run`` is non-deterministic if the
    value changes between runs — Temporal would fail on replay.

Deterministic assert after wait_condition (TM-1)
    After ``wait_condition`` returns (not via TimeoutError), ``self._decision``
    is guaranteed non-None.  We assert this instead of using a type-ignore so
    mypy and the runtime both catch any future regression.

workflow.logger inside workflow code (L-1)
    Temporal workflows replay their event history deterministically.  Using the
    standard structlog logger inside ``@workflow.run`` / signal handlers is fine
    for side-effect-free logging, but ``workflow.logger`` correctly associates
    log entries with the workflow execution context in the Temporal UI.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import TimeoutError as TemporalTimeoutError

with workflow.unsafe.imports_passed_through():
    from workflow.activities import (
        A2ACallbackInput,
        GrantAccessInput,
        NotifyApproverInput,
        NotifyUserInput,
        RevokeApprovalInput,
        grant_access_in_openfga,
        notify_approver,
        notify_user_of_decision,
        revoke_pending_in_openfga,
        send_a2a_callback,
    )

# ── Retry policies ────────────────────────────────────────────────────────────

NO_RETRY = RetryPolicy(maximum_attempts=1)
RETRY_3  = RetryPolicy(maximum_attempts=3, initial_interval=timedelta(seconds=5))


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class ApprovalInput:
    """Workflow input — snapshot all settings at start time for replay safety."""

    approval_request_id: str
    user_id: str
    chunk_ids: list[str]
    query: str

    # Approver details (resolved from OpenFGA owner relation by nodes.py)
    approver_id: str
    approver_slack_id: str | None = None
    approver_email: str | None = None

    # Cross-cluster: originating A2A task for the callback after decision
    # No token stored here — AgentMesh DID signing handles auth (H-7).
    originating_task_id: str | None = None
    originating_agent_url: str | None = None

    # Snapshot timeout from settings at workflow-start time (Q-7)
    timeout_seconds: int = 86400   # default 24 h; caller overrides from settings


@dataclass
class ApprovalDecisionSignal:
    """Signal payload sent from the approval UI endpoint."""

    decision: str      # "approved" | "denied"
    reason: str = ""
    approver_id: str = ""


@dataclass
class ApprovalResult:
    """Workflow return value."""

    decision: str      # "approved" | "denied" | "timeout"
    reason: str = ""
    approver_id: str = ""
    approval_request_id: str = ""


# ── Workflow ──────────────────────────────────────────────────────────────────

@workflow.defn
class ApprovalWorkflow:
    """Human-in-the-loop approval workflow for restricted data access.

    State:
        _decision — set by the approval_decision signal handler; None until
                    a signal arrives.
    """

    def __init__(self) -> None:
        self._decision: ApprovalDecisionSignal | None = None

    # ── Signal handler ────────────────────────────────────────────────────────

    @workflow.signal
    async def approval_decision(self, signal: ApprovalDecisionSignal) -> None:
        """Receive approve/deny signal from the approval UI."""
        self._decision = signal
        workflow.logger.info(
            "approval_signal_received",
            decision=signal.decision,
            approver=signal.approver_id,
        )

    # ── Main run ──────────────────────────────────────────────────────────────

    @workflow.run
    async def run(self, inp: ApprovalInput) -> ApprovalResult:
        """Execute the full approval flow: notify → wait → decide."""
        workflow.logger.info(
            "approval_workflow_started",
            request_id=inp.approval_request_id,
            user=inp.user_id,
            chunk_count=len(inp.chunk_ids),
        )

        # Step 1: notify the approver with HMAC-signed deep-link buttons
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
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RETRY_3,
        )

        # Step 2: wait for signal or timeout
        # Q-7: use inp.timeout_seconds (snapshotted at start) not settings.*
        try:
            await workflow.wait_condition(
                lambda: self._decision is not None,
                timeout=timedelta(seconds=inp.timeout_seconds),
            )
        except TemporalTimeoutError:
            await self._handle_timeout(inp)
            return ApprovalResult(
                decision="timeout",
                reason="No response from approver within the deadline.",
                approval_request_id=inp.approval_request_id,
            )

        # TM-1: wait_condition guarantees _decision is set — assert for mypy + safety
        assert self._decision is not None, (
            "wait_condition returned without TimeoutError but _decision is None"
        )
        decision = self._decision

        if decision.decision == "approved":
            return await self._handle_approved(inp, decision)
        else:
            return await self._handle_denied(inp, decision)

    # ── Decision handlers ─────────────────────────────────────────────────────

    async def _handle_approved(
        self, inp: ApprovalInput, signal: ApprovalDecisionSignal
    ) -> ApprovalResult:
        """Grant viewer access, clean up pending tuples, notify user, callback."""
        # grant_access_in_openfga also revokes pending tuples atomically
        await workflow.execute_activity(
            grant_access_in_openfga,
            GrantAccessInput(user_id=inp.user_id, chunk_ids=inp.chunk_ids),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RETRY_3,
        )

        await workflow.execute_activity(
            notify_user_of_decision,
            NotifyUserInput(
                user_id=inp.user_id,
                message=(
                    "Your access request has been approved. "
                    "You can now query the requested data."
                ),
                callback_task_id=inp.originating_task_id,
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=NO_RETRY,
        )

        # Cross-cluster callback — M-1: final=True set inside the activity
        if inp.originating_agent_url and inp.originating_task_id:
            await workflow.execute_activity(
                send_a2a_callback,
                A2ACallbackInput(
                    peer_agent_url=inp.originating_agent_url,
                    task_id=inp.originating_task_id,
                    decision="approved",
                    message=(
                        "Access approved. Re-send the original request to retrieve data."
                    ),
                ),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RETRY_3,
            )

        workflow.logger.info(
            "approval_workflow_approved",
            request_id=inp.approval_request_id,
        )
        return ApprovalResult(
            decision="approved",
            reason=signal.reason,
            approver_id=signal.approver_id,
            approval_request_id=inp.approval_request_id,
        )

    async def _handle_denied(
        self, inp: ApprovalInput, signal: ApprovalDecisionSignal
    ) -> ApprovalResult:
        """Revoke pending tuples, notify user, optional cross-cluster callback."""
        await workflow.execute_activity(
            revoke_pending_in_openfga,
            RevokeApprovalInput(user_id=inp.user_id, chunk_ids=inp.chunk_ids),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RETRY_3,
        )

        # Cap reason at 500 chars to prevent oversized notification payloads
        reason_display = (signal.reason or "Not specified")[:500]
        await workflow.execute_activity(
            notify_user_of_decision,
            NotifyUserInput(
                user_id=inp.user_id,
                message=f"Your access request was denied. Reason: {reason_display}",
                callback_task_id=inp.originating_task_id,
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=NO_RETRY,
        )

        if inp.originating_agent_url and inp.originating_task_id:
            await workflow.execute_activity(
                send_a2a_callback,
                A2ACallbackInput(
                    peer_agent_url=inp.originating_agent_url,
                    task_id=inp.originating_task_id,
                    decision="denied",
                    message=f"Access denied. Reason: {signal.reason or 'Not specified'}",
                ),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RETRY_3,
            )

        workflow.logger.info(
            "approval_workflow_denied",
            request_id=inp.approval_request_id,
        )
        return ApprovalResult(
            decision="denied",
            reason=signal.reason,
            approver_id=signal.approver_id,
            approval_request_id=inp.approval_request_id,
        )

    async def _handle_timeout(self, inp: ApprovalInput) -> None:
        """Revoke pending tuples, notify user, notify originating peer agent."""
        await workflow.execute_activity(
            revoke_pending_in_openfga,
            RevokeApprovalInput(user_id=inp.user_id, chunk_ids=inp.chunk_ids),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RETRY_3,
        )

        await workflow.execute_activity(
            notify_user_of_decision,
            NotifyUserInput(
                user_id=inp.user_id,
                message=(
                    "Your access request timed out — no response from the approver. "
                    "You may re-submit the request."
                ),
                callback_task_id=inp.originating_task_id,
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=NO_RETRY,
        )

        # Notify the originating peer so its task transitions out of INPUT_REQUIRED.
        # Without this callback the peer's task stays in INPUT_REQUIRED indefinitely.
        # M-1: final=True set inside send_a2a_callback activity.
        if inp.originating_agent_url and inp.originating_task_id:
            await workflow.execute_activity(
                send_a2a_callback,
                A2ACallbackInput(
                    peer_agent_url=inp.originating_agent_url,
                    task_id=inp.originating_task_id,
                    decision="denied",
                    message=(
                        "Access request timed out — no approver response within the deadline."
                    ),
                ),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RETRY_3,
            )

        workflow.logger.warning(
            "approval_workflow_timed_out",
            request_id=inp.approval_request_id,
            user=inp.user_id,
        )
