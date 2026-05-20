"""Temporal worker — runs the approval workflow and its activities.

FIX R-1: revoke_pending_in_openfga was missing from the activities list.
Without this registration, the H-6 fix (revoke on denial/timeout) silently
fails with a NotRegisteredError at runtime, leaving stale pending_approval
tuples in OpenFGA.
"""
from __future__ import annotations

import asyncio

import structlog
from temporalio.client import Client
from temporalio.worker import Worker

from config import settings
from workflow.activities import (
    grant_access_in_openfga,
    notify_approver,
    notify_user_of_decision,
    revoke_pending_in_openfga,   # FIX R-1
    send_a2a_callback,
)
from workflow.approval import ApprovalWorkflow

log = structlog.get_logger(__name__)


async def _run() -> None:
    client = await Client.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
    )
    log.info("temporal_worker_starting", task_queue=settings.temporal_task_queue)
    async with Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[ApprovalWorkflow],
        activities=[
            notify_approver,
            grant_access_in_openfga,
            revoke_pending_in_openfga,   # FIX R-1: was missing
            notify_user_of_decision,
            send_a2a_callback,
        ],
    ):
        log.info("temporal_worker_running")
        await asyncio.Event().wait()   # run forever


def run() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    run()
