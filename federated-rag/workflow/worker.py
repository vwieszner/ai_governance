"""Temporal worker — runs the approval workflow and its activities.

FIX R-1: revoke_pending_in_openfga was missing from the activities list.
Without this registration, the H-6 fix (revoke on denial/timeout) silently
fails with a NotRegisteredError at runtime, leaving stale pending_approval
tuples in OpenFGA.
"""
from __future__ import annotations

import asyncio
import signal

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
    # NIT-3: handle SIGTERM so Kubernetes graceful shutdown stops the worker
    # cleanly instead of killing it mid-activity.  The shutdown event is set on
    # the first signal; the Worker context-manager then drains in-flight
    # activities before returning.
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _handle_signal() -> None:
        log.info("temporal_worker_shutdown_signal")
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal)

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
        await shutdown_event.wait()   # run until SIGTERM / SIGINT
    log.info("temporal_worker_stopped")


def run() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    run()
