"""Temporal worker — registers the ApprovalWorkflow and all 5 activities.

Graceful shutdown
-----------------
SIGTERM and SIGINT are handled via an ``asyncio.Event`` so the Kubernetes
pod can drain in-flight activities before the process exits.  The Worker
context manager waits for all running activities to complete (up to Temporal's
configured drain timeout) before returning from ``__aexit__``.

Activity registration
---------------------
All five activities are explicitly registered:
  - notify_approver
  - grant_access_in_openfga
  - revoke_pending_in_openfga   ← critical: without this the denial/timeout
  - notify_user_of_decision       revoke path silently fails with
  - send_a2a_callback             NotRegisteredError at runtime.

The worker connects to Temporal using settings from config.py (no hardcoded
addresses or namespaces).

Entry points
------------
``run()`` is called by the ``worker`` script entry-point defined in pyproject.toml::

    [project.scripts]
    worker = "workflow.worker:run"
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
    revoke_pending_in_openfga,
    send_a2a_callback,
)
from workflow.approval import ApprovalWorkflow

log = structlog.get_logger(__name__)


async def _run() -> None:
    """Async worker loop with SIGTERM/SIGINT graceful shutdown."""
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
    log.info(
        "temporal_worker_starting",
        task_queue=settings.temporal_task_queue,
        address=settings.temporal_address,
        namespace=settings.temporal_namespace,
    )

    async with Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[ApprovalWorkflow],
        activities=[
            notify_approver,
            grant_access_in_openfga,
            revoke_pending_in_openfga,   # required — denial + timeout revoke path
            notify_user_of_decision,
            send_a2a_callback,
        ],
    ):
        log.info("temporal_worker_running")
        await shutdown_event.wait()   # block until SIGTERM or SIGINT

    log.info("temporal_worker_stopped")


def run() -> None:
    """Synchronous entry-point called by the ``worker`` script."""
    asyncio.run(_run())


if __name__ == "__main__":
    run()
