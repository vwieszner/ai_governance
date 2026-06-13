"""Scheduled credential rotation (Phase-1 item 8).

A Temporal cron workflow periodically rotates this division's secrets:
  - the agent's Ed25519 DID credentials (via AgentMesh LifecycleManager), and
  - the approval-deep-link HMAC secret (rolled with a one-window overlap so links signed
    just before rotation still verify).

Why Temporal: the stack already runs a Temporal worker per division, so a cron workflow
is durable, observable in the Temporal UI, and survives restarts — no extra scheduler.
Start it once with scripts/schedule_rotation.py; Temporal then fires it on the cron spec.

The actual work lives in :func:`perform_rotation` (a plain async function) so it is unit-
testable without the Temporal sandbox; the activity is a thin wrapper.
"""
from __future__ import annotations

import json
import secrets as _secrets
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import structlog
from temporalio import activity, workflow
from temporalio.common import RetryPolicy

log = structlog.get_logger(__name__)


def rotate_approval_hmac(secrets_path: str) -> bool:
    """Roll the approval HMAC secret in the division's secrets.json, keeping the prior
    value as ``approval_hmac_secret_prev`` for a one-rotation grace window (so a deep-link
    signed just before rotation still verifies). Returns True on write.

    Takes effect on the next agent restart (config is read at startup) — runtime hot-reload
    is part of the secrets-backend item (#14). Idempotent-safe: always writes a fresh value.
    """
    p = Path(secrets_path)
    if not p.exists():
        log.warning("hmac_rotation_secrets_missing", path=secrets_path)
        return False
    data = json.loads(p.read_text(encoding="utf-8"))
    cur = data.get("approval_hmac_secret", "")
    if cur:
        data["approval_hmac_secret_prev"] = cur
    data["approval_hmac_secret"] = _secrets.token_hex(32)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log.info("approval_hmac_rotated", path=secrets_path, agt_audit=True)
    return True


async def perform_rotation(secrets_path: str | None = None) -> dict:
    """Rotate DID credentials + (optionally) the approval HMAC secret. Best-effort per
    item: a failure of one is logged and reported, never aborts the other. Returns a
    summary dict {did: bool, hmac: bool}."""
    summary = {"did": False, "hmac": False}
    # DID credentials (AgentMesh) — best-effort inside rotate_credentials already.
    try:
        from mesh.agent_identity import rotate_credentials
        await rotate_credentials()
        summary["did"] = True
    except Exception as exc:  # noqa: BLE001
        log.error("did_rotation_failed", error=str(exc))
    # Approval HMAC secret.
    if secrets_path:
        try:
            summary["hmac"] = rotate_approval_hmac(secrets_path)
        except Exception as exc:  # noqa: BLE001
            log.error("hmac_rotation_failed", error=str(exc))
    log.info("rotation_complete", agt_audit=True, **summary)
    return summary


@dataclass
class RotationInput:
    secrets_path: str | None = None


@activity.defn
async def rotate_keys_activity(inp: RotationInput) -> dict:
    return await perform_rotation(inp.secrets_path)


@workflow.defn
class KeyRotationWorkflow:
    """Single-shot rotation; started with a cron_schedule so Temporal re-runs it."""

    @workflow.run
    async def run(self, inp: RotationInput) -> dict:
        return await workflow.execute_activity(
            rotate_keys_activity,
            inp,
            start_to_close_timeout=timedelta(seconds=120),
            retry_policy=RetryPolicy(maximum_attempts=3, initial_interval=timedelta(seconds=10)),
        )
