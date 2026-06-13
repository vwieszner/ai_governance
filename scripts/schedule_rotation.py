"""Start the credential-rotation cron workflow for a division (Phase-1 item 8).

Registers a Temporal cron that periodically rotates the division's DID credentials +
approval HMAC secret (workflow.rotation.KeyRotationWorkflow, run by the division's worker).
Idempotent: re-running replaces the cron schedule on the same workflow id.

    .venv\\Scripts\\python.exe scripts/schedule_rotation.py --division alpha --cron "0 3 * * 0"

Default cron is weekly (Sunday 03:00). The worker must be running (it registers the
workflow + activity). Verify in the Temporal UI or via `temporal workflow list`.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "agt-federated-rag"
sys.path.insert(0, str(APP))


async def _main(division: str, cron: str) -> int:
    import os
    os.environ["RAG_ENV_FILE"] = f".env.{division}"
    os.chdir(APP)  # so RAG_ENV_FILE resolves like the agent/worker

    from temporalio.client import Client
    from config import settings
    from workflow.rotation import KeyRotationWorkflow, RotationInput

    secrets_path = str(ROOT / "infra" / "generated" / division / "secrets.json")
    client = await Client.connect(settings.temporal_address, namespace=settings.temporal_namespace)
    handle = await client.start_workflow(
        KeyRotationWorkflow.run,
        RotationInput(secrets_path=secrets_path),
        id=f"key-rotation-{division}",
        task_queue=settings.temporal_task_queue,
        cron_schedule=cron,
    )
    print(f"[rotation] scheduled key-rotation-{division} cron={cron!r} (workflow {handle.id})")
    print("[rotation] the division worker runs it; check the Temporal UI for next-run time.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--division", required=True)
    ap.add_argument("--cron", default="0 3 * * 0", help="cron spec (default weekly Sun 03:00)")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(_main(args.division, args.cron)))
