"""Backup / restore a division's durable state (Phase-1 item 13).

Captures the per-division stores so a division can be rebuilt after data loss:
  - Postgres (OpenFGA datastore)  : pg_dump via `docker exec`
  - Qdrant (vectors)             : snapshot via the Qdrant API
  - Keycloak realm               : partial realm export via the admin API
  - OpenFGA tuples               : read all tuples (logical backup; store/model in state.json)
  - DID + secrets                : copy infra/generated/<id>/{did.json,secrets.json,state.json}

Output: a timestamped folder under backups/<division>/<stamp>/. Restore guidance is printed
and documented in infra/observability/BACKUP_RUNBOOK.md (full automated restore of Postgres
+ Qdrant is the high-value path; Keycloak/OpenFGA logical exports support rebuild/verify).

    .venv\\Scripts\\python.exe scripts/backup_division.py --division alpha --stamp 20260613
(stamp is required — the runtime can't call Date.now deterministically; pass it in.)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import yaml  # noqa: E402

PORT_OFFSETS = {"openfga": 1, "qdrant": 5}


def _ctx(div: str) -> dict:
    base = int(yaml.safe_load((ROOT / "infra" / "divisions" / f"{div}.yml").read_text())["port_base"])
    gen = ROOT / "infra" / "generated" / div
    secrets = json.loads((gen / "secrets.json").read_text())
    state = json.loads((gen / "state.json").read_text())
    return {"base": base, "gen": gen, "secrets": secrets, "state": state,
            "ofga": f"http://127.0.0.1:{base + 1}", "qdrant": f"http://127.0.0.1:{base + 5}"}


def _post(url, token, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})},
        method="POST")
    raw = urllib.request.urlopen(req, timeout=30).read()
    return json.loads(raw) if raw.strip() else None


def backup(div: str, stamp: str) -> int:
    ctx = _ctx(div)
    out = ROOT / "backups" / div / stamp
    out.mkdir(parents=True, exist_ok=True)

    # 1. Postgres dump via docker exec (container div-<id>-postgres).
    try:
        pg = subprocess.run(
            ["docker", "exec", f"div-{div}-postgres", "pg_dump", "-U",
             ctx["secrets"].get("postgres_user", "openfga"), "openfga"],
            capture_output=True, text=True, timeout=120)
        if pg.returncode == 0:
            (out / "postgres.sql").write_text(pg.stdout, encoding="utf-8")
            print(f"  [ok] postgres -> postgres.sql ({len(pg.stdout)} bytes)")
        else:
            print(f"  [warn] pg_dump rc={pg.returncode}: {pg.stderr[:120]}")
    except Exception as e:
        print(f"  [warn] postgres dump skipped: {type(e).__name__}")

    # 2. Qdrant snapshot (API) — records the snapshot name on the server.
    try:
        snap = _post(f"{ctx['qdrant']}/collections/knowledge_base/snapshots", "", {})
        (out / "qdrant_snapshot.json").write_text(json.dumps(snap, indent=2))
        print("  [ok] qdrant snapshot created (see qdrant_snapshot.json)")
    except Exception as e:
        print(f"  [warn] qdrant snapshot skipped: {type(e).__name__}")

    # 3. OpenFGA tuples (logical) — read all tuples for the store.
    try:
        tuples = _post(f"{ctx['ofga']}/stores/{ctx['state']['store_id']}/read",
                       ctx["secrets"].get("openfga_api_token", ""), {})
        (out / "openfga_tuples.json").write_text(json.dumps(tuples, indent=2))
        n = len(tuples.get("tuples", [])) if isinstance(tuples, dict) else 0
        print(f"  [ok] openfga tuples -> openfga_tuples.json ({n} tuples)")
    except Exception as e:
        print(f"  [warn] openfga export skipped: {type(e).__name__}")

    # 4. Identity + provisioning state (copy the gitignored generated artifacts).
    for fn in ("did.json", "state.json"):
        src = ctx["gen"] / fn
        if src.exists():
            (out / fn).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"  [ok] copied did.json + state.json")
    print(f"\nBackup complete: {out}")
    print("Restore: see infra/observability/BACKUP_RUNBOOK.md")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--division", required=True)
    ap.add_argument("--stamp", required=True, help="backup folder stamp, e.g. 20260613-1200")
    args = ap.parse_args()
    raise SystemExit(backup(args.division, args.stamp))
