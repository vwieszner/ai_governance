"""Verify the tamper-evident audit chain(s) (IMPLEMENTATION_PLAN.md M8).

Recomputes each per-(division, role) hash chain and reports OK / the first break
(tampered field, deletion, reorder, truncation).

Usage:
    python scripts/verify_audit.py                 # all chains under agt-federated-rag/audit_logs
    python scripts/verify_audit.py --division beta # only beta's chains
    python scripts/verify_audit.py --dir <path>    # a specific audit dir
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGT = ROOT / "agt-federated-rag"
sys.path.insert(0, str(AGT))

from audit_log import verify_chain  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify tamper-evident audit chains (M8).")
    ap.add_argument("--dir", default=None, help="audit dir (default agt-federated-rag/audit_logs)")
    ap.add_argument("--division", default=None, help="limit to this division id")
    args = ap.parse_args()

    base = Path(args.dir) if args.dir else (AGT / "audit_logs")
    if not base.is_dir():
        print(f"no audit dir: {base}")
        return 1
    pattern = f"{args.division}_*.jsonl" if args.division else "*.jsonl"
    files = sorted(base.glob(pattern))
    if not files:
        print(f"no chain files matching {pattern} in {base}")
        return 1

    rc = 0
    for f in files:
        ok, detail = verify_chain(f)
        print(f"[{'OK  ' if ok else 'FAIL'}] {f.name}: {detail}")
        if not ok:
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
