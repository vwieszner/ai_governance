"""Push the current OpenFGA authorization model to a live division store (Phase-1 item 3/12).

OpenFGA models are immutable + versioned: writing a new model returns a new model_id; old
tuples remain valid. This applies the current scripts/_provisioning.AUTH_MODEL (e.g. after
adding the group#member viewer userset) to a division's existing store WITHOUT re-onboarding,
updates infra/generated/<id>/state.json and agt-federated-rag/.env.<id> to the new model_id,
and tells you to restart the agent so its checks use it. Additive + reversible.

    .venv\\Scripts\\python.exe scripts/migrate_authz_model.py alpha beta
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from _provisioning import AUTH_MODEL  # noqa: E402

PORT_OFFSETS = {"openfga": 1}
import yaml  # noqa: E402


def _port_base(div: str) -> int:
    return int(yaml.safe_load((ROOT / "infra" / "divisions" / f"{div}.yml").read_text())["port_base"])


def migrate(div: str) -> str:
    gen = ROOT / "infra" / "generated" / div
    secrets = json.loads((gen / "secrets.json").read_text())
    state = json.loads((gen / "state.json").read_text())
    ofga = f"http://127.0.0.1:{_port_base(div) + 1}"
    req = urllib.request.Request(
        f"{ofga}/stores/{state['store_id']}/authorization-models",
        data=json.dumps(AUTH_MODEL).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {secrets.get('openfga_api_token','')}"},
        method="POST")
    new_id = json.load(urllib.request.urlopen(req, timeout=20))["authorization_model_id"]

    state["model_id"] = new_id
    (gen / "state.json").write_text(json.dumps(state, indent=2))
    # Update the agent env's OPENFGA_MODEL_ID line in place.
    env_path = ROOT / "agt-federated-rag" / f".env.{div}"
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()
        out, found = [], False
        for ln in lines:
            if ln.startswith("OPENFGA_MODEL_ID="):
                out.append(f"OPENFGA_MODEL_ID={new_id}"); found = True
            else:
                out.append(ln)
        if not found:
            out.append(f"OPENFGA_MODEL_ID={new_id}")
        env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"[migrate] {div}: new model_id={new_id}")
    return new_id


def main(argv: list[str]) -> int:
    divs = argv or ["alpha", "beta", "gamma"]
    for d in divs:
        migrate(d)
    print("\n[migrate] restart the affected agents so checks use the new model:")
    print("  scripts/clusters.ps1 restart " + " ".join(divs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
