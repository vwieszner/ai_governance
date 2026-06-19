"""Provision a Kubernetes division by REUSING the exact, tested onboarding logic.

`bootstrap-k8s.ps1` port-forwards a division's in-cluster services to that division's
derived host ports, then runs this script. Because `onboard_division.provision()` already
talks to `localhost:<derived ports>` (the same ports compose maps), we can drive the full,
battle-tested provisioning — OpenFGA store+model, Keycloak realm/clients/users/roles, doc
ingest into Qdrant, DID issuance, seed grants — against the CLUSTER, with zero duplicated
logic. The only k8s-specific step is emitting the resulting store/model ids so the caller
can complete the in-cluster Secret (the agent pod reads config from the ConfigMap/Secret,
not the .env this writes — that .env is only used host-side for the ingest step).

Usage:  python scripts/k8s_provision.py <division-id>
Prints (on success):  STORE_ID=<...>  and  MODEL_ID=<...>
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "agt-federated-rag"))

import onboard_division as od  # noqa: E402


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/k8s_provision.py <division-id>")
    div = sys.argv[1]
    manifest = od.load_manifest(ROOT / "infra" / "divisions" / f"{div}.yml")
    ports = od.derive_ports(manifest.port_base)
    secretz = od._load_or_make_secrets(div)

    # Drive the real provisioning against the port-forwarded cluster services.
    # no_neo4j=True: the k8s base ships no Neo4j (retrieval is Qdrant-only, inert seam).
    asyncio.run(od.provision(manifest, ports, secretz, no_neo4j=True))

    state = json.loads((od.generated_dir(div) / "state.json").read_text(encoding="utf-8"))
    print(f"STORE_ID={state['store_id']}")
    print(f"MODEL_ID={state['model_id']}")


if __name__ == "__main__":
    main()
