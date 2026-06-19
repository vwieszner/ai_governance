"""Interactive playground for governed cross-department tool delegation.

Send ANY tool request to ANY department as that department's user, and see whether it ran
LOCALLY or was securely DELEGATED to the peer that owns the tool. The department doesn't have
to own the tool — if it doesn't, it delegates over the DID-signed /a2a/tool channel.

Usage (from repo root):
    python examples/cross-agent-pii/try_tool.py <division> <capability> '<json-args>'

Examples:
    python examples/cross-agent-pii/try_tool.py epsilon tool.pii      '{"text": "reach me at me@acme.com, card 4242424242424242"}'
    python examples/cross-agent-pii/try_tool.py gamma   tool.fincheck '{"amount": 99999, "currency": "USD", "counterparty": "Volkov Holdings"}'
    python examples/cross-agent-pii/try_tool.py delta   tool.compliance '{"topic": "human oversight"}'
    python examples/cross-agent-pii/try_tool.py epsilon tool.risk     '{"description": "a biometric identification system in public spaces"}'

Capabilities: tool.pii {text} | tool.compliance {topic} | tool.risk {description}
              tool.classify {text} | tool.fincheck {amount,currency,counterparty}
Departments (kind-agt): gamma=Security/Legal (pii,compliance), delta=Risk/Data-Gov (risk,classify),
                        epsilon=Finance (fincheck). Any dept can use any tool (own or borrowed).
Prereq: the divisions are up + federated on the cluster (scripts/bootstrap_k8s.py).
"""
from __future__ import annotations

import http.client
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CTX = "kind-agt"
PORT_BASE = {"alpha": 9000, "beta": 9100, "gamma": 9200, "delta": 9300, "epsilon": 9400}


def _retry(fn, n=6):
    last = None
    for _ in range(n):
        try:
            return fn()
        except (http.client.RemoteDisconnected, ConnectionError, urllib.error.URLError) as exc:
            last = exc
            time.sleep(2)
    raise last


def main() -> None:
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    div, capability, args_json = sys.argv[1], sys.argv[2], sys.argv[3]
    if div not in PORT_BASE:
        print(f"unknown division {div!r} (one of {', '.join(PORT_BASE)})")
        sys.exit(2)
    arguments = json.loads(args_json)
    base = PORT_BASE[div]
    ns = f"agt-div-{div}"

    procs = [
        subprocess.Popen(["kubectl", "--context", CTX, "-n", ns, "port-forward", "svc/agent",
                          f"{base}:8000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen(["kubectl", "--context", CTX, "-n", ns, "port-forward", "svc/keycloak",
                          f"{base + 2}:8080"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]
    time.sleep(8)
    try:
        pw = json.loads((ROOT / "infra" / "generated" / div / "secrets.json").read_text())["seed_user_password"]
        data = urllib.parse.urlencode({"grant_type": "password", "client_id": "rag-ui",
                                       "username": "alice", "password": pw}).encode()
        tok_url = f"http://localhost:{base + 2}/realms/rag/protocol/openid-connect/token"
        tok = _retry(lambda: json.loads(urllib.request.urlopen(tok_url, data=data, timeout=15).read()))["access_token"]

        def call():
            req = urllib.request.Request(
                f"http://localhost:{base}/solve",
                data=json.dumps({"capability": capability, "arguments": arguments}).encode(),
                headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())

        r = _retry(call)
        src = r.get("source")
        where = "ran LOCALLY (this department owns the tool)" if src == "local" \
            else f"DELEGATED to peer {r.get('peer_did')} (borrowed the tool, governed)" if src == "peer" \
            else f"source={src}"
        print(f"\n  {div} asked for {capability}  ->  {where}")
        print(f"  status: {r.get('status')}")
        print(f"  result: {json.dumps(r.get('result'), indent=2)}")
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
