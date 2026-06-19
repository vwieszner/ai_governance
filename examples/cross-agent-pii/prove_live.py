"""Reproducible LIVE proof of governed cross-department tool delegation on Kubernetes.

Runs a fixed set of scenarios against the running kind cluster through the REAL
authenticated POST /solve API, over real HTTP between division pods, and asserts the
expected governed outcome for each (local vs delegated-to-peer). This is the script behind
the "it works" claim — run it yourself:

    python examples/cross-agent-pii/prove_live.py            # gamma+delta+epsilon (3 depts)
    python examples/cross-agent-pii/prove_live.py gamma delta   # just the two

Prereqs: the divisions are up + federated on the cluster (see this folder's README /
scripts/bootstrap_k8s.py). The script opens its own kubectl port-forwards and tears them
down. Seed-user passwords are read from infra/generated/<div>/secrets.json (gitignored).

What each scenario proves:
  - source == "local"  : the division ran ITS OWN governed tool.
  - source == "peer"   : the division lacked the tool and securely DELEGATED to the peer
                         that owns it (peer_did shown), over the DID-signed /a2a/tool channel,
                         the peer re-authorizing the delegated user (not bypassed).
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

# division -> (agent local port, keycloak local port). Derived from each manifest's port_base
# (agent=base, keycloak=base+2) — see onboard_division.derive_ports.
PORT_BASE = {"alpha": 9000, "beta": 9100, "gamma": 9200, "delta": 9300, "epsilon": 9400}

# Each scenario: (sender division, capability, arguments, expected source). The expected
# source encodes which department OWNS the tool: a division that serves the capability runs it
# locally; one that doesn't delegates to its configured peer.
SCENARIOS = [
    ("epsilon", "tool.fincheck",
     {"amount": 50000, "currency": "USD", "counterparty": "Volkov Holdings"}, "local",
     "Finance screens a $50k payment with its OWN AML tool"),
    ("epsilon", "tool.pii",
     {"text": "wire confirmation to alice@example.com, card 4242424242424242"}, "peer",
     "Finance borrows Security/Legal's PII/DLP tool"),
    ("gamma", "tool.fincheck",
     {"amount": 250, "currency": "KPW", "counterparty": "North Star Trading"}, "peer",
     "Security/Legal borrows Finance's AML tool"),
    ("gamma", "tool.pii",
     {"text": "contact bob at bob@acme.com"}, "local",
     "Security/Legal runs its OWN PII tool"),
    ("delta", "tool.risk",
     {"description": "a recruitment screening AI system that ranks candidates"}, "local",
     "Risk/Data-Gov runs its OWN EU AI Act risk tool"),
    ("delta", "tool.compliance",
     {"topic": "transparency obligations"}, "peer",
     "Risk/Data-Gov borrows Security/Legal's compliance tool"),
]


def _retry(fn, n=6):
    last = None
    for _ in range(n):
        try:
            return fn()
        except (http.client.RemoteDisconnected, ConnectionError, urllib.error.URLError) as exc:
            last = exc
            time.sleep(2)
    raise last


def _pf(div: str):
    base = PORT_BASE[div]
    ns = f"agt-div-{div}"
    return [
        subprocess.Popen(["kubectl", "--context", CTX, "-n", ns, "port-forward", "svc/agent",
                          f"{base}:8000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen(["kubectl", "--context", CTX, "-n", ns, "port-forward", "svc/keycloak",
                          f"{base + 2}:8080"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]


def _token(div: str) -> str:
    base = PORT_BASE[div]
    pw = json.loads((ROOT / "infra" / "generated" / div / "secrets.json").read_text())["seed_user_password"]
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "rag-ui",
                                   "username": "alice", "password": pw}).encode()
    url = f"http://localhost:{base + 2}/realms/rag/protocol/openid-connect/token"
    return _retry(lambda: json.loads(urllib.request.urlopen(url, data=data, timeout=15).read()))["access_token"]


def _solve(div: str, tok: str, capability: str, arguments: dict) -> dict:
    base = PORT_BASE[div]

    def call():
        req = urllib.request.Request(
            f"http://localhost:{base}/solve",
            data=json.dumps({"capability": capability, "arguments": arguments}).encode(),
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    return _retry(call)


def main() -> None:
    divs = sys.argv[1:] or ["gamma", "delta", "epsilon"]
    scenarios = [s for s in SCENARIOS if s[0] in divs]
    procs = []
    for d in divs:
        procs += _pf(d)
    time.sleep(10)
    npass = nfail = 0
    try:
        tokens = {d: _token(d) for d in divs}
        for sender, capability, arguments, expect_source, label in scenarios:
            r = _solve(sender, tokens[sender], capability, arguments)
            src = r.get("source")
            ok = r.get("status") == "completed" and src == expect_source
            npass += ok
            nfail += (not ok)
            mark = "PASS" if ok else "FAIL"
            peer = f" via {r.get('peer_did')}" if src == "peer" else ""
            print(f"[{mark}] {sender:8s} {capability:16s} -> {src}{peer}")
            print(f"        {label}")
            print(f"        result: {json.dumps(r.get('result'))[:160]}")
    finally:
        for p in procs:
            p.terminate()
    print(f"\n{npass} passed, {nfail} failed (of {npass + nfail}) — "
          f"governed cross-department tool delegation, live on {CTX}.")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
