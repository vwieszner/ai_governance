#!/usr/bin/env python
"""Stand up the AGT federated-RAG template across MULTIPLE Kubernetes clusters.

This is the template's PRODUCTION-SHAPED topology: each division is its **own cluster**
(its own control plane, its own physically-isolated stack), and divisions federate over
**routable network URLs + DIDs** — the multi-cloud / multi-cluster deployment the template
targets (k8s/README: "Kubernetes is for a real multi-node / multi-cloud deployment"). It does
that locally with **one kind cluster per division**, so you can run and present the real
multi-cluster model on a single host.

    python scripts/multicluster.py up     --divisions gamma,delta   # create clusters + deploy + federate
    python scripts/multicluster.py status  --divisions gamma,delta
    python scripts/multicluster.py prove   --divisions gamma,delta   # cross-cluster tool delegation, live
    python scripts/multicluster.py down    --divisions gamma,delta   # delete the clusters

Mapping: division `d` -> kind cluster `agt-<d>` (context `kind-agt-<d>`). After `up`, an agent
in one cluster delegates a tool it lacks to the peer that owns it — **across clusters** — over
the DID-signed `/a2a/tool` channel, re-authorized by the owner. Nothing is shared across a
cluster boundary except the signed peer call.

REUSE: this orchestrates the existing, tested `scripts/bootstrap_k8s.py` — one division's
bring-up is the SAME single-cluster path (`bootstrap_division`); only "a cluster per division"
and the routable cross-cluster federation (`federate_multicluster`) are added here. It does not
reimplement provisioning, federation, or the governed tool mesh.

Connectivity (local kind): every kind cluster attaches to the shared `kind` Docker bridge, so a
pod in cluster A reaches cluster B's agent at B's node IP + the agent NodePort (30800). On the
default kind CNI (kindnet) NetworkPolicy is inert, so this just works; on an enforcing CNI add
the peer node CIDR to `allow-agent-federation` (see the doc). In a real multi-cloud deploy the
peer URL is the agent's LoadBalancer/Ingress hostname instead of a node IP — same wiring.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "agt-federated-rag"))
import bootstrap_k8s as bk  # noqa: E402

KIND = str(ROOT / ".tools" / "kind.exe")
if not Path(KIND).exists():
    KIND = "kind"  # fall back to kind on PATH
IMAGE = "agt-federated-rag"
SRC_TAG = "src"


def cluster_name(div: str) -> str:
    return f"agt-{div}"


def context(div: str) -> str:
    return f"kind-{cluster_name(div)}"


def _run(cmd: list[str], check: bool = True, capture: bool = False) -> str:
    r = subprocess.run(cmd, cwd=str(ROOT), text=True,
                       capture_output=True if capture else False)
    if check and r.returncode != 0:
        if capture:
            sys.stderr.write((r.stdout or "") + (r.stderr or ""))
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(cmd)}")
    return (r.stdout or "") if capture else ""


def existing_clusters() -> set[str]:
    out = _run([KIND, "get", "clusters"], check=False, capture=True)
    return {ln.strip() for ln in out.splitlines() if ln.strip()}


def _make_context_insecure(div: str) -> None:
    """Set the new cluster's kube-context to skip API-server TLS verification.

    Host-specific (documented in CLAUDE.md / k8s/README): when an AV/proxy intercepts TLS
    (Norton here), kubectl can't verify the kind API server's localhost cert ("certificate
    signed by unknown authority"). The existing kind-agt context is already configured this
    way; we apply the same to each new context. Must unset the CA data first — kubectl
    rejects insecure-skip-tls-verify while a certificate-authority is also set."""
    ctx = context(div)  # kind contexts name the cluster entry the same as the context
    _run(["kubectl", "config", "unset", f"clusters.{ctx}.certificate-authority-data"], check=False)
    _run(["kubectl", "config", "set-cluster", ctx, "--insecure-skip-tls-verify=true"], check=False)


def create_cluster(div: str) -> None:
    name = cluster_name(div)
    if name in existing_clusters():
        print(f"  cluster {name} already exists")
    else:
        print(f"  creating kind cluster {name} ...")
        _run([KIND, "create", "cluster", "--name", name])
    # Always (re)assert the insecure-skip-tls-verify context fix — idempotent, and needed
    # whether the cluster was just created or already existed.
    _make_context_insecure(div)


def delete_cluster(div: str) -> None:
    name = cluster_name(div)
    if name not in existing_clusters():
        print(f"  cluster {name} not present")
        return
    print(f"  deleting kind cluster {name} ...")
    _run([KIND, "delete", "cluster", "--name", name], check=False)


# ── cross-cluster RELAY: the host is the L4 router between the kind clusters ────────────────
# On this kind/Docker-Desktop host the clusters' Service/pod networks don't traverse the Docker
# bridge (kindnet iptables routing is inert cross-cluster), but every pod CAN reach the host
# (host.docker.internal) and the host can reach every cluster (kubectl port-forward). So each
# agent is port-forwarded to a stable HOST port (bound on 0.0.0.0 so pods reach it via
# host.docker.internal), and the peer trust map points at http://host.docker.internal:<port>.
# This is the local analogue of a cloud LoadBalancer; production uses the real LB/Ingress URL.
def _seed_password(div: str) -> str:
    return json.loads((ROOT / "infra" / "generated" / div / "secrets.json").read_text())["seed_user_password"]


def _agent_relay_pf(div: str) -> subprocess.Popen:
    """Host port-forward exposing a division's agent on its relay host port, bound on 0.0.0.0
    so other clusters' pods reach it via host.docker.internal."""
    return subprocess.Popen(
        ["kubectl", "--context", context(div), "-n", f"agt-div-{div}", "port-forward",
         "--address", "0.0.0.0", "svc/agent", f"{bk.relay_host_port(div)}:8000"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _keycloak_port_forward(div: str, local: int) -> subprocess.Popen:
    return subprocess.Popen(
        ["kubectl", "--context", context(div), "-n", f"agt-div-{div}",
         "port-forward", "svc/keycloak", f"{local}:8080"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _port_open(port: int) -> bool:
    import socket
    s = socket.socket()
    s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def relay(divs: list[str]) -> None:
    """Hold the cross-cluster relay up: a host port-forward per division agent, auto-restarted
    on the flaky proxy aborts. Keep this running while you use the federated mesh."""
    procs: dict[str, subprocess.Popen] = {}
    print("Cross-cluster relay (host = L4 router between clusters). Ctrl+C to stop.\n")
    for d in divs:
        procs[d] = _agent_relay_pf(d)
        print(f"  {d}: host.docker.internal:{bk.relay_host_port(d)} -> {context(d)} svc/agent")
    print("\n  relay up — cross-cluster /a2a calls will route through the host.")
    try:
        while True:
            time.sleep(5)
            for d in divs:
                if procs[d].poll() is not None or not _port_open(bk.relay_host_port(d)):
                    procs[d].terminate()
                    procs[d] = _agent_relay_pf(d)  # restart a dead/stale forward
    except KeyboardInterrupt:
        print("\nstopping relay ...")
    finally:
        for p in procs.values():
            p.terminate()


def _token(div: str, kc_local: int) -> str:
    pw = _seed_password(div)
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "rag-ui",
                                   "username": "alice", "password": pw}).encode()
    url = f"http://localhost:{kc_local}/realms/rag/protocol/openid-connect/token"
    last: Exception | None = None
    for _ in range(10):
        try:
            return json.loads(urllib.request.urlopen(url, data=data, timeout=15).read())["access_token"]
        except Exception as exc:  # noqa: BLE001 — port-forward warmup
            last = exc
            time.sleep(2)
    raise RuntimeError(f"could not get token for {div}: {last}")


def _solve(div: str, agent_local: int, token: str, capability: str, arguments: dict) -> dict:
    body = json.dumps({"capability": capability, "arguments": arguments}).encode()
    req = urllib.request.Request(f"http://localhost:{agent_local}/solve", data=body,
                                 headers={"Authorization": f"Bearer {token}",
                                          "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def up(divs: list[str]) -> None:
    print(f"AGT multi-cluster bring-up: {', '.join(divs)} (one cluster per division)\n")
    print("[1/4] build the agent image once")
    bk.build_image(IMAGE, SRC_TAG)

    print("\n[2/4] create one kind cluster per division")
    for d in divs:
        create_cluster(d)

    print("\n[3/4] deploy each division into ITS OWN cluster")
    for d in divs:
        bk.bootstrap_division(context(d), IMAGE, d, SRC_TAG)

    print("\n[4/4] federate ACROSS clusters (routable URLs + DIDs)")
    bk.federate_multicluster({d: context(d) for d in divs})

    print()
    status(divs)
    print("\n  Start the cross-cluster relay (host = L4 router), then prove delegation:")
    print("    python scripts/multicluster.py relay  --divisions " + ",".join(divs) + "   # keep running")
    print("    python scripts/multicluster.py prove  --divisions " + ",".join(divs))


def down(divs: list[str]) -> None:
    print(f"Deleting clusters for: {', '.join(divs)}")
    for d in divs:
        delete_cluster(d)


def status(divs: list[str]) -> None:
    have = existing_clusters()
    print("  division   cluster (context)              agent     routable peer URL")
    print("  " + "-" * 72)
    for d in divs:
        name, ctx = cluster_name(d), context(d)
        if name not in have:
            print(f"  {d:<10} {name:<22} (no cluster)")
            continue
        ready = bk.kubectl(ctx, "-n", f"agt-div-{d}", "get", "deploy/agent",
                           "-o", "jsonpath={.status.readyReplicas}", check=False, capture=True).strip()
        agent = "UP" if ready and ready != "0" else "down"
        print(f"  {d:<10} {name:<22} kind-{name:<6} {agent:<9} {bk.relay_url(d)}")
    print("\n  Each division is a SEPARATE cluster, federated over the routable URLs above.")
    print("  Cross-cluster routing needs the relay running (host = L4 router):")
    print("    python scripts/multicluster.py relay --divisions " + ",".join(divs))
    print("  Prove cross-cluster delegation:  python scripts/multicluster.py prove --divisions " + ",".join(divs))


def prove(divs: list[str]) -> None:
    """Live proof: for each division, call a capability it does NOT serve locally so it must
    DELEGATE to the peer that owns it — in another cluster — over the signed /a2a/tool channel.
    Reads each division's PEER_TOOL_MAP to pick a genuinely-delegated capability."""
    import federate_divisions as fd

    facts = {d: fd.DivisionFacts(bk.od.load_manifest(ROOT / "infra" / "divisions" / f"{d}.yml"))
             for d in divs}
    # capability -> example arguments (deterministic governed tools)
    args_for = {
        "tool.pii": {"text": "email alice@example.com, card 4242424242424242"},
        "tool.compliance": {"topic": "data retention"},
        "tool.risk": {"description": "wire $2M to a new offshore counterparty"},
        "tool.classify": {"text": "internal board minutes — restricted"},
        "tool.fincheck": {"amount": 250000, "currency": "USD", "counterparty": "Acme Holdings"},
    }
    print(f"=== Cross-cluster tool delegation proof: {', '.join(divs)} ===\n")
    # The relay (host = L4 router) must be up so the delegating agent can reach its peer's
    # agent at host.docker.internal:<relay-port>. Start one per division and hold them.
    relays = [_agent_relay_pf(d) for d in divs]
    time.sleep(10)
    any_proved = False
    try:
        for i, d in enumerate(divs):
            tool_map = fd.compute_peer_tool_map(facts[d], facts)
            if not tool_map:
                print(f"  {d}: serves all needed tools locally — nothing to delegate")
                continue
            cap = next(iter(tool_map))
            owner = next((p for p in divs if facts[p].did_jwk()[0] == tool_map[cap]), "?")
            # Mint the token on the division's DERIVED keycloak port so the stamped issuer
            # (http://localhost:<kc>/realms/rag) matches the agent's OIDC_ISSUER — else 401.
            kc_local = bk.port_base(d) + 2
            kc = _keycloak_port_forward(d, kc_local)
            time.sleep(7)
            try:
                token = _token(d, kc_local)
                # Call the DELEGATING agent via its own relay host port (also reachable on
                # localhost); it routes `cap` to the owner over host.docker.internal.
                res = _solve(d, bk.relay_host_port(d), token, cap, args_for.get(cap, {}))
                ok = res.get("status") == "completed"
                src = res.get("source", "?")
                print(f"  {d} (cluster agt-{d})  --{cap}-->  {owner} (cluster agt-{owner})")
                print(f"     status={res.get('status')}  source={src}  "
                      f"{'OK delegated cross-cluster' if ok and src == 'peer' else ''}")
                any_proved = any_proved or (ok and src == "peer")
            except Exception as exc:  # noqa: BLE001
                print(f"  {d} -> {owner}: ERR {type(exc).__name__} {exc}")
            finally:
                kc.terminate()
            time.sleep(2)
    finally:
        for p in relays:
            p.terminate()
    print("\n" + ("PROVEN: a capability was delegated across clusters over the signed /a2a/tool channel."
                  if any_proved else "No cross-cluster delegation observed — is the relay reachable?"))


def main() -> int:
    ap = argparse.ArgumentParser(description="AGT multi-cluster bring-up (one cluster per division)")
    ap.add_argument("action", choices=["up", "down", "status", "prove", "relay"])
    ap.add_argument("--divisions", default="gamma,delta", help="comma-separated division ids")
    args = ap.parse_args()
    divs = [d.strip() for d in args.divisions.split(",") if d.strip()]
    if len(divs) < 2 and args.action in ("up", "prove", "relay"):
        print("multi-cluster needs at least 2 divisions", file=sys.stderr)
        return 2
    {"up": up, "down": down, "status": status, "prove": prove, "relay": relay}[args.action](divs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
