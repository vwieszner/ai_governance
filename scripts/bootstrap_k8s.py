"""Turnkey Kubernetes bring-up for AGT federated-RAG divisions (cross-platform).

Parity with the Compose bootstrap, on Kubernetes — for each division:
  load image into the cluster -> mint per-division secrets -> kubectl apply -k overlay
  -> create the agent-secrets Secret -> wait for the data plane -> provision (OpenFGA
  store/model + Keycloak realm/users/roles + DOC INGEST + DID, by running
  scripts/k8s_provision.py over short-lived port-forwards) -> complete the Secret with the
  store/model ids -> restart agent+worker -> verify /health.

TRANSPARENCY: this spawns no hidden processes and force-kills no arbitrary PIDs. Port-forwards
are ordinary child processes started with subprocess.Popen and stopped with .terminate(). It
only runs `docker`, `kind`, `kubectl`, and `python scripts/k8s_provision.py`. No downloads, no
obfuscation, no system/registry changes — plain, readable orchestration. (Rewritten from the
earlier PowerShell version, which a behavioral AV heuristic false-flagged for using hidden
windows + Stop-Process; this Python version avoids both and is cross-platform.)

Usage:
  python scripts/bootstrap_k8s.py --divisions gamma
  python scripts/bootstrap_k8s.py --divisions alpha,beta --context kind-agt
Ports note: provisioning reaches the cluster over each division's DERIVED host ports (so it
reuses the tested provision() unchanged); don't run the SAME division under Compose at the
same time (different divisions on different port bands are fine).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "agt-federated-rag"))
import onboard_division as od  # noqa: E402

VENV_PY = str(od.VENV_PY)


def run(cmd: list[str], check: bool = True, capture: bool = False, stdin: str | None = None) -> str:
    r = subprocess.run(cmd, cwd=str(ROOT), text=True, input=stdin,
                       capture_output=True if capture else False)
    if capture and r.returncode != 0 and check:
        sys.stderr.write(r.stdout + r.stderr)
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(cmd)}")
    return (r.stdout or "") if capture else ""


def kubectl(ctx: str, *args: str, check: bool = True, capture: bool = False, stdin: str | None = None) -> str:
    return run(["kubectl", "--context", ctx, *args], check=check, capture=capture, stdin=stdin)


def port_base(div: str) -> int:
    for line in (ROOT / "infra" / "divisions" / f"{div}.yml").read_text().splitlines():
        s = line.strip()
        if s.startswith("port_base:"):
            return int(s.split(":", 1)[1].split("#")[0].strip())
    raise RuntimeError(f"no port_base in {div}.yml")


def make_secret_yaml(ctx: str, ns: str, div: str, store: str | None, model: str | None) -> str:
    s = json.loads((ROOT / "infra" / "generated" / div / "secrets.json").read_text())
    nv = ""
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith("NVIDIA_API_KEY="):
            nv = line.split("=", 1)[1].strip()
    lits = {
        "OPENAI_API_KEY": nv, "EMBEDDING_API_KEY": nv, "POSTGRES_USER": "openfga",
        "POSTGRES_PASSWORD": s["postgres_password"], "OPENFGA_API_TOKEN": s["openfga_api_token"],
        "KEYCLOAK_ADMIN": "admin", "KEYCLOAK_ADMIN_PASSWORD": s["keycloak_admin_password"],
        "AGENT_CLIENT_SECRET": s["agent_client_secret"], "APPROVAL_HMAC_SECRET": s["approval_hmac_secret"],
    }
    if store:
        lits["OPENFGA_STORE_ID"] = store
    if model:
        lits["OPENFGA_MODEL_ID"] = model
    args = ["create", "secret", "generic", "agent-secrets", "-n", ns]
    for k, v in lits.items():
        args += [f"--from-literal={k}={v}"]
    args += ["--dry-run=client", "-o", "yaml"]
    return kubectl(ctx, *args, capture=True)


@contextmanager
def port_forwards(ctx: str, ns: str, mappings: list[tuple[str, int, int]]):
    """Start `kubectl port-forward` children (plain subprocesses); terminate on exit."""
    procs = []
    try:
        for svc, local, remote in mappings:
            procs.append(subprocess.Popen(
                ["kubectl", "--context", ctx, "-n", ns, "port-forward", f"svc/{svc}", f"{local}:{remote}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(8)
        yield
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()


def wait_rollout(ctx: str, ns: str) -> None:
    # StatefulSets + Deployments that make up the data plane.
    for kind, name in [("statefulset", "postgres"), ("deployment", "openfga"),
                       ("statefulset", "keycloak"), ("statefulset", "qdrant"),
                       ("statefulset", "temporal"), ("statefulset", "redis")]:
        kubectl(ctx, "-n", ns, "rollout", "status", f"{kind}/{name}", "--timeout=180s", check=False)


def health(base: int) -> str:
    try:
        with urllib.request.urlopen(f"http://localhost:{base}/health", timeout=10) as r:
            return r.read().decode()
    except Exception as exc:  # noqa: BLE001
        return f"<not ready: {exc}>"


def bootstrap_division(ctx: str, image: str, div: str) -> None:
    ns = f"agt-div-{div}"
    base = port_base(div)
    p = od.derive_ports(base)
    print(f"\n=== Division '{div}' (namespace {ns}, ports {base}..{base + 6}) ===")

    print("-> load agent image into the cluster")
    src = f"{image}:alpha"
    if subprocess.run(["docker", "image", "inspect", src], capture_output=True).returncode != 0:
        src = f"{image}:latest"
    run(["docker", "tag", src, f"{image}:{div}"], check=False)
    cluster = ctx[5:] if ctx.startswith("kind-") else ctx
    run([str(ROOT / ".tools" / "kind.exe"), "load", "docker-image", f"{image}:{div}", "--name", cluster], check=False)

    print("-> mint/load per-division secrets")
    od._load_or_make_secrets(div)

    print(f"-> kubectl apply -k k8s/overlays/{div}")
    kubectl(ctx, "apply", "-k", f"k8s/overlays/{div}", "--validate=false")
    kubectl(ctx, "apply", "-f", "-", stdin=make_secret_yaml(ctx, ns, div, None, None))

    print("-> wait for the data plane")
    wait_rollout(ctx, ns)

    print("-> provision (store/model + realm/users/roles + ingest + DID) over port-forwards")
    maps = [("openfga", p["openfga"], 8080), ("keycloak", p["keycloak"], 8080),
            ("qdrant", p["qdrant"], 6333), ("temporal", p["temporal_ui"], 8233),
            ("redis", p["redis"], 6379)]
    store = model = None
    with port_forwards(ctx, ns, maps):
        out = run([VENV_PY, "scripts/k8s_provision.py", div], capture=True)
        print(out.strip())
        for line in out.splitlines():
            if line.startswith("STORE_ID="):
                store = line.split("=", 1)[1].strip()
            if line.startswith("MODEL_ID="):
                model = line.split("=", 1)[1].strip()
    if not store:
        raise RuntimeError(f"provisioning returned no STORE_ID for '{div}'")

    print("-> complete the Secret with store/model + restart agent & worker")
    kubectl(ctx, "apply", "-f", "-", stdin=make_secret_yaml(ctx, ns, div, store, model))
    kubectl(ctx, "-n", ns, "rollout", "restart", "deploy/agent", "deploy/worker")
    kubectl(ctx, "-n", ns, "rollout", "status", "deploy/agent", "--timeout=120s", check=False)

    print("-> verify agent /health")
    with port_forwards(ctx, ns, [("agent", base, 8000)]):
        print(f"   /health -> {health(base)}")


def federate(ctx: str, divisions: list[str]) -> None:
    """Cross-wire DID trust + cross-grants between k8s divisions (turnkey federation).

    Reuses federate_divisions' DivisionFacts + _apply_cross_grants (the exact tested logic).
    The two k8s-specific bits: (1) mount each division's PROVISIONED DID identity so the
    running agent's DID matches the trust map (instead of a pod-generated ephemeral DID);
    (2) the peer agent_url is the cross-namespace Service DNS that the allow-agent-federation
    NetworkPolicy permits. Issuers stay unique per division (each division's
    http://localhost:<kc-port> issuer), while JWKS is fetched in-cluster.
    """
    import asyncio
    import json as _json
    import federate_divisions as fd

    print(f"\n=== Federating divisions: {', '.join(divisions)} ===")
    facts = {d: fd.DivisionFacts(od.load_manifest(ROOT / "infra" / "divisions" / f"{d}.yml")) for d in divisions}
    for d in divisions:
        if not facts[d].onboarded:
            raise RuntimeError(f"division '{d}' not onboarded (run bootstrap_k8s for it first)")

    # 1) Mount each division's stable DID identity as a Secret + point the agent at it.
    print("-> mount stable DID identities")
    for d in divisions:
        ns = f"agt-div-{d}"
        idfile = ROOT / "agt-federated-rag" / f"agent_identity_{d}.json"
        y = kubectl(ctx, "-n", ns, "create", "secret", "generic", "agent-identity",
                    f"--from-file=agent_identity.json={idfile}", "--dry-run=client", "-o", "yaml", capture=True)
        kubectl(ctx, "apply", "-f", "-", stdin=y)

    # 2) Per division: patch its ConfigMap with the peer trust map + the unique issuer,
    #    and patch the agent/worker Deployments to mount the identity Secret.
    print("-> wire peer trust map + identity mount into each division")
    for d in divisions:
        ns = f"agt-div-{d}"
        peers = [p for p in divisions if p != d]
        trust = {}
        for p in peers:
            pdid, pjwk = facts[p].did_jwk()
            trust[pdid] = {"issuer": facts[p].issuer,
                           "public_jwk": _json.loads(pjwk),
                           "agent_url": f"http://agent.agt-div-{p}.svc.cluster.local:8000",
                           "division_id": p}
        primary = peers[0]
        pdid, pjwk = facts[primary].did_jwk()
        cm_patch = {"data": {
            "PEER_AGENT_URL": f"http://agent.agt-div-{primary}.svc.cluster.local:8000",
            "PEER_AGENT_DID": pdid,
            "PEER_AGENT_PUBLIC_JWK": pjwk,
            "PEER_AGENT_ISSUER": facts[primary].issuer,
            "TRUSTED_ISSUERS": ",".join(facts[p].issuer for p in peers),
            "PEER_TRUST_MAP": _json.dumps(trust, separators=(",", ":")),
            "OIDC_ISSUER": facts[d].issuer,                       # unique per division
            "AGENT_IDENTITY_PATH": "/identity/agent_identity.json",
        }}
        kubectl(ctx, "-n", ns, "patch", "configmap", "agent-config", "--type=merge",
                "-p", _json.dumps(cm_patch))
        # Mount the identity Secret read-only into agent + worker.
        vol_patch = {"spec": {"template": {"spec": {
            "volumes": [{"name": "agent-identity", "secret": {"secretName": "agent-identity"}}],
            "containers": [{"name": "$NAME", "volumeMounts":
                            [{"name": "agent-identity", "mountPath": "/identity", "readOnly": True}]}],
        }}}}
        for dep, cname in (("agent", "agent"), ("worker", "worker")):
            patch = _json.loads(_json.dumps(vol_patch).replace("$NAME", cname))
            kubectl(ctx, "-n", ns, "patch", "deployment", dep, "--type=strategic", "-p", _json.dumps(patch))

    # 3) Apply each division's cross_grants to its OWN OpenFGA (reuse the tested writer),
    #    over a port-forward to that division's OpenFGA + Qdrant.
    print("-> apply cross-grants")
    by_id = facts
    for d in divisions:
        if not facts[d].m.cross_grants:
            continue
        ns = f"agt-div-{d}"
        p = facts[d].ports
        with port_forwards(ctx, ns, [("openfga", p["openfga"], 8080), ("qdrant", p["qdrant"], 6333)]):
            asyncio.run(fd._apply_cross_grants(facts[d], by_id, dry_run=False))

    # 4) Restart agents/workers so they load the identity + peer config.
    print("-> restart agents to pick up peers")
    for d in divisions:
        ns = f"agt-div-{d}"
        kubectl(ctx, "-n", ns, "rollout", "restart", "deploy/agent", "deploy/worker")
    for d in divisions:
        kubectl(ctx, "-n", f"agt-div-{d}", "rollout", "status", "deploy/agent", "--timeout=120s", check=False)
    print("Federation complete: each division trusts its peers' DIDs and holds the cross-grants.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--divisions", default="gamma", help="comma-separated division ids")
    ap.add_argument("--context", default="kind-agt")
    ap.add_argument("--image", default="agt-federated-rag")
    ap.add_argument("--federate", action="store_true",
                    help="after bring-up, cross-wire DID trust + cross-grants between the divisions")
    args = ap.parse_args()
    divs = [d.strip() for d in args.divisions.split(",") if d.strip()]
    for div in divs:
        bootstrap_division(args.context, args.image, div)
    if args.federate and len(divs) > 1:
        federate(args.context, divs)
    print(f"\nDone. Divisions on Kubernetes: {args.divisions}"
          + (" (federated)" if args.federate and len(divs) > 1 else "") + ".")


if __name__ == "__main__":
    main()
