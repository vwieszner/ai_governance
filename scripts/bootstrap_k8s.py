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
import os
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


def run(cmd: list[str], check: bool = True, capture: bool = False, stdin: str | None = None,
        env: dict | None = None) -> str:
    r = subprocess.run(cmd, cwd=str(ROOT), text=True, input=stdin, env=env,
                       capture_output=True if capture else False)
    if capture and r.returncode != 0 and check:
        sys.stderr.write(r.stdout + r.stderr)
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(cmd)}")
    return (r.stdout or "") if capture else ""


# Transient kubectl-over-proxy failures on this host (Norton MITM): the connection is
# occasionally aborted mid-handshake. CLAUDE.md flags this — retry rather than fail the run.
_TRANSIENT = ("wsarecv", "connection was aborted", "tls handshake", "unexpected eof",
              "i/o timeout", "connection reset", "couldn't get current server")


def kubectl(ctx: str, *args: str, check: bool = True, capture: bool = False, stdin: str | None = None) -> str:
    """kubectl with retry on transient TLS/connection aborts (Norton proxy flakiness).

    Always captures internally so a transient failure can be detected and retried; returns
    stdout when capture=True (else ""), preserving the previous contract for callers."""
    last = ""
    for attempt in range(5):
        r = subprocess.run(["kubectl", "--context", ctx, *args], cwd=str(ROOT), text=True,
                           input=stdin, capture_output=True)
        if r.returncode == 0:
            return r.stdout or ""
        last = (r.stdout or "") + (r.stderr or "")
        if attempt < 4 and any(t in last.lower() for t in _TRANSIENT):
            time.sleep(2)
            continue
        break
    if check:
        sys.stderr.write(last)
        raise RuntimeError(f"command failed: kubectl {' '.join(args)}")
    return last if capture else ""


def port_base(div: str) -> int:
    for line in (ROOT / "infra" / "divisions" / f"{div}.yml").read_text().splitlines():
        s = line.strip()
        if s.startswith("port_base:"):
            return int(s.split(":", 1)[1].split("#")[0].strip())
    raise RuntimeError(f"no port_base in {div}.yml")


def nvidia_key() -> str:
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith("NVIDIA_API_KEY="):
            return line.split("=", 1)[1].strip()
    return ""


def ingest_embedding_env(ctx: str, ns: str) -> dict[str, str]:
    """The embedding config the HOST-side ingest must use, taken from the DEPLOYED configmap
    (so it matches the cluster) + the NVIDIA key. Without this the ingest falls back to the
    local FastEmbed model, which tries to reach HuggingFace and fails on this network (and is
    blocked by Norton anyway) — the documented 'set EMBEDDING_PROVIDER=api on the host' gotcha.
    Env vars override the regenerated .env.<div>, so this forces the served API embedder."""
    cfg = json.loads(kubectl(ctx, "-n", ns, "get", "configmap", "agent-config", "-o", "json",
                             capture=True) or "{}").get("data", {})
    emb = {k: v for k, v in cfg.items()
           if k.startswith("EMBEDDING_") or k in ("QDRANT_SCORE_THRESHOLD",)}
    key = nvidia_key()
    if key:
        emb["EMBEDDING_API_KEY"] = key
    return emb


def make_secret_yaml(ctx: str, ns: str, div: str, store: str | None, model: str | None) -> str:
    s = json.loads((ROOT / "infra" / "generated" / div / "secrets.json").read_text())
    nv = nvidia_key()
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


def build_image(image: str, source_tag: str) -> None:
    """Build the agent image ONCE from the current source into {image}:{source_tag}.

    This is the fix for the per-division image-tag CLOBBER: the old code re-tagged each
    division from {image}:alpha (a possibly-stale image), so `--divisions <id>` could deploy
    OLD code even after you changed the source. Building fresh into a dedicated source tag,
    then tagging each division from THAT, guarantees a division always runs current code."""
    print(f"-> build agent image {image}:{source_tag} from current source")
    run(["docker", "build", "-t", f"{image}:{source_tag}", str(ROOT / "agt-federated-rag")])


def bootstrap_division(ctx: str, image: str, div: str, source_tag: str) -> None:
    ns = f"agt-div-{div}"
    base = port_base(div)
    p = od.derive_ports(base)
    print(f"\n=== Division '{div}' (namespace {ns}, ports {base}..{base + 6}) ===")

    print("-> load agent image into the cluster")
    # Tag this division from the chosen SOURCE tag (a fresh build by default — see
    # build_image / --no-build), NEVER blindly from :alpha. Fail loudly if the source is
    # missing so we don't silently deploy a stale/absent image.
    src = f"{image}:{source_tag}"
    if subprocess.run(["docker", "image", "inspect", src], capture_output=True).returncode != 0:
        raise RuntimeError(
            f"source image {src} not found — run with --build (default) to build it, "
            f"or --source-tag <tag> to point at an existing image."
        )
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
    # Force the host-side doc ingest to use the SERVED API embedder (matching the cluster's
    # configmap), not the local FastEmbed model — see ingest_embedding_env.
    prov_env = {**os.environ, **ingest_embedding_env(ctx, ns)}
    with port_forwards(ctx, ns, maps):
        out = run([VENV_PY, "scripts/k8s_provision.py", div], capture=True, env=prov_env)
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
        # Governed cross-agent TOOL wiring (capability-based delegation), derived from
        # the manifests' local_tools so a fresh `--federate` is always correctly wired:
        #   * AGT_LOCAL_TOOLS — the capabilities THIS division serves locally (manifest
        #     local_tools). Absent (None) => leave the base ConfigMap default (serve ALL);
        #     an explicit list (incl. []) is asserted so a consumer truly serves none.
        #   * PEER_TOOL_MAP — capability -> provider-peer DID for every capability this
        #     division LACKS but a trusted peer serves (fd.compute_peer_tool_map). The DID
        #     is resolved against PEER_TRUST_MAP above (correct cross-namespace agent_url),
        #     so delegation needs no discovery broker. Reuses the SAME helper as the compose
        #     federate path — identical wiring, two deployment targets.
        if facts[d].m.local_tools is not None:
            cm_patch["data"]["AGT_LOCAL_TOOLS"] = ",".join(facts[d].m.local_tools)
        tool_map = fd.compute_peer_tool_map(facts[d], facts)
        if tool_map:
            cm_patch["data"]["PEER_TOOL_MAP"] = _json.dumps(tool_map, separators=(",", ":"))
            print(f"   {d}: tool routing {', '.join(f'{c}->{t[:18]}…' for c, t in tool_map.items())}")
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


def relay_host_port(div: str) -> int:
    """Stable host port used as the cross-cluster relay for a division's agent (port_base +
    30000 — unique per division, well clear of the derived service ports). On the local kind
    setup the HOST is the L4 router between otherwise-isolated clusters (the analogue of a
    cloud LoadBalancer): each division's agent is port-forwarded to this host port, and peers
    reach it at http://host.docker.internal:<this> (host.docker.internal resolves from kind
    pods). See multicluster.py's `relay` supervisor."""
    return port_base(div) + 30000


def relay_url(div: str) -> str:
    return f"http://host.docker.internal:{relay_host_port(div)}"


def federate_multicluster(div_ctx: dict[str, str]) -> None:
    """Federate divisions that live in SEPARATE clusters (one cluster per division).

    Identical TRUST MODEL to federate() — reuses fd.DivisionFacts / compute_peer_tool_map /
    _apply_cross_grants unchanged — but each division is reached at a ROUTABLE cross-cluster
    URL instead of the in-cluster Service DNS, and each division's ConfigMap/cross-grants are
    applied in its OWN kube-context. This is the multi-cluster (multi-cloud-shaped) expression
    of the same federation.

    Routable URL on local kind: http://host.docker.internal:<relay-port>. On this host the
    clusters' pod/Service networks don't traverse the Docker bridge (kindnet iptables routing
    is inert cross-cluster), but every pod CAN reach the host, and the host can reach every
    cluster (kubectl port-forward) — so the host acts as the L4 router between clusters (run
    `multicluster.py relay`). In a real multi-cloud deploy this URL is the agent's
    LoadBalancer/Ingress hostname instead — same wiring (see k8s/MULTICLUSTER.md).

    `div_ctx` maps division id -> kube context (e.g. {"gamma": "kind-agt-gamma", ...}).
    """
    import asyncio
    import json as _json

    import federate_divisions as fd

    divisions = list(div_ctx)
    print(f"\n=== Federating ACROSS clusters: {', '.join(divisions)} ===")
    facts = {d: fd.DivisionFacts(od.load_manifest(ROOT / "infra" / "divisions" / f"{d}.yml"))
             for d in divisions}
    for d in divisions:
        if not facts[d].onboarded:
            raise RuntimeError(f"division '{d}' not onboarded (bootstrap it first)")

    # 1) Resolve each division's routable (cross-cluster) URL via the host relay.
    print("-> resolve routable peer URLs (host relay)")
    ext_url: dict[str, str] = {d: relay_url(d) for d in divisions}
    for d in divisions:
        print(f"   {d}: {ext_url[d]}  (ctx {div_ctx[d]})")

    # 2) Mount each division's stable DID identity as a Secret (in its own cluster).
    print("-> mount stable DID identities")
    for d in divisions:
        ctx, ns = div_ctx[d], f"agt-div-{d}"
        idfile = ROOT / "agt-federated-rag" / f"agent_identity_{d}.json"
        y = kubectl(ctx, "-n", ns, "create", "secret", "generic", "agent-identity",
                    f"--from-file=agent_identity.json={idfile}", "--dry-run=client", "-o", "yaml",
                    capture=True)
        kubectl(ctx, "apply", "-f", "-", stdin=y)

    # 3) Wire each division's peer trust map (ROUTABLE urls) + tool routing + identity mount.
    print("-> wire peer trust map + tool routing into each division")
    for d in divisions:
        ctx, ns = div_ctx[d], f"agt-div-{d}"
        peers = [p for p in divisions if p != d]
        trust: dict[str, dict] = {}
        for p in peers:
            pdid, pjwk = facts[p].did_jwk()
            while isinstance(pjwk, str):
                pjwk = _json.loads(pjwk)
            trust[pdid] = {"issuer": facts[p].issuer, "public_jwk": pjwk,
                           "agent_url": ext_url[p], "division_id": p}
        primary = peers[0]
        pdid, pjwk_s = facts[primary].did_jwk()
        cm_patch = {"data": {
            "PEER_AGENT_URL": ext_url[primary],
            "PEER_AGENT_DID": pdid,
            "PEER_AGENT_PUBLIC_JWK": pjwk_s,
            "PEER_AGENT_ISSUER": facts[primary].issuer,
            "TRUSTED_ISSUERS": ",".join(facts[p].issuer for p in peers),
            "PEER_TRUST_MAP": _json.dumps(trust, separators=(",", ":")),
            "OIDC_ISSUER": facts[d].issuer,                       # unique per division
            "AGENT_IDENTITY_PATH": "/identity/agent_identity.json",
        }}
        if facts[d].m.local_tools is not None:
            cm_patch["data"]["AGT_LOCAL_TOOLS"] = ",".join(facts[d].m.local_tools)
        tool_map = fd.compute_peer_tool_map(facts[d], facts)
        if tool_map:
            cm_patch["data"]["PEER_TOOL_MAP"] = _json.dumps(tool_map, separators=(",", ":"))
            print(f"   {d}: tool routing {', '.join(f'{c}->{t[:14]}…' for c, t in tool_map.items())}")
        kubectl(ctx, "-n", ns, "patch", "configmap", "agent-config", "--type=merge",
                "-p", _json.dumps(cm_patch))
        vol_patch = {"spec": {"template": {"spec": {
            "volumes": [{"name": "agent-identity", "secret": {"secretName": "agent-identity"}}],
            "containers": [{"name": "$NAME", "volumeMounts":
                            [{"name": "agent-identity", "mountPath": "/identity", "readOnly": True}]}],
        }}}}
        for dep, cname in (("agent", "agent"), ("worker", "worker")):
            patch = _json.loads(_json.dumps(vol_patch).replace("$NAME", cname))
            kubectl(ctx, "-n", ns, "patch", "deployment", dep, "--type=strategic", "-p", _json.dumps(patch))

    # 4) Apply each division's cross-grants to its OWN OpenFGA (in its own cluster).
    print("-> apply cross-grants")
    for d in divisions:
        if not facts[d].m.cross_grants:
            continue
        ctx, ns = div_ctx[d], f"agt-div-{d}"
        p = facts[d].ports
        with port_forwards(ctx, ns, [("openfga", p["openfga"], 8080), ("qdrant", p["qdrant"], 6333)]):
            asyncio.run(fd._apply_cross_grants(facts[d], facts, dry_run=False))

    # 5) Restart agents/workers so they load identity + peer config.
    print("-> restart agents to pick up peers")
    for d in divisions:
        ctx, ns = div_ctx[d], f"agt-div-{d}"
        kubectl(ctx, "-n", ns, "rollout", "restart", "deploy/agent", "deploy/worker")
    for d in divisions:
        kubectl(div_ctx[d], "-n", f"agt-div-{d}", "rollout", "status", "deploy/agent",
                "--timeout=120s", check=False)
    print("Cross-cluster federation complete: each division trusts its peers' DIDs over routable URLs.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--divisions", default="gamma", help="comma-separated division ids")
    ap.add_argument("--context", default="kind-agt")
    ap.add_argument("--image", default="agt-federated-rag")
    ap.add_argument("--federate", action="store_true",
                    help="after bring-up, cross-wire DID trust + cross-grants between the divisions")
    ap.add_argument("--source-tag", default="src",
                    help="image tag to deploy each division FROM (default 'src', built fresh unless --no-build)")
    ap.add_argument("--no-build", dest="build", action="store_false",
                    help="skip building; tag divisions from the existing --source-tag image")
    ap.set_defaults(build=True)
    args = ap.parse_args()
    divs = [d.strip() for d in args.divisions.split(",") if d.strip()]
    # Build ONCE from current source (the fix for the per-division stale-image clobber), then
    # every division is tagged from this fresh image. --no-build reuses --source-tag as-is.
    if args.build:
        build_image(args.image, args.source_tag)
    for div in divs:
        bootstrap_division(args.context, args.image, div, args.source_tag)
    if args.federate and len(divs) > 1:
        federate(args.context, divs)
    print(f"\nDone. Divisions on Kubernetes: {args.divisions}"
          + (" (federated)" if args.federate and len(divs) > 1 else "") + ".")


if __name__ == "__main__":
    main()
