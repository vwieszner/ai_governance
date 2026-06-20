"""Orchestrate a PRODUCTION-REPRESENTATIVE load benchmark on the kind cluster.

``load_bench.py`` drives the agent from the host through a ``kubectl port-forward`` — which
serializes every request through one localhost TCP proxy and caps throughput at ~18 rps no
matter how fast the backend is. That number characterizes the DEV RIG, not the system.

This runner removes the dev-rig distortions and measures the system itself:

  1. (optional) scales the agent Deployment to ``--replicas`` so the in-cluster Service
     load-balances across N pods (horizontal scale-out).
  2. (optional, ``--raise-limit``) temporarily raises the per-subject anti-abuse rate limit
     (``RATE_LIMIT_PER_MINUTE``) so a single benchmark user can drive sustained load to find
     the real throughput ceiling — and RESTORES it afterwards (always, in a finally).
  3. runs ``bench.incluster_load`` as a Kubernetes Job INSIDE the namespace, hitting the agent
     ClusterIP directly (``http://agent:8000``) — no port-forward in the path.
  4. collects the JSON result from the Job logs, prints a table, writes
     ``bench/results_incluster.json``, and tears down the Job + ConfigMap + credential Secret.

Everything it mutates on the cluster (replica count, rate limit) is restored on exit, so the
cluster is left exactly as it was found. Run from inside ``agt-federated-rag``::

    ../.venv/Scripts/python.exe -m bench.run_incluster_bench --division gamma \
        --replicas 3 --raise-limit --mode sweep --levels 1,8,16,32,64,128,256 --total 1500

Seed-user password is read from ``infra/generated/<div>/secrets.json`` (gitignored) and passed
to the Job via a transient Secret — never printed, never written to the manifest.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = Path(__file__).resolve().parent
CTX = "kind-agt"
JOB = "bench-load"
CM = "bench-load"
SECRET = "bench-cred"
_RESULTS = BENCH_DIR / "results_incluster.json"


def _kubectl(*args: str, check: bool = True, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["kubectl", "--context", CTX, *args], check=check, text=True,
                          input=stdin, capture_output=True)


def _ns(div: str) -> str:
    return f"agt-div-{div}"


def _agent_image(ns: str) -> str:
    return _kubectl("-n", ns, "get", "deploy/agent",
                    "-o", "jsonpath={.spec.template.spec.containers[0].image}").stdout.strip()


def _seed_password(div: str) -> str:
    return json.loads((ROOT / "infra" / "generated" / div / "secrets.json").read_text())["seed_user_password"]


def _issuer_host(ns: str) -> str:
    """The host:port the agent expects in the token's `iss` (from the deployed OIDC_ISSUER) —
    so the in-cluster token request can present it as the Host header. Not hardcoded: read
    from the live agent-config ConfigMap."""
    out = _kubectl("-n", ns, "get", "configmap", "agent-config",
                   "-o", "jsonpath={.data.OIDC_ISSUER}").stdout.strip()
    return urllib.parse.urlparse(out).netloc if out else ""


def _current_replicas(ns: str) -> int:
    out = _kubectl("-n", ns, "get", "deploy/agent", "-o", "jsonpath={.spec.replicas}").stdout.strip()
    return int(out or "1")


def _current_rate_limit(ns: str) -> str | None:
    """Return the RATE_LIMIT_PER_MINUTE currently set as an explicit container env, or None
    (meaning it falls back to the app default 60) — so we can restore it precisely."""
    out = _kubectl("-n", ns, "get", "deploy/agent", "-o",
                   "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='RATE_LIMIT_PER_MINUTE')].value}").stdout.strip()
    return out or None


def _set_rate_limit(ns: str, value: str | None) -> None:
    if value is None:
        _kubectl("-n", ns, "set", "env", "deploy/agent", "RATE_LIMIT_PER_MINUTE-", check=False)
    else:
        _kubectl("-n", ns, "set", "env", "deploy/agent", f"RATE_LIMIT_PER_MINUTE={value}")
    _kubectl("-n", ns, "rollout", "status", "deploy/agent", "--timeout=120s", check=False)


def _apply_configmap(ns: str) -> None:
    files = ["__init__.py", "load_bench.py", "incluster_load.py"]
    args = ["-n", ns, "create", "configmap", CM]
    for f in files:
        args += [f"--from-file={f}={BENCH_DIR / f}"]
    args += ["--dry-run=client", "-o", "yaml"]
    y = _kubectl(*args).stdout
    _kubectl("apply", "-f", "-", stdin=y)


def _apply_secret(ns: str, password: str) -> None:
    y = _kubectl("-n", ns, "create", "secret", "generic", SECRET,
                 f"--from-literal=password={password}", "--dry-run=client", "-o", "yaml").stdout
    _kubectl("apply", "-f", "-", stdin=y)


def _job_manifest(ns: str, image: str, env: dict[str, str]) -> str:
    container_env = [{"name": k, "value": v} for k, v in env.items()]
    container_env.append({"name": "PASSWORD",
                          "valueFrom": {"secretKeyRef": {"name": SECRET, "key": "password"}}})
    manifest = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB, "namespace": ns},
        "spec": {
            "backoffLimit": 0, "ttlSecondsAfterFinished": 600,
            "template": {"spec": {
                "restartPolicy": "Never",
                "containers": [{
                    "name": "load", "image": image, "imagePullPolicy": "IfNotPresent",
                    "workingDir": "/work",
                    "command": ["python", "-m", "bench.incluster_load"],
                    "env": container_env,
                    "volumeMounts": [{"name": "bench", "mountPath": "/work/bench"}],
                }],
                "volumes": [{"name": "bench", "configMap": {"name": CM}}],
            }},
        },
    }
    return json.dumps(manifest)


def _wait_job(ns: str, timeout_s: int) -> str:
    """Poll the Job to Complete/Fail; return 'complete' | 'failed' | 'timeout'."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        out = _kubectl("-n", ns, "get", "job", JOB, "-o",
                       "jsonpath={.status.succeeded}|{.status.failed}", check=False).stdout.strip()
        succeeded, _, failed = out.partition("|")
        if succeeded.strip() == "1":
            return "complete"
        if failed.strip() and failed.strip() != "0":
            return "failed"
        time.sleep(3)
    return "timeout"


def _extract_result(logs: str) -> dict | None:
    if "<<<RESULT" not in logs or "RESULT>>>" not in logs:
        return None
    body = logs.split("<<<RESULT", 1)[1].split("RESULT>>>", 1)[0].strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def _cleanup(ns: str) -> None:
    for kind, name in (("job", JOB), ("configmap", CM), ("secret", SECRET)):
        _kubectl("-n", ns, "delete", kind, name, "--ignore-not-found", check=False)


def _print_report(result: dict) -> None:
    print(f"\n=== IN-CLUSTER LOAD — {result['mode']} (no port-forward; target {result['target']}) ===")
    print(f"  capability={result.get('capability')}  (deterministic governed path, no LLM)")
    if result["mode"] == "sweep_incluster":
        print(f"  {'conc':>5} {'rps':>9} {'p50ms':>9} {'p95ms':>9} {'p99ms':>9} {'err':>5} {'429':>5}")
        print("  " + "-" * 56)
        for row in result["levels"]:
            s = row["stats"]
            print(f"  {row['concurrency']:>5} {s['throughput_rps']:>9.1f} {s['p50']:>9.1f} "
                  f"{s['p95']:>9.1f} {s['p99']:>9.1f} {s['errors']:>5} {s['rate_limited']:>5}")
        peak = max(result["levels"], key=lambda r: r["stats"]["throughput_rps"])
        print(f"\n  peak sustained: {peak['stats']['throughput_rps']:.1f} rps "
              f"at concurrency {peak['concurrency']} (p50 {peak['stats']['p50']:.0f}ms)")
    else:
        s = result["stats"]
        print(f"  concurrency={result['concurrency']} total={result['total']}: "
              f"{s['throughput_rps']:.1f} rps, p50 {s['p50']:.0f}ms, p95 {s['p95']:.0f}ms, "
              f"err {s['errors']}, 429 {s['rate_limited']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="In-cluster (no port-forward) load benchmark")
    ap.add_argument("--division", default="gamma")
    ap.add_argument("--mode", choices=["sweep", "throughput"], default="sweep")
    ap.add_argument("--levels", default="1,8,16,32,64,128,256")
    ap.add_argument("--total", type=int, default=1500)
    ap.add_argument("--concurrency", type=int, default=64)
    ap.add_argument("--pace", type=float, default=0.0,
                    help="seconds between sweep levels so each lands in a fresh per-subject "
                         "60/min window (use with total<=55 to measure clean of 429s WITHOUT "
                         "raising the limit); 0 disables")
    ap.add_argument("--capability", default="tool.pii")
    ap.add_argument("--replicas", type=int, default=None,
                    help="scale the agent to N replicas for the run (restored after)")
    ap.add_argument("--raise-limit", action="store_true",
                    help="raise RATE_LIMIT_PER_MINUTE to measure raw throughput (restored after)")
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args(argv)

    ns = _ns(args.division)
    image = _agent_image(ns)
    if not image:
        print(f"could not resolve agent image in {ns}", file=sys.stderr)
        return 1
    password = _seed_password(args.division)

    orig_replicas = _current_replicas(ns)
    orig_limit = _current_rate_limit(ns)
    restore_needed = False

    try:
        # 1. scale out (optional)
        if args.replicas is not None and args.replicas != orig_replicas:
            print(f"scaling agent {orig_replicas} -> {args.replicas} replicas")
            _kubectl("-n", ns, "scale", "deploy/agent", f"--replicas={args.replicas}")
            _kubectl("-n", ns, "rollout", "status", "deploy/agent", "--timeout=180s", check=False)
            restore_needed = True

        # 2. raise the rate limit (optional) — measured, then restored
        if args.raise_limit:
            print(f"raising RATE_LIMIT_PER_MINUTE (was {orig_limit or 'default 60'}) -> 1000000 for the run")
            _set_rate_limit(ns, "1000000")
            restore_needed = True

        # 3. ship the load driver + run it as a Job hitting the ClusterIP
        print("deploying load Job (configmap + transient secret) ...")
        _apply_configmap(ns)
        _apply_secret(ns, password)
        _kubectl("-n", ns, "delete", "job", JOB, "--ignore-not-found", check=False)
        env = {"TARGET_BASE": "http://agent:8000", "KC_BASE": "http://keycloak:8080",
               "ISSUER_HOST": _issuer_host(ns),
               "MODE": args.mode, "LEVELS": args.levels, "TOTAL": str(args.total),
               "CONCURRENCY": str(args.concurrency), "CAPABILITY": args.capability,
               "PACE": str(args.pace)}
        _kubectl("apply", "-f", "-", stdin=_job_manifest(ns, image, env))

        # The paced waits between sweep levels add to wall time — extend the watch timeout.
        n_levels = len([x for x in args.levels.split(",") if x.strip()])
        timeout_s = args.timeout + (int(args.pace) * max(0, n_levels - 1) if args.mode == "sweep" else 0)
        print(f"running load (mode={args.mode}, total/level={args.total}, pace={args.pace}s) — live progress:")
        status = _wait_job(ns, timeout_s)
        logs = _kubectl("-n", ns, "logs", f"job/{JOB}", check=False).stdout
        for line in logs.splitlines():
            if line.strip().startswith("c=") or line.strip().startswith("PASSWORD"):
                print("  " + line.strip())

        if status != "complete":
            print(f"\nJob did not complete cleanly: {status}")
            print("--- job logs (tail) ---")
            print("\n".join(logs.splitlines()[-25:]))
            return 1

        result = _extract_result(logs)
        if result is None:
            print("\ncould not parse a RESULT from the job logs:")
            print("\n".join(logs.splitlines()[-25:]))
            return 1

        _print_report(result)
        _RESULTS.write_text(json.dumps({
            "context": CTX, "division": args.division, "replicas": args.replicas or orig_replicas,
            "rate_limit_raised": args.raise_limit, "result": result,
            "note": "Measured IN-CLUSTER against the agent ClusterIP — NO kubectl port-forward "
                    "in the path. Deterministic governed tool path (no LLM). The agent was "
                    f"scaled to {args.replicas or orig_replicas} replica(s) and the rate limit "
                    f"{'raised for the run' if args.raise_limit else 'left at default'}; both "
                    "restored after the run.",
        }, indent=2), encoding="utf-8")
        print(f"\nwrote {_RESULTS}")
        return 0
    finally:
        print("\ncleaning up + restoring cluster to its original state ...")
        _cleanup(ns)
        if restore_needed:
            if args.raise_limit:
                _set_rate_limit(ns, orig_limit)  # back to explicit value or app default
            if args.replicas is not None and args.replicas != orig_replicas:
                _kubectl("-n", ns, "scale", "deploy/agent", f"--replicas={orig_replicas}")
            print(f"  restored: replicas={orig_replicas}, RATE_LIMIT_PER_MINUTE={orig_limit or 'default 60'}")


if __name__ == "__main__":
    raise SystemExit(main())
