"""In-cluster load driver — runs INSIDE the kind cluster (as a k8s Job) so the load hits the
agent Service ClusterIP DIRECTLY. This removes the two dev-rig distortions baked into
``load_bench.py`` when driven from the host:

  * NO ``kubectl port-forward`` in the path (the host runs every request through one localhost
    TCP proxy, which serializes and caps throughput at ~18 rps regardless of the backend).
  * the agent can be scaled to N replicas and the in-namespace ClusterIP Service load-balances
    across them — so this measures the SYSTEM's real horizontal throughput, not one pod behind
    one proxy.

It REUSES the proven engine from ``bench.load_bench`` (``run_load`` + ``_solve_request`` +
``_summarize``) — only the targets (in-cluster DNS ``http://agent:8000`` / ``http://keycloak:8080``)
and the token source differ. It is mounted into the Job pod alongside ``load_bench.py`` (see
``run_incluster_bench.py``), which generates the ConfigMap + Job + transient credential Secret.

Config comes from env (set by the Job):
  TARGET_BASE   agent base URL              (default http://agent:8000)
  KC_BASE       keycloak base URL           (default http://keycloak:8080)
  REALM         keycloak realm              (default rag)
  USERNAME      seed user                   (default alice)
  PASSWORD      seed-user password          (required — injected from a Secret, never logged)
  CAPABILITY    governed tool capability    (default tool.pii — deterministic, no LLM)
  MODE          throughput | sweep          (default sweep)
  LEVELS        sweep concurrency levels    (default 1,8,16,32,64,128,256)
  TOTAL         requests per measured window(default 1500)
  CONCURRENCY   throughput-mode concurrency (default 64)

It prints a single JSON object between ``<<<RESULT`` / ``RESULT>>>`` markers on stdout, which
``run_incluster_bench.py`` extracts from the Job logs.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.parse
import urllib.request

import httpx

# Reuse the load engine — same percentiles / sustained-rps math the host benchmark uses, so
# the in-cluster numbers are directly comparable to load_bench's port-forward numbers.
from bench.load_bench import _solve_request, _summarize, run_load  # noqa: F401  (engine reuse)

_PII_ARGS = {"text": "contact me at alice@example.com, card 4242424242424242"}


def _env(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _token() -> str:
    """Fetch a seed-user bearer token from the IN-CLUSTER Keycloak (no port-forward).

    The agent validates ``iss == OIDC_ISSUER`` (the EXTERNAL host, e.g.
    ``http://localhost:9202/realms/rag``), while we must REACH Keycloak at its in-cluster
    address (``http://keycloak:8080``). Keycloak (dynamic-hostname dev mode) derives the token
    issuer from the request ``Host`` header — so we connect to ``keycloak:8080`` but send
    ``Host: <ISSUER_HOST>`` so the issued token carries exactly the ``iss`` the agent expects.
    """
    kc = _env("KC_BASE", "http://keycloak:8080").rstrip("/")
    realm = _env("REALM", "rag")
    issuer_host = os.environ.get("ISSUER_HOST", "").strip()  # e.g. localhost:9202
    pw = os.environ.get("PASSWORD")
    if not pw:
        raise SystemExit("PASSWORD env is required (seed-user password)")
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "rag-ui",
        "username": _env("USERNAME", "alice"), "password": pw,
    }).encode()
    url = f"{kc}/realms/{realm}/protocol/openid-connect/token"

    def _build() -> urllib.request.Request:
        req = urllib.request.Request(url, data=data, method="POST")
        if issuer_host:
            # Make Keycloak stamp the issuer the agent expects (it reads Host / X-Forwarded-*).
            req.add_unredirected_header("Host", issuer_host)
            req.add_header("X-Forwarded-Host", issuer_host)
            req.add_header("X-Forwarded-Proto", "http")
        return req

    # Retry/backoff — Keycloak on the single-node kind cluster can be briefly slow under churn
    # (cold JIT, a concurrent rollout). One transient timeout must NOT kill the whole run.
    last: Exception | None = None
    for _ in range(8):
        try:
            return json.loads(urllib.request.urlopen(_build(), timeout=10).read())["access_token"]
        except Exception as exc:  # noqa: BLE001 — transient network/Keycloak warmup
            last = exc
            time.sleep(3)
    raise SystemExit(f"could not obtain token after retries: {last}")


async def _sweep(target: str, token: str, cap: str, total: int, levels: list[int],
                 pace_s: float) -> dict:
    rows = []
    for i, c in enumerate(levels):
        if i > 0 and pace_s > 0:
            # Sleep so this level lands in a FRESH per-subject 60/min window (clean of 429s
            # without raising the limit), then refresh the token (a long paced sweep can
            # outlive Keycloak's ~5-min access token).
            await asyncio.sleep(pace_s)
            token = _token()
        async with httpx.AsyncClient(base_url=target, limits=httpx.Limits(
                max_connections=c + 8, max_keepalive_connections=c + 8)) as client:
            stats = await run_load(_solve_request(token, cap, _PII_ARGS), client, total, c)
        rows.append({"concurrency": c, "stats": stats})
        # Progress to stderr so the JSON on stdout stays clean.
        print(f"  c={c:<4} rps={stats['throughput_rps']:>7.1f}  p50={stats['p50']:>7.1f}ms  "
              f"p95={stats['p95']:>7.1f}ms  err={stats['errors']}  429={stats['rate_limited']}",
              flush=True)
    return {"mode": "sweep_incluster", "target": target, "capability": cap,
            "total_per_level": total, "pace_s": pace_s, "levels": rows}


async def _throughput(target: str, token: str, cap: str, total: int, concurrency: int) -> dict:
    async with httpx.AsyncClient(base_url=target, limits=httpx.Limits(
            max_connections=concurrency + 8, max_keepalive_connections=concurrency + 8)) as client:
        stats = await run_load(_solve_request(token, cap, _PII_ARGS), client, total, concurrency)
    return {"mode": "throughput_incluster", "target": target, "capability": cap,
            "concurrency": concurrency, "total": total, "stats": stats}


async def _main() -> dict:
    target = _env("TARGET_BASE", "http://agent:8000").rstrip("/")
    cap = _env("CAPABILITY", "tool.pii")
    mode = _env("MODE", "sweep")
    total = int(_env("TOTAL", "1500"))
    token = _token()
    if mode == "throughput":
        return await _throughput(target, token, cap, total, int(_env("CONCURRENCY", "64")))
    levels = [int(x) for x in _env("LEVELS", "1,8,16,32,64,128,256").split(",") if x.strip()]
    return await _sweep(target, token, cap, total, levels, float(_env("PACE", "0")))


if __name__ == "__main__":
    result = asyncio.run(_main())
    # Fenced so the orchestrator can extract exactly the JSON from the Job logs.
    print("<<<RESULT")
    print(json.dumps(result))
    print("RESULT>>>")
