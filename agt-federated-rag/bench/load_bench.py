"""Real performance / load benchmark for the AGT federated-RAG system, run LIVE.

Unlike ``bench_tools.py`` (in-process micro-latency of the governed tool path), this drives
the running kind-cluster divisions over the REAL authenticated HTTP API, under concurrency,
and reports sustained throughput + latency percentiles. It measures the four things that
actually matter for presenting the system, with HONEST framing that separates the
DETERMINISTIC governance/infra path from the LLM-bound end-user path:

  1. throughput  — sustained req/s on the governed tool path (POST /solve, deterministic, no
                   LLM) at a fixed concurrency for a fixed total.
  2. sweep       — p50/p95/p99 latency AND req/s across concurrency = 1,4,8,16,32,64 — shows
                   how latency degrades under load.
  3. e2e         — the full /query RAG path (retrieve -> LLM -> govern). The LLM (NVIDIA NIM
                   free tier) DOMINATES and rate-limits, so this is the end-USER path number,
                   NOT the system's ceiling. Kept low-concurrency + few iterations on purpose.
  4. xdiv        — a DELEGATED /solve (a division borrowing a peer's tool over the DID-signed
                   /a2a/tool channel) vs a LOCAL /solve, so the cost of the federated hop
                   under load is visible.

Targets are the LIVE divisions on the kind cluster. The token + kubectl port-forward pattern
mirrors ``examples/cross-agent-pii/prove_live.py``. gamma SERVES tool.pii locally; delta /
epsilon do NOT, so sending tool.pii to them DELEGATES to gamma (the xdiv path).

Run from inside ``agt-federated-rag`` (Python from ``../.venv/Scripts/python.exe``)::

    ../.venv/Scripts/python.exe -m bench.load_bench --mode throughput --division gamma \
        --concurrency 16 --total 400
    ../.venv/Scripts/python.exe -m bench.load_bench --mode sweep --division gamma --total 200
    ../.venv/Scripts/python.exe -m bench.load_bench --mode xdiv  --division delta --total 200
    ../.venv/Scripts/python.exe -m bench.load_bench --mode e2e   --division gamma \
        --concurrency 1 --total 5
    ../.venv/Scripts/python.exe -m bench.load_bench --mode all   --division gamma

The script opens its own kubectl port-forwards (and tears them down). Seed-user passwords are
read from ``infra/generated/<div>/secrets.json`` (gitignored). Results are written to
``bench/results_load.json``. CAVEATS (printed with the report): single-node kind cluster,
port-forward adds local hop overhead, NIM free-tier rate limits the e2e path.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

ROOT = Path(__file__).resolve().parents[2]
CTX = "kind-agt"

# division -> port_base (agent=base, keycloak=base+2). Same derivation as prove_live.py /
# onboard_division.derive_ports. gamma/delta/epsilon are the cluster divisions.
PORT_BASE = {"alpha": 9000, "beta": 9100, "gamma": 9200, "delta": 9300, "epsilon": 9400}

# The deterministic tool used for the governed-path load: a PII/DLP screen (regex + Luhn +
# redaction). gamma SERVES tool.pii (so /solve runs it LOCALLY); delta/epsilon do NOT (so
# /solve DELEGATES to gamma over /a2a/tool — the xdiv path).
_PII_ARGS = {"text": "contact me at alice@example.com, card 4242424242424242"}
_E2E_QUERY = "What are the transparency obligations under the EU AI Act?"

_SWEEP_CONCURRENCY = [1, 4, 8, 16, 32, 64]
_RESULTS_PATH = Path(__file__).resolve().parent / "results_load.json"


# ── port-forward + token (mirrors prove_live.py) ────────────────────────────────────────
def _pf(div: str) -> list[subprocess.Popen]:
    """Open kubectl port-forwards for a division's agent + keycloak services."""
    base = PORT_BASE[div]
    ns = f"agt-div-{div}"
    return [
        subprocess.Popen(["kubectl", "--context", CTX, "-n", ns, "port-forward", "svc/agent",
                          f"{base}:8000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen(["kubectl", "--context", CTX, "-n", ns, "port-forward", "svc/keycloak",
                          f"{base + 2}:8080"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]


def _token(div: str) -> str:
    """Fetch a real seed-user (alice) bearer token from the division's Keycloak (retried —
    the freshly-opened port-forward is flaky for the first second or two)."""
    base = PORT_BASE[div]
    pw = json.loads(
        (ROOT / "infra" / "generated" / div / "secrets.json").read_text()
    )["seed_user_password"]
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "rag-ui",
                                   "username": "alice", "password": pw}).encode()
    url = f"http://localhost:{base + 2}/realms/rag/protocol/openid-connect/token"

    last: Exception | None = None
    for _ in range(8):
        try:
            return json.loads(urllib.request.urlopen(url, data=data, timeout=15).read())["access_token"]
        except Exception as exc:  # noqa: BLE001 — port-forward warmup can drop the connection
            last = exc
            time.sleep(2)
    raise RuntimeError(f"could not obtain token for {div}: {last}")


# ── core async load generator ───────────────────────────────────────────────────────────
def _percentile(sorted_ms: list[float], pct: float) -> float:
    """Nearest-rank percentile (pct in [0,100]) over an ascending list of ms samples."""
    if not sorted_ms:
        return 0.0
    if len(sorted_ms) == 1:
        return sorted_ms[0]
    rank = max(1, min(len(sorted_ms), round(pct / 100.0 * len(sorted_ms))))
    return sorted_ms[rank - 1]


def _summarize(latencies_ms: list[float], wall_s: float, errors: int,
               rate_limited: int = 0) -> dict[str, Any]:
    """Reduce per-request latencies (ms) + wall-clock duration to a report dict.

    throughput_rps is the COMPLETED count over the wall-clock duration of the run — i.e. the
    sustained rate actually achieved at this concurrency, not a per-request reciprocal.
    ``rate_limited`` (HTTP 429) is broken out from ``errors`` because it is a REAL governance
    gate (per-subject 60/min anti-abuse limit), not a system failure — it must not be read as
    the system buckling."""
    s = sorted(latencies_ms)
    n = len(s)
    return {
        "count": n,
        "errors": errors,
        "rate_limited": rate_limited,
        "duration_s": round(wall_s, 4),
        "throughput_rps": round(n / wall_s, 2) if wall_s > 0 else 0.0,
        "p50": round(_percentile(s, 50), 2),
        "p95": round(_percentile(s, 95), 2),
        "p99": round(_percentile(s, 99), 2),
        "mean": round(statistics.fmean(s), 2) if s else 0.0,
        "min": round(s[0], 2) if s else 0.0,
        "max": round(s[-1], 2) if s else 0.0,
    }


async def run_load(
    make_request: Callable[[httpx.AsyncClient], Awaitable[None]],
    client: httpx.AsyncClient,
    total: int,
    concurrency: int,
    warmup: int = 0,
) -> dict[str, Any]:
    """Fire ``total`` requests, ``concurrency`` in flight at once (asyncio.Semaphore).

    ``make_request`` performs ONE request against the shared ``client`` and must raise on a
    non-success outcome (so it counts as an error, not a latency sample). Each successful call
    is timed with perf_counter. The first ``warmup`` completed requests are discarded from the
    stats (they prime connection pools / server caches) but still count toward wall time of the
    warmup, which is excluded from the measured window. Returns the ``_summarize`` dict.
    """
    sem = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    errors = 0
    rate_limited = 0

    async def _one() -> None:
        nonlocal errors, rate_limited
        async with sem:
            t0 = time.perf_counter()
            try:
                await make_request(client)
            except httpx.HTTPStatusError as exc:
                # Distinguish the per-subject 60/min anti-abuse gate (a real governance
                # control) from genuine failures, so a large run doesn't read as the system
                # breaking when it's actually the rate limiter doing its job.
                if exc.response is not None and exc.response.status_code == 429:
                    rate_limited += 1
                else:
                    errors += 1
                return
            except Exception:  # noqa: BLE001 — any other failure is an error sample
                errors += 1
                return
            latencies.append((time.perf_counter() - t0) * 1000.0)

    # Warmup window (discarded): run `warmup` requests at the same concurrency first.
    if warmup > 0:
        await asyncio.gather(*[_one() for _ in range(warmup)])
        latencies.clear()
        errors = 0
        rate_limited = 0

    # Measured window: time the whole batch wall-clock for an honest sustained req/s.
    wall0 = time.perf_counter()
    await asyncio.gather(*[_one() for _ in range(total)])
    wall_s = time.perf_counter() - wall0
    return _summarize(latencies, wall_s, errors, rate_limited)


# ── request builders ────────────────────────────────────────────────────────────────────
def _solve_request(token: str, capability: str, arguments: dict) -> Callable[[httpx.AsyncClient], Awaitable[None]]:
    """A make_request that POSTs a DIRECT {capability, arguments} to /solve and asserts the
    governed call completed (raises otherwise so it's counted as an error)."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"capability": capability, "arguments": arguments}

    async def _do(client: httpx.AsyncClient) -> None:
        r = await client.post("/solve", json=payload, headers=headers, timeout=60.0)
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "completed":
            raise RuntimeError(f"/solve not completed: {data!r}")

    return _do


def _query_request(token: str, query: str) -> Callable[[httpx.AsyncClient], Awaitable[None]]:
    """A make_request that POSTs to /query and CONSUMES the SSE stream to the terminal
    ``done`` event — so the measured latency is the full retrieve -> LLM -> govern path, not
    just time-to-first-byte. Raises if the stream errors or never reaches ``done``."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"query": query}

    async def _do(client: httpx.AsyncClient) -> None:
        async with client.stream("POST", "/query", json=payload, headers=headers, timeout=180.0) as r:
            r.raise_for_status()
            done = False
            async for line in r.aiter_lines():
                if line.startswith("event:"):
                    ev = line.split(":", 1)[1].strip()
                    if ev == "error":
                        raise RuntimeError("/query stream errored")
                    if ev == "done":
                        done = True
            if not done:
                raise RuntimeError("/query stream ended without a 'done' event")

    return _do


# ── modes ───────────────────────────────────────────────────────────────────────────────
def _agent_base(div: str) -> str:
    return f"http://localhost:{PORT_BASE[div]}"


async def mode_throughput(div: str, token: str, concurrency: int, total: int, warmup: int) -> dict[str, Any]:
    """Sustained req/s on the deterministic governed tool path (local /solve tool.pii)."""
    async with httpx.AsyncClient(base_url=_agent_base(div), limits=httpx.Limits(
            max_connections=concurrency + 4, max_keepalive_connections=concurrency + 4)) as client:
        stats = await run_load(_solve_request(token, "tool.pii", _PII_ARGS),
                               client, total, concurrency, warmup=warmup)
    return {"mode": "throughput", "division": div, "path": "local /solve tool.pii (deterministic)",
            "concurrency": concurrency, "total": total, "warmup": warmup, "stats": stats}


async def mode_sweep(div: str, token: str, total: int, warmup: int,
                     levels: list[int], pace_s: float = 0.0) -> dict[str, Any]:
    """Latency percentiles + req/s across a concurrency sweep on the local governed path.

    ``pace_s`` sleeps between levels so each lands in a fresh per-subject 60/min rate-limit
    window (set it >= 60 with total <= 60 to keep every level clean of 429s); 0 disables it."""
    rows: list[dict[str, Any]] = []
    for i, c in enumerate(levels):
        if i > 0 and pace_s > 0:
            await asyncio.sleep(pace_s)
            # A long paced sweep can outlive the access token (~5 min Keycloak default), so
            # refresh it each level after the first.
            token = await asyncio.to_thread(_token, div)
        async with httpx.AsyncClient(base_url=_agent_base(div), limits=httpx.Limits(
                max_connections=c + 4, max_keepalive_connections=c + 4)) as client:
            stats = await run_load(_solve_request(token, "tool.pii", _PII_ARGS),
                                   client, total, c, warmup=warmup)
        rows.append({"concurrency": c, "stats": stats})
    return {"mode": "sweep", "division": div, "path": "local /solve tool.pii (deterministic)",
            "total_per_level": total, "warmup": warmup, "pace_s": pace_s, "levels": rows}


async def mode_xdiv(div: str, token: str, concurrency: int, total: int, warmup: int) -> dict[str, Any]:
    """Cost of the federated hop under load: a DELEGATED /solve (div borrows gamma's tool.pii
    over /a2a/tool) vs a LOCAL /solve of the same tool on gamma — so the delta is the secure
    cross-division hop. ``div`` MUST be one that does NOT serve tool.pii (delta/epsilon)."""
    if div not in ("delta", "epsilon"):
        raise SystemExit(f"xdiv mode needs a division that DELEGATES tool.pii (delta/epsilon), got {div}")

    # Delegated leg: send tool.pii to `div` -> it delegates to gamma.
    async with httpx.AsyncClient(base_url=_agent_base(div), limits=httpx.Limits(
            max_connections=concurrency + 4, max_keepalive_connections=concurrency + 4)) as client:
        delegated = await run_load(_solve_request(token, "tool.pii", _PII_ARGS),
                                   client, total, concurrency, warmup=warmup)

    # Local baseline leg: the SAME tool.pii run locally on gamma (its owner), for the delta.
    gamma_token = _token("gamma")
    async with httpx.AsyncClient(base_url=_agent_base("gamma"), limits=httpx.Limits(
            max_connections=concurrency + 4, max_keepalive_connections=concurrency + 4)) as client:
        local = await run_load(_solve_request(gamma_token, "tool.pii", _PII_ARGS),
                               client, total, concurrency, warmup=warmup)

    hop_overhead_ms = round(delegated["p50"] - local["p50"], 2)
    factor = round(delegated["p50"] / local["p50"], 2) if local["p50"] else None
    return {
        "mode": "xdiv", "division": div, "concurrency": concurrency, "total": total,
        "warmup": warmup,
        "delegated": {"path": f"{div} /solve tool.pii -> DELEGATES to gamma (/a2a/tool)", "stats": delegated},
        "local": {"path": "gamma /solve tool.pii (LOCAL owner, baseline)", "stats": local},
        "comparison": {
            "delegated_p50_ms": delegated["p50"], "local_p50_ms": local["p50"],
            "secure_hop_overhead_p50_ms": hop_overhead_ms,
            "delegated_over_local_x": factor,
            "delegated_throughput_rps": delegated["throughput_rps"],
            "local_throughput_rps": local["throughput_rps"],
        },
    }


async def _probe_query_outcome(div: str, token: str) -> str:
    """Single /query probe that returns a human-readable outcome string: 'ok' on a completed
    stream, otherwise the server's first SSE error payload (or the HTTP/transport failure).
    Used to EXPLAIN an all-errors e2e run honestly in the report instead of a bare count."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(base_url=_agent_base(div)) as client:
            async with client.stream("POST", "/query", json={"query": _E2E_QUERY},
                                     headers=headers, timeout=180.0) as r:
                if r.status_code != 200:
                    return f"HTTP {r.status_code}"
                last_event = None
                async for line in r.aiter_lines():
                    if line.startswith("event:"):
                        last_event = line.split(":", 1)[1].strip()
                    elif line.startswith("data:") and last_event == "error":
                        return f"server error event: {line.split(':', 1)[1].strip()}"
                    elif last_event == "done":
                        return "ok"
        return "stream ended without 'done'"
    except Exception as exc:  # noqa: BLE001 — report the failure verbatim
        return f"{type(exc).__name__}: {exc}"


async def mode_e2e(div: str, token: str, concurrency: int, total: int, warmup: int) -> dict[str, Any]:
    """Full RAG path (/query: retrieve -> LLM -> govern). LLM-DOMINATED + rate-limited — keep
    concurrency + total small. This is the end-USER path number, not the system ceiling."""
    async with httpx.AsyncClient(base_url=_agent_base(div), limits=httpx.Limits(
            max_connections=concurrency + 2, max_keepalive_connections=concurrency + 2)) as client:
        stats = await run_load(_query_request(token, _E2E_QUERY),
                               client, total, concurrency, warmup=warmup)
    out = {"mode": "e2e", "division": div, "path": "/query full RAG (retrieve -> LLM -> govern)",
           "concurrency": concurrency, "total": total, "warmup": warmup,
           "caveat": "LLM (NVIDIA NIM free tier) dominates this latency and rate-limits it; "
                     "this is the END-USER path, NOT the system's throughput ceiling.",
           "stats": stats}
    # If nothing completed, probe once to capture WHY (so the JSON explains the gap honestly
    # rather than just showing errors with no cause).
    if stats["count"] == 0:
        out["diagnostic"] = await _probe_query_outcome(div, token)
    return out


# ── reporting ───────────────────────────────────────────────────────────────────────────
def _fmt_stats_row(label: str, st: dict[str, Any]) -> str:
    return (f"  {label:<22} {st['count']:>6} {st['errors']:>4} {st.get('rate_limited', 0):>4} "
            f"{st['throughput_rps']:>9.2f} {st['p50']:>9.2f} {st['p95']:>9.2f} "
            f"{st['p99']:>9.2f} {st['mean']:>9.2f} {st['min']:>9.2f} {st['max']:>9.2f}")


_STATS_HEADER = (f"  {'target':<22} {'reqs':>6} {'err':>4} {'429':>4} {'rps':>9} {'p50':>9} "
                 f"{'p95':>9} {'p99':>9} {'mean':>9} {'min':>9} {'max':>9}")


def print_report(result: dict[str, Any]) -> None:
    """Print a clean table for a single mode's result (latencies in ms)."""
    mode = result["mode"]
    print(f"\n=== {mode.upper()} — division {result['division']} "
          f"(latencies in milliseconds, ms) ===")

    if mode == "throughput":
        print(f"path: {result['path']}  concurrency={result['concurrency']} "
              f"total={result['total']} warmup={result['warmup']}")
        print(_STATS_HEADER)
        print("  " + "-" * (len(_STATS_HEADER) - 2))
        print(_fmt_stats_row(result["division"], result["stats"]))

    elif mode == "sweep":
        print(f"path: {result['path']}  total/level={result['total_per_level']} "
              f"warmup={result['warmup']}")
        print(_STATS_HEADER)
        print("  " + "-" * (len(_STATS_HEADER) - 2))
        for row in result["levels"]:
            print(_fmt_stats_row(f"c={row['concurrency']}", row["stats"]))

    elif mode == "xdiv":
        print(f"concurrency={result['concurrency']} total={result['total']} "
              f"warmup={result['warmup']}")
        print(_STATS_HEADER)
        print("  " + "-" * (len(_STATS_HEADER) - 2))
        print(_fmt_stats_row("delegated->gamma", result["delegated"]["stats"]))
        print(_fmt_stats_row("local gamma", result["local"]["stats"]))
        c = result["comparison"]
        print(f"\n  delegated p50: {c['delegated_p50_ms']:.2f} ms   "
              f"local p50: {c['local_p50_ms']:.2f} ms")
        fx = f"{c['delegated_over_local_x']:.2f}x" if c["delegated_over_local_x"] else "n/a"
        print(f"  secure cross-division hop overhead (p50): "
              f"+{c['secure_hop_overhead_p50_ms']:.2f} ms ({fx} the local call)")
        print(f"  throughput: delegated {c['delegated_throughput_rps']:.2f} rps   "
              f"local {c['local_throughput_rps']:.2f} rps")

    elif mode == "e2e":
        print(f"path: {result['path']}  concurrency={result['concurrency']} "
              f"total={result['total']} warmup={result['warmup']}")
        print(f"CAVEAT: {result['caveat']}")
        print(_STATS_HEADER)
        print("  " + "-" * (len(_STATS_HEADER) - 2))
        print(_fmt_stats_row(result["division"], result["stats"]))
        if result.get("diagnostic"):
            print(f"\n  NOTE: 0 completed — {result['diagnostic']}")
    print()


_CAVEATS = [
    "single-node kind cluster — all divisions + their infra (Qdrant/Postgres/Keycloak/"
    "OpenFGA/Redis) share one host's CPU; this is a dev cluster, not production hardware.",
    "kubectl port-forward adds a localhost proxy hop in front of every request — real "
    "in-cluster service-to-service latency is lower than these numbers.",
    "e2e (/query) latency is dominated by the NVIDIA NIM free-tier LLM, which also rate-"
    "limits; treat it as the end-USER path, not the system's deterministic ceiling.",
    "the governed tool path (/solve tool.pii) is DETERMINISTIC (regex + Luhn + redaction + "
    "policy engine) — no LLM — so throughput/sweep/xdiv reflect the SYSTEM, not a model.",
]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AGT federated-RAG live load benchmark")
    ap.add_argument("--mode", choices=["throughput", "sweep", "e2e", "xdiv", "all"],
                    default="throughput")
    ap.add_argument("--division", choices=["alpha", "beta", "gamma", "delta", "epsilon"],
                    default="gamma")
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--total", type=int, default=40,
                    help="requests per measured window. The governed path enforces a REAL "
                         "per-subject 60/min rate limit, so keep total<=~55 (or use --pace) to "
                         "avoid 429s counting against a single user.")
    ap.add_argument("--warmup", type=int, default=0,
                    help="requests discarded before the measured window (per level for sweep); "
                         "they also consume the per-subject rate-limit budget, so default 0")
    ap.add_argument("--sweep-levels", default=",".join(map(str, _SWEEP_CONCURRENCY)),
                    help="comma-separated concurrency levels for --mode sweep")
    ap.add_argument("--pace", type=float, default=62.0,
                    help="seconds to sleep between sweep levels so each lands in a fresh "
                         "per-subject 60/min window (default 62; set 0 to disable)")
    ap.add_argument("--no-port-forward", action="store_true",
                    help="assume port-forwards are already open (don't spawn/teardown them)")
    args = ap.parse_args(argv)

    div = args.division
    levels = [int(x) for x in args.sweep_levels.split(",") if x.strip()]

    # xdiv also needs gamma's port-forward (the local baseline leg) — open both.
    pf_divs = [div]
    if args.mode in ("xdiv", "all") and div != "gamma":
        pf_divs.append("gamma")

    procs: list[subprocess.Popen] = []
    if not args.no_port_forward:
        for d in pf_divs:
            procs += _pf(d)
        time.sleep(10)  # let the port-forwards establish (same as prove_live.py)

    results: dict[str, Any] = {"context": CTX, "division": div, "modes": {}}
    try:
        token = _token(div)
        modes = (["throughput", "sweep", "xdiv", "e2e"] if args.mode == "all" else [args.mode])
        # 'all' xdiv only makes sense for a delegating division; skip it for gamma.
        if args.mode == "all" and div == "gamma":
            modes = [m for m in modes if m != "xdiv"]

        for m in modes:
            if m == "throughput":
                r = asyncio.run(mode_throughput(div, token, args.concurrency, args.total, args.warmup))
            elif m == "sweep":
                r = asyncio.run(mode_sweep(div, token, args.total, args.warmup, levels, args.pace))
            elif m == "xdiv":
                r = asyncio.run(mode_xdiv(div, token, args.concurrency, args.total, args.warmup))
            elif m == "e2e":
                # e2e: cap concurrency/total so we don't hammer the rate-limited LLM.
                e2e_c = min(args.concurrency, 4) if args.mode == "all" else args.concurrency
                e2e_t = min(args.total, 5) if args.mode == "all" else args.total
                r = asyncio.run(mode_e2e(div, token, e2e_c, e2e_t, min(args.warmup, 1)))
            else:  # pragma: no cover — argparse restricts choices
                continue
            print_report(r)
            results["modes"][m] = r
    finally:
        for p in procs:
            p.terminate()

    print("CAVEATS (what these numbers do and do NOT mean):")
    for c in _CAVEATS:
        print(f"  - {c}")

    # Merge into any existing results file (keyed by mode) so separate invocations
    # (throughput, then sweep, then xdiv, then e2e) accumulate into ONE report instead of
    # each run clobbering the last. The caveats are stored once alongside the modes.
    merged: dict[str, Any] = {"context": CTX, "modes": {}, "caveats": _CAVEATS}
    if _RESULTS_PATH.exists():
        try:
            prev = json.loads(_RESULTS_PATH.read_text(encoding="utf-8"))
            if isinstance(prev.get("modes"), dict):
                merged["modes"].update(prev["modes"])
        except Exception:  # noqa: BLE001 — a corrupt/old file just starts fresh
            pass
    merged["modes"].update(results["modes"])
    _RESULTS_PATH.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    print(f"\nwrote {_RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
