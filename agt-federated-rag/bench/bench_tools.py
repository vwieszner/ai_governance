"""Governance-overhead benchmark for the LOCAL governed tool path.

Measures how much the AGT governance gates add to a tool call by comparing, per tool:
  (a) RAW   — the bare tool function (e.g. ``local_tools.pii_scan({...})``): the latency floor.
  (b) GOVERNED — ``local_tools.run_local_tool(server, tool, {...})``, which runs the policy
      engine (``_enforce``, default-deny), the McpAuthPolicy gateway (per-server allowlist +
      auth method + TLS), and the §4.2 no-credential boundary, then dispatches to the same
      function via the injected ``local_caller``.
The difference (governed_mean − raw_mean) is the per-call governance overhead.

SCOPE: this benchmarks the in-process LOCAL governed path ONLY. The cross-agent DELEGATED
path (DID-sign the request → HTTP POST to the peer's /a2a/tool → signature verify → run →
signed response) is a separate, much larger cost and is NOT measured here; see the
``bench_delegated`` stub for where it plugs in once mesh-builder's ``call_peer_tool`` lands.

Hermetic: no network, no live services. Run from inside ``agt-federated-rag``::

    RAG_ENV_FILE=__none__ ../.venv/Scripts/python.exe -m bench.bench_tools [iterations]

It primes the policy/gateway caches with a warmup, times each variant with
``time.perf_counter_ns``, prints a table to stdout, and writes ``bench/results_local.json``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

# Make `from config import ...` / `from tools import ...` resolve when launched as
# `python -m bench.bench_tools` from inside agt-federated-rag (mirrors conftest's path
# setup, which only runs under pytest). The package root is this file's parent's parent.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Hermetic default: if no env file is present, seed the REQUIRED settings so
# `import config` (which builds a module-level Settings()) succeeds without a .env.
# Mirrors conftest._REQUIRED. Applies ONLY when the selected env file is absent, so a
# real .env run is unchanged. RAG_ENV_FILE=__none__ (the documented invocation) points
# at a non-existent file, which triggers this path.
_REQUIRED = dict(
    OPENAI_API_KEY="bench-openai-key",
    OPENFGA_STORE_ID="bench-store",
    OPENFGA_MODEL_ID="bench-model",
    NEO4J_PASSWORD="bench-neo4j",
    AGENT_CLIENT_ID="bench-agent",
    AGENT_CLIENT_SECRET="bench-agent-secret",
    AGENT_SPONSOR_EMAIL="sponsor@example.com",
    APPROVAL_HMAC_SECRET="0" * 64,
)
_ENV_FILE = _ROOT / os.environ.get("RAG_ENV_FILE", ".env")
if not _ENV_FILE.exists():
    for _k, _v in _REQUIRED.items():
        os.environ.setdefault(_k, _v)

from tools import local_tools  # noqa: E402  (import after sys.path / env bootstrap)

_RESULTS_PATH = Path(__file__).resolve().parent / "results_local.json"
_DEFAULT_ITERS = 1000
_WARMUP_ITERS = 50           # discarded — primes the policy/gateway caches


def _quiet_logging() -> None:
    """Silence the per-call governance audit logs during timing.

    Every governed call emits structlog INFO/DEBUG events (``mcp_call``,
    ``agt_policy_allowed``). Those are real, but they are log I/O to stdout, not governance
    COMPUTE — and synchronous stdout writes (the default console renderer) would dominate
    and distort the per-call latency. We drop everything below CRITICAL so the measured
    overhead reflects the policy/gateway WORK, which is what this benchmark is about. (A
    production deployment ships these audit events through an async handler, not blocking
    stdout, so excluding the console write here is the fairer measurement.)"""
    logging.disable(logging.CRITICAL)
    try:
        import structlog
        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL),
        )
    except Exception:
        pass


def _percentile(sorted_us: list[float], pct: float) -> float:
    """Nearest-rank percentile (pct in [0,100]) over an ascending list of µs samples."""
    if not sorted_us:
        return 0.0
    if len(sorted_us) == 1:
        return sorted_us[0]
    rank = max(1, min(len(sorted_us), round(pct / 100.0 * len(sorted_us))))
    return sorted_us[rank - 1]


def _summarize(samples_us: list[float]) -> dict[str, float]:
    """Reduce a list of per-call latencies (µs) to summary stats (all µs)."""
    s = sorted(samples_us)
    return {
        "count": len(s),
        "mean": statistics.fmean(s),
        "p50": _percentile(s, 50),
        "p95": _percentile(s, 95),
        "p99": _percentile(s, 99),
        "min": s[0],
        "max": s[-1],
    }


async def _time_async(fn: Callable[[], Awaitable[Any]], iters: int) -> list[float]:
    """Run an async callable ``iters`` times, returning per-call latencies in µs."""
    samples: list[float] = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        await fn()
        samples.append((time.perf_counter_ns() - t0) / 1000.0)
    return samples


def _time_sync(fn: Callable[[], Any], iters: int) -> list[float]:
    """Run a sync callable ``iters`` times, returning per-call latencies in µs."""
    samples: list[float] = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1000.0)
    return samples


# Each case: a label, the RAW sync call, and the GOVERNED async call. The arguments are
# fixed deterministic inputs so timing reflects the path, not input-dependent work. The
# benchmarked tool is the REAL PII / DLP screen (tool.pii) — a representative governance
# workload (regex classification + Luhn validation + redaction), not a toy.
_PII_TEXT = "Contact alice@example.com, card 4242424242424242, SSN 123-45-6789."
_CASES = [
    {
        "tool": "pii",
        "server": "pii-scan",
        "args": {"text": _PII_TEXT},
        "raw": lambda: local_tools.pii_scan({"text": _PII_TEXT}),
        "governed": lambda: local_tools.run_local_tool("pii-scan", "scan", {"text": _PII_TEXT}),
    },
]


async def run_benchmark(iters: int = _DEFAULT_ITERS) -> dict[str, Any]:
    """Benchmark every case (raw + governed) and return the structured results."""
    # Silence per-call audit logs so timing reflects governance compute, not stdout I/O.
    _quiet_logging()
    # Register the local servers + prime the executor's gateway cache once up front.
    local_tools.ensure_local_servers_registered()

    cases_out: list[dict[str, Any]] = []
    for case in _CASES:
        raw_fn = case["raw"]
        gov_fn = case["governed"]

        # Warmup (discarded): primes the policy engine + gateway caches so the timed
        # governed runs reflect steady-state cost, not one-time policy YAML loading.
        _time_sync(raw_fn, _WARMUP_ITERS)
        await _time_async(gov_fn, _WARMUP_ITERS)

        raw = _summarize(_time_sync(raw_fn, iters))
        gov = _summarize(await _time_async(gov_fn, iters))

        overhead_us = gov["mean"] - raw["mean"]
        overhead_pct = (overhead_us / raw["mean"] * 100.0) if raw["mean"] > 0 else 0.0
        cases_out.append({
            "tool": case["tool"],
            "server": case["server"],
            "args": case["args"],
            "raw": raw,
            "governed": gov,
            "overhead_us": overhead_us,
            "overhead_pct": overhead_pct,
        })

    return {
        "scope": "local_governed_path",
        "iterations": iters,
        "warmup": _WARMUP_ITERS,
        "note": "Measures the in-process LOCAL governed path (policy + gateway + caller). "
                "The cross-agent DELEGATED path (sign + HTTP + verify) is benchmarked "
                "separately — see bench_delegated().",
        "cases": cases_out,
    }


def _fmt_row(label: str, stats: dict[str, float]) -> str:
    return (f"  {label:<10} "
            f"{stats['count']:>7} "
            f"{stats['mean']:>10.2f} "
            f"{stats['p50']:>10.2f} "
            f"{stats['p95']:>10.2f} "
            f"{stats['p99']:>10.2f} "
            f"{stats['min']:>10.2f} "
            f"{stats['max']:>10.2f}")


def print_table(results: dict[str, Any]) -> None:
    """Print a clean fixed-width table of the benchmark results to stdout."""
    print("\nAGT local governed-tool benchmark (latencies in microseconds, µs)")
    print(f"iterations={results['iterations']} warmup={results['warmup']} "
          f"scope={results['scope']}")
    header = (f"  {'variant':<10} {'count':>7} {'mean':>10} {'p50':>10} {'p95':>10} "
              f"{'p99':>10} {'min':>10} {'max':>10}")
    for case in results["cases"]:
        print(f"\n[{case['tool']}]  ({case['server']})  args={case['args']}")
        print(header)
        print("  " + "-" * (len(header) - 2))
        print(_fmt_row("raw", case["raw"]))
        print(_fmt_row("governed", case["governed"]))
        print(f"  governance overhead: {case['overhead_us']:+.2f} µs "
              f"({case['overhead_pct']:+.1f}% over raw)")
    print()


_RESULTS_DELEGATED_PATH = Path(__file__).resolve().parent / "results_delegated.json"

# Identity constants for the in-process delegated round-trip (mirror tests/test_a2a_tool.py).
_SELF_DID = "did:mesh:bench-self"
_PEER_DID = "did:mesh:bench-peer-b"
_PEER_ISSUER = "http://bench-peer-b/realms/rag"
_USER_ID = "alice@example.com|deadbeefdeadbeef"


class _patched:
    """Tiny save/restore monkeypatch (no pytest). setattr on enter, restore on exit.

    Used so bench_delegated can exercise the REAL endpoint coroutine + REAL policy engine +
    REAL governed tool while simulating ONLY the crypto/identity/registry gates that need live
    infra (Ed25519 verify, AgentMesh registry trust, JWKS issuer validation) — exactly the
    seams tests/test_a2a_tool.py stubs. The signing/verify here is simulated, but the policy
    default-deny gate, the assertion RECIPIENT-binding shape, the MCP gateway, and the PII-scan
    tool all run for real, so the measured cost reflects the genuine governed delegation path
    minus only the (separately-characterised) asymmetric-crypto + socket time."""

    def __init__(self) -> None:
        self._saved: list[tuple[Any, str, Any]] = []

    def set(self, obj: Any, name: str, value: Any) -> None:
        self._saved.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def __enter__(self) -> "_patched":
        return self

    def __exit__(self, *exc: Any) -> None:
        for obj, name, old in reversed(self._saved):
            setattr(obj, name, old)


async def bench_delegated(iters: int = _DEFAULT_ITERS) -> dict[str, Any]:
    """Benchmark the DELEGATED cross-agent tool round-trip IN-PROCESS via httpx ASGITransport.

    Measures the FULL governed delegation path for a single tool call, end to end:
      sign_outbound_message (SEND side)
        → HTTP POST /a2a/tool (ASGITransport — no socket, no network)
        → receiver: verify signature + registry trust + recipient-bound assertion + policy
          default-deny (_enforce) + run_local_tool (MCP gateway + PII-scan tool)
        → DID-signed response
        → verify response signature (caller side).

    REAL vs simulated: the policy engine, the MCP gateway, the assertion recipient/expiry
    binding shape, and the PII-scan tool all run for real. The Ed25519 sign/verify, the
    AgentMesh registry trust lookup, and the JWKS issuer validation are simulated (they need
    live infra), exactly as tests/test_a2a_tool.py does — so this is the governed delegation
    path minus only the asymmetric-crypto + socket cost, which the report calls out explicitly.

    Returns the structured results (same stat shape as the local benchmark) and includes a
    comparison against the LOCAL governed p50 from results_local.json (the cost of the secure
    cross-agent hop). Hermetic; never touches the network.
    """
    _quiet_logging()
    local_tools.ensure_local_servers_registered()

    # Import the app + its patch points lazily (after the env/path bootstrap at module top).
    from httpx import ASGITransport, AsyncClient

    from api import main

    # A signed /a2a/tool body. The real signature is simulated by the verify stub below; the
    # application fields (capability + arguments + recipient-bound assertion) are real and are
    # what the endpoint validates and runs.
    def _make_body() -> dict[str, Any]:
        return {
            "capability": "tool.pii",
            "arguments": {"text": "Contact alice@example.com, card 4242424242424242."},
            "source_division": "division-b",
            "user_assertion": {
                "sub": "x", "email": "alice@example.com", "email_verified": True,
                "iss": _PEER_ISSUER, "aud": _SELF_DID, "exp": 9999999999,
            },
            "_agentmesh": {"sender_did": _PEER_DID, "signature": "sig", "alg": "EdDSA"},
        }

    # ── Simulated crypto/identity/registry seams (the live-infra-only gates) ──
    async def fake_verify_signed(payload: dict) -> tuple[bool, str]:
        return (True, _PEER_DID)

    async def fake_verify_peer(did: str) -> tuple[bool, float]:
        return (True, 0.99)

    async def fake_get_did() -> str:
        return _SELF_DID

    async def fake_sign(obj: dict) -> dict:
        # SEND-side + receiver-side signing seam (Ed25519 simulated). Returns a signed-shaped
        # object so the response-signature verify on the caller passes.
        return {**obj, "_agentmesh": {"sender_did": _SELF_DID, "signature": "s", "alg": "EdDSA"}}

    def fake_validate(assertion: dict, *, expected_issuer: str, expected_audience: str,
                      **kw: Any) -> str:
        # Real recipient-binding CHECK (aud must equal self DID) — the binding shape is
        # exercised; only the JWKS/issuer crypto is simulated.
        if assertion.get("aud") != expected_audience:
            raise ValueError("aud mismatch")
        return _USER_ID

    class _FakeRedis:
        def __init__(self) -> None:
            self.kv: dict = {}
        async def get(self, k: Any) -> Any:
            return self.kv.get(k)
        async def set(self, k: Any, v: Any) -> None:
            self.kv[k] = v
        async def setex(self, k: Any, ttl: Any, v: Any) -> None:
            self.kv[k] = v

    fake_redis = _FakeRedis()

    async def fake_get_redis() -> Any:
        return fake_redis

    import json as _json

    samples: list[float] = []
    with _patched() as p:
        p.set(main.settings, "agent_kill_switch_engaged", False)
        p.set(main.settings, "division_id", "bench-alpha")
        p.set(main.settings, "agent_trust_threshold", 0.5)
        p.set(main.settings, "peer_trust_map", _json.dumps(
            {_PEER_DID: {"issuer": _PEER_ISSUER, "public_jwk": "",
                         "agent_url": "http://bench-peer-b", "division_id": "division-b"}}))
        p.set(main.agent_identity, "verify_signed_message", fake_verify_signed)
        p.set(main.agent_identity, "verify_peer_identity", fake_verify_peer)
        p.set(main.agent_identity, "get_did", fake_get_did)
        p.set(main.agent_identity, "sign_outbound_message", fake_sign)
        p.set(main, "validate_cross_division_assertion", fake_validate)
        p.set(main, "_get_redis", fake_get_redis)

        transport = ASGITransport(app=main.app)
        async with AsyncClient(transport=transport, base_url="http://bench") as client:

            async def _one_roundtrip() -> None:
                # SEND side: sign the outbound tool request (Ed25519 seam), then POST it to the
                # receiver over ASGITransport; the receiver runs the full governed path and
                # returns a signed response, which we then verify (caller-side signature check).
                body = _make_body()
                signed_request = await main.agent_identity.sign_outbound_message(body)
                resp = await client.post("/a2a/tool", json=signed_request)
                data = resp.json()
                ok, signer = await main.agent_identity.verify_signed_message(data)
                if not ok or data.get("status") != "completed":
                    raise RuntimeError(f"delegated round-trip did not complete: {data!r}")

            # Warmup (discarded) — primes policy/gateway caches + the ASGI app path.
            await _time_async(_one_roundtrip, _WARMUP_ITERS)
            samples = await _time_async(_one_roundtrip, iters)

    delegated = _summarize(samples)

    # Comparison line: delegated p50 vs the LOCAL governed p50 (cost of the secure hop).
    local_governed_p50 = None
    if _RESULTS_PATH.exists():
        try:
            local = json.loads(_RESULTS_PATH.read_text(encoding="utf-8"))
            for case in local.get("cases", []):
                if case.get("server") == "pii-scan":
                    local_governed_p50 = case["governed"]["p50"]
                    break
        except Exception:
            local_governed_p50 = None

    comparison = None
    if local_governed_p50:
        comparison = {
            "local_governed_p50_us": local_governed_p50,
            "delegated_p50_us": delegated["p50"],
            "secure_hop_overhead_us": delegated["p50"] - local_governed_p50,
            "delegated_over_local_x": delegated["p50"] / local_governed_p50,
        }

    return {
        "scope": "delegated_cross_agent_path",
        "iterations": iters,
        "warmup": _WARMUP_ITERS,
        "transport": "httpx ASGITransport (in-process, no network)",
        "note": "Full governed /a2a/tool round-trip: sign -> POST -> verify+trust+assertion+"
                "policy+run_local_tool -> signed response -> verify. REAL policy engine, MCP "
                "gateway, assertion recipient-binding, and PII-scan tool; SIMULATED Ed25519 "
                "sign/verify + AgentMesh registry trust + JWKS issuer validation (live-infra "
                "seams, stubbed exactly as tests/test_a2a_tool.py does).",
        "capability": "tool.pii",
        "delegated": delegated,
        "comparison_to_local": comparison,
    }


def print_delegated_table(results: dict[str, Any]) -> None:
    """Print the delegated-path benchmark table + the local-vs-delegated comparison line."""
    print("\nAGT DELEGATED cross-agent tool benchmark (latencies in microseconds, µs)")
    print(f"iterations={results['iterations']} warmup={results['warmup']} "
          f"scope={results['scope']}")
    print(f"transport={results['transport']}")
    header = (f"  {'variant':<12} {'count':>7} {'mean':>10} {'p50':>10} {'p95':>10} "
              f"{'p99':>10} {'min':>10} {'max':>10}")
    print(f"\n[{results['capability']}]  (delegated /a2a/tool round-trip)")
    print(header)
    print("  " + "-" * (len(header) - 2))
    print(_fmt_row("delegated", results["delegated"]))
    comp = results.get("comparison_to_local")
    if comp:
        print(f"\n  local governed p50:  {comp['local_governed_p50_us']:>10.2f} µs")
        print(f"  delegated     p50:   {comp['delegated_p50_us']:>10.2f} µs")
        print(f"  secure cross-agent hop overhead: +{comp['secure_hop_overhead_us']:.2f} µs "
              f"({comp['delegated_over_local_x']:.1f}x the local governed call)")
    else:
        print("\n  (no results_local.json found — run the local benchmark first for the "
              "comparison line)")
    print()


_USAGE = ("usage: python -m bench.bench_tools [local|delegated|all] [iterations]\n"
          "  local      — raw vs governed local tool path (default; writes results_local.json)\n"
          "  delegated  — cross-agent /a2a/tool round-trip (writes results_delegated.json)\n"
          "  all        — run both")


def _parse_args(argv: list[str]) -> tuple[str, int] | None:
    """Parse [mode] [iters]. Either may be omitted; mode defaults to 'local', iters to the
    default. Returns (mode, iters) or None on a usage error."""
    mode = "local"
    iters = _DEFAULT_ITERS
    rest = list(argv)
    if rest and rest[0] in ("local", "delegated", "all"):
        mode = rest.pop(0)
    if rest:
        try:
            iters = int(rest[0])
        except ValueError:
            return None
        if iters < 1:
            return None
    return mode, iters


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parsed = _parse_args(argv)
    if parsed is None:
        print(_USAGE, file=sys.stderr)
        return 2
    mode, iters = parsed

    if mode in ("local", "all"):
        results = asyncio.run(run_benchmark(iters))
        print_table(results)
        _RESULTS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"wrote {_RESULTS_PATH}")

    if mode in ("delegated", "all"):
        d_results = asyncio.run(bench_delegated(iters))
        print_delegated_table(d_results)
        _RESULTS_DELEGATED_PATH.write_text(json.dumps(d_results, indent=2), encoding="utf-8")
        print(f"wrote {_RESULTS_DELEGATED_PATH}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
