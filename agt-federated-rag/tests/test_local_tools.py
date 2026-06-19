"""In-process governed tool registry tests (local_tools.py).

Two concerns:
  1. the tools compute correctly (calc / units) — and the calc evaluator is a real
     sandbox: the security tests below pin that non-whitelisted constructs are rejected
     (these are the sandbox-escape guards — do NOT relax them).
  2. execution flows through the governed executor: run_local_tool passes every gate
     (policy → gateway → §4.2 credential boundary) and an unconfigured server / a
     credential-bearing argument still fails closed through the new path.
"""
from __future__ import annotations

import asyncio

import pytest

from tools import local_tools
from tools import mcp as mcp_tools
from tools.local_tools import calc, units


def _patch_enforce_ok(monkeypatch):
    async def ok(action, ctx):
        return None
    monkeypatch.setattr("agent.nodes._enforce", ok)


# ── calc: correctness ─────────────────────────────────────────────────────────
def test_calc_arithmetic():
    assert calc({"expression": "2+3*4"})["result"] == 14
    assert calc({"expression": "(2+3)*4"})["result"] == 20
    assert calc({"expression": "7 // 2"})["result"] == 3
    assert calc({"expression": "7 % 3"})["result"] == 1
    assert calc({"expression": "-5 + 2"})["result"] == -3


def test_calc_functions_and_constants():
    assert calc({"expression": "sqrt(16)"})["result"] == 4.0
    assert calc({"expression": "max(1, 2, 3)"})["result"] == 3
    assert calc({"expression": "abs(-7)"})["result"] == 7
    assert calc({"expression": "floor(3.9)"})["result"] == 3
    assert abs(calc({"expression": "cos(0)"})["result"] - 1.0) < 1e-9
    assert abs(calc({"expression": "pi"})["result"] - 3.14159265) < 1e-6


def test_calc_echoes_expression():
    out = calc({"expression": "1+1"})
    assert out == {"result": 2, "expression": "1+1"}


# ── calc: SECURITY — sandbox-escape guards (the important tests) ───────────────
# Each of these is a construct an eval()-based evaluator would happily run. The AST
# evaluator must REJECT every one with ValueError. Loosening any of these reopens a
# sandbox escape, so they are load-bearing.
@pytest.mark.parametrize("expr", [
    "__import__('os')",            # dunder builtin / call to non-whitelisted name
    "__import__('os').system('x')",
    "(1).__class__",               # attribute access -> type traversal
    "().__class__.__bases__",      # the classic sandbox-escape chain
    "os.system('x')",              # attribute access on a bare name
    "os",                          # bare name not in the constant whitelist
    "open('f')",                   # non-whitelisted function call
    "eval('1')",                   # non-whitelisted function call
    "[x for x in range(3)]",       # comprehension
    "lambda: 1",                   # lambda
    "{1: 2}",                      # dict literal
    "'a' * 3",                     # non-numeric (string) literal
    "globals()",                   # non-whitelisted function call
])
def test_calc_rejects_sandbox_escapes(expr):
    with pytest.raises(ValueError):
        calc({"expression": expr})


def test_calc_rejects_huge_exponent():
    # DoS guard: a giant power tower must be rejected BEFORE it is computed.
    with pytest.raises(ValueError):
        calc({"expression": "9**9**9"})
    with pytest.raises(ValueError):
        calc({"expression": "2 ** 5000"})
    # A modest exponent within the bound is still fine.
    assert calc({"expression": "2 ** 10"})["result"] == 1024


# ── F1 (HIGH/DoS): the pow()/exp() FUNCTIONS must respect the same exponent bound as `**` ──
# The whitelisted pow()/exp() bypass the `**` operator, so without a call-site magnitude check
# pow(2,5000) builds a 1506-digit int and pow(2,999999999)/exp(1e9) hang or overflow. These are
# the sandbox-escape DoS guards — do NOT relax them.
import time as _time          # noqa: E402 — used by the FAST-rejection timing assertions


def test_calc_pow_function_respects_exponent_bound():
    with pytest.raises(ValueError):
        calc({"expression": "pow(2, 5000)"})        # bypassed the ** bound before the fix
    assert calc({"expression": "pow(2, 10)"})["result"] == 1024   # legit pow still works


def test_calc_pow_giant_exponent_is_rejected_FAST_not_hung():
    # The repro hung >4s pre-fix. Assert it is rejected effectively instantly (bound checked
    # BEFORE the int is materialised) — a generous ceiling that still fails a hang.
    t0 = _time.perf_counter()
    with pytest.raises(ValueError):
        calc({"expression": "pow(2, 999999999)"})
    assert _time.perf_counter() - t0 < 1.0, "pow() giant exponent should reject fast, not hang"


def test_calc_exp_giant_argument_is_rejected_FAST_not_hung():
    # exp(1000000000) overflows/DoS without an arg bound. Must reject fast, never hang/overflow.
    t0 = _time.perf_counter()
    with pytest.raises(ValueError):
        calc({"expression": "exp(1000000000)"})
    assert _time.perf_counter() - t0 < 1.0, "exp() giant arg should reject fast, not hang"


def test_calc_rejects_giant_int_result_via_chained_ops():
    # Defence-in-depth result bound: a giant int reachable through ops that each pass the
    # per-** exponent bound (so the bound alone wouldn't catch it) is still refused.
    with pytest.raises(ValueError):
        calc({"expression": "(10**1000)**100"})     # ~332k bits, exponent 100 is "allowed"


def test_calc_successful_results_are_finite_and_bounded():
    # Every accepted numeric result must be finite (no inf/nan) and within the int bit cap.
    import math as _math
    for expr, _ in [("2+3*4", 14), ("sqrt(16)", 4.0), ("pow(2, 100)", None),
                    ("exp(5)", None), ("log(e)", None), ("2 ** 1000", None)]:
        r = calc({"expression": expr})["result"]
        if isinstance(r, float):
            assert _math.isfinite(r), f"{expr!r} produced a non-finite float"
        if isinstance(r, int):
            assert r.bit_length() <= 13_330, f"{expr!r} produced an over-large int"


def test_calc_rejects_oversized_input():
    with pytest.raises(ValueError):
        calc({"expression": "1+" * 500 + "1"})


def test_calc_rejects_non_string_expression():
    with pytest.raises(ValueError):
        calc({"expression": 123})


# ── units: correctness ────────────────────────────────────────────────────────
def test_units_length():
    assert units({"value": 1, "from": "km", "to": "m"})["result"] == 1000.0
    assert units({"value": 100, "from": "cm", "to": "m"})["result"] == 1.0
    assert abs(units({"value": 1, "from": "ft", "to": "in"})["result"] - 12.0) < 1e-9


def test_units_mass():
    assert units({"value": 1, "from": "kg", "to": "g"})["result"] == 1000.0
    assert abs(units({"value": 1, "from": "lb", "to": "oz"})["result"] - 16.0) < 1e-6


def test_units_temperature():
    assert units({"value": 0, "from": "C", "to": "F"})["result"] == 32.0
    assert units({"value": 100, "from": "C", "to": "F"})["result"] == 212.0
    assert units({"value": 0, "from": "C", "to": "K"})["result"] == 273.15
    assert abs(units({"value": 32, "from": "F", "to": "C"})["result"]) < 1e-9


def test_units_incompatible_or_unknown_raises():
    with pytest.raises(ValueError):
        units({"value": 1, "from": "m", "to": "kg"})      # cross-dimension
    with pytest.raises(ValueError):
        units({"value": 1, "from": "m", "to": "furlong"})  # unknown unit
    with pytest.raises(ValueError):
        units({"value": "x", "from": "m", "to": "km"})     # non-numeric value


def test_units_echoes_fields():
    out = units({"value": 2, "from": "km", "to": "m"})
    assert out == {"result": 2000.0, "from": "km", "to": "m", "value": 2}


# ── registry helpers ──────────────────────────────────────────────────────────
def test_capability_mapping():
    assert local_tools.capability_for("local-calc") == "tool.calc"
    assert local_tools.capability_for("local-units") == "tool.units"
    assert local_tools.capability_for("nope") is None
    assert local_tools.server_for_capability("tool.calc") == "local-calc"
    assert local_tools.server_for_capability("tool.units") == "local-units"
    assert local_tools.server_for_capability("tool.nope") is None


def test_local_server_configs_shape():
    configs = {c["name"]: c for c in local_tools.local_server_configs()}
    assert set(configs) == {"local-calc", "local-units"}
    calc_cfg = configs["local-calc"]
    assert calc_cfg["auth_mode"] == "service_rebac"
    assert calc_cfg["require_tls"] is False
    assert calc_cfg["url"] == ""
    assert calc_cfg["capability"] == "tool.calc"
    assert "calc" in calc_cfg["tools"]


# ── execution through the governance gates ────────────────────────────────────
def test_run_local_tool_executes_through_gates(monkeypatch):
    _patch_enforce_ok(monkeypatch)
    # Start from a clean (empty) mcp_servers; run_local_tool registers the locals itself.
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()

    out = asyncio.run(local_tools.run_local_tool("local-calc", "calc", {"expression": "2+3*4"}))
    assert out == {"result": 14, "expression": "2+3*4"}

    out = asyncio.run(local_tools.run_local_tool("local-units", "units",
                                                 {"value": 1, "from": "km", "to": "m"}))
    assert out["result"] == 1000.0


def test_ensure_local_servers_registered_is_idempotent(monkeypatch):
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    local_tools.ensure_local_servers_registered()
    import json
    first = json.loads(mcp_tools.settings.mcp_servers)
    names = sorted(s["name"] for s in first)
    assert names == ["local-calc", "local-units"]
    # Calling again does not duplicate entries.
    local_tools.ensure_local_servers_registered()
    second = json.loads(mcp_tools.settings.mcp_servers)
    assert len(second) == len(first)


def test_ensure_local_servers_preserves_existing(monkeypatch):
    # An already-configured (real) MCP server must survive the merge.
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers",
                        '[{"name":"jira","url":"https://mcp/jira","allowed_auth_methods":["oauth2"]}]')
    mcp_tools.reset_cache()
    local_tools.ensure_local_servers_registered()
    import json
    names = sorted(s["name"] for s in json.loads(mcp_tools.settings.mcp_servers))
    assert names == ["jira", "local-calc", "local-units"]


def test_stale_gateway_is_reset_so_local_tool_does_not_spuriously_fail(monkeypatch):
    """Regression (ordering hazard): a gateway cached from a DIFFERENT settings.mcp_servers
    that lacked the local servers must NOT cause run_local_tool to fail closed once settings
    list the local servers again. ensure_local_servers_registered detects the stale cache and
    resets it. Order-independent on its OWN — no autouse reset crutch needed.

    SAFETY of the failure direction is also asserted: the stale gateway only ever fails CLOSED
    (legitimate call rejected), never fail-OPEN — proven by the separate unconfigured-server
    test; here we prove the reliability fix removes the spurious closed-failure."""
    _patch_enforce_ok(monkeypatch)
    import json

    # 1. Warm the executor's gateway from a settings value WITHOUT the local servers (as a
    #    prior suite would, e.g. an mcp_servers monkeypatched to just 'jira').
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers",
                        '[{"name":"jira","url":"https://mcp/jira","allowed_auth_methods":["oauth2"]}]')
    mcp_tools.reset_cache()
    mcp_tools._load_servers()                       # builds + CACHES the stale gateway
    assert "local-calc" not in (mcp_tools._server_cfg or {})   # cache predates our servers

    # 2. Now settings DOES list the local servers (as after a revert + a registration), but the
    #    cached gateway is stale. The OLD code returned early here and never reset the cache.
    settings_with_locals = json.dumps(
        [{"name": "jira", "url": "https://mcp/jira", "allowed_auth_methods": ["oauth2"]}]
        + local_tools.local_server_configs()
    )
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", settings_with_locals)

    # 3. run_local_tool calls ensure_local_servers_registered, which must spot the stale
    #    gateway and reset it so the call succeeds rather than raising "not configured".
    out = asyncio.run(local_tools.run_local_tool("local-calc", "calc", {"expression": "2+3*4"}))
    assert out == {"result": 14, "expression": "2+3*4"}
    # The gateway was rebuilt and now includes the local servers (jira preserved too).
    assert {"jira", "local-calc", "local-units"}.issubset(set(mcp_tools._server_cfg or {}))


def test_unconfigured_server_fails_closed_via_local_caller(monkeypatch):
    # Governance still applies when wiring local_caller directly: a server that is NOT in
    # settings.mcp_servers is rejected at the gateway (gate 2) before local_caller runs.
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")  # nothing configured
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(mcp_tools.call_mcp_tool("local-calc", "calc", {"expression": "1+1"},
                                            caller=local_tools.local_caller))


def test_policy_denial_blocks_local_tool(monkeypatch):
    # Gate 1 (policy default-deny) still fires for local tools.
    async def deny(action, ctx):
        raise PermissionError("policy denied")
    monkeypatch.setattr("agent.nodes._enforce", deny)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    with pytest.raises(PermissionError):
        asyncio.run(local_tools.run_local_tool("local-calc", "calc", {"expression": "1+1"}))


def test_credential_in_arguments_fails_closed_via_run_local_tool(monkeypatch):
    # §4.2 boundary holds through the new path: a credential field in the arguments is
    # refused (McpToolError) before the tool runs. Proves the guard isn't bypassed.
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(local_tools.run_local_tool("local-calc", "calc",
                                               {"expression": "1+1", "token": "SECRET"}))


def test_unknown_tool_on_local_server_fails_closed(monkeypatch):
    # A configured server but a tool name it does not serve → McpToolError from local_caller.
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(local_tools.run_local_tool("local-calc", "nonexistent", {"expression": "1+1"}))


def test_arithmetic_error_wraps_to_mcptoolerror(monkeypatch):
    # F3 (contract): an ArithmeticError from the tool (ZeroDivisionError "1/0", or an
    # OverflowError) must surface as McpToolError through the governed path — NOT leak as a
    # raw arithmetic exception. local_caller wraps (ValueError, ArithmeticError).
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(local_tools.run_local_tool("local-calc", "calc", {"expression": "1/0"}))
