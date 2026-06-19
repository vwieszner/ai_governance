"""In-process governed tool registry — real, deterministic local tools.

The governed MCP executor (``tools.mcp.call_mcp_tool``) is transport-agnostic: it runs
the three governance gates (policy default-deny → McpAuthPolicy gateway → the §4.2
no-credential boundary) and then delegates the actual call to an injected ``caller``.
Until now no in-process ``caller`` existed, so ``call_mcp_tool`` always raised "no MCP
transport configured". This module provides that transport for a small set of SAFE,
dependency-light, pure-compute tools so the agent can actually EXECUTE work end-to-end
through every gate — and so different divisions can advertise DIFFERENT capabilities
(``tool.calc``, ``tool.units``) for cross-agent tool delegation.

Each local server is registered into ``settings.mcp_servers`` exactly like a real MCP
server (so the gateway treats it as configured). It authenticates with the agent's own
SERVICE credential — ``auth_mode: "service_rebac"`` — which is why ``url`` is empty,
``require_tls`` is False (the call never leaves the process) and the gateway auth method
is ``bearer`` (a service credential; the gateway has no "in-process" method). No network,
no filesystem: every tool is a deterministic function of its arguments.
"""
from __future__ import annotations

import ast
import math
from typing import Any, Callable

from tools.mcp import McpToolError

# ── calc: a SAFE arithmetic evaluator (NO eval/exec) ──────────────────────────
# We walk the parsed AST and permit ONLY a fixed grammar (numeric literals, the listed
# binary/unary operators, parentheses, and a whitelist of math functions/constants).
# Anything outside that — names, attribute access (``__class__``), arbitrary calls,
# comprehensions, subscripts, etc. — raises ValueError. This is the sandbox boundary:
# treat every addition to the whitelists as a security decision.
_MAX_EXPR_LEN = 256            # cap input size (DoS / pathological-parse guard)
_MAX_POW_EXPONENT = 1000       # cap exponentiation magnitude (** operator AND pow()/exp())
# General defensive cap on any integer result's size. A short (<=256-char) expression must
# never be able to materialise a giant int (CPU/memory DoS) — even via a chain of * that
# individually pass the per-** bound. 13_330 bits ≈ 4000 decimal digits: comfortably above any
# legitimate calculator result, far below a hang. Float results are separately required FINITE.
_MAX_RESULT_BITS = 13_330


def _check_result_bounds(value: float) -> float:
    """Defence-in-depth result guard (DoS / inf / nan): reject a giant int or a non-finite
    float so no <=256-char expression can hang or yield an unusable value. Applied after every
    exponentiation, every whitelisted call, and at the top-level result. Allowlist-spirit:
    ordinary calculator results pass untouched; only pathological magnitudes are refused."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value.bit_length() > _MAX_RESULT_BITS:
            raise ValueError(
                f"integer result is too large ({value.bit_length()} bits > "
                f"{_MAX_RESULT_BITS}) — refusing (DoS guard)"
            )
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("result is not a finite number (inf/nan) — refusing")
    return value

# Whitelisted callables (name -> function). Only these may be CALLED.
_CALC_FUNCS: dict[str, Callable[..., float]] = {
    "sqrt": math.sqrt, "sin": math.sin, "cos": math.cos, "tan": math.tan,
    "log": math.log, "exp": math.exp, "floor": math.floor, "ceil": math.ceil,
    "abs": abs, "pow": pow, "min": min, "max": max,
}
# Whitelisted constants (name -> value). Only these bare names resolve.
_CALC_CONSTS: dict[str, float] = {"pi": math.pi, "e": math.e}

# Whitelisted operators. ``**`` is included but its exponent magnitude is bounded below.
_BIN_OPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
    ast.Pow: None,  # handled specially (exponent bound) in _calc_eval
}
_UNARY_OPS = {
    ast.UAdd: lambda a: +a,
    ast.USub: lambda a: -a,
}


def _calc_eval(node: ast.AST) -> float:
    """Recursively evaluate a whitelisted AST node. Raises ValueError on anything
    outside the permitted grammar (the sandbox-escape boundary)."""
    if isinstance(node, ast.Expression):
        return _calc_eval(node.body)
    # Numeric literals only (no strings, bytes, lists, dicts, ...).
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise ValueError(f"non-numeric literal not allowed: {node.value!r}")
        return node.value
    # Bare names resolve ONLY to whitelisted constants — never to builtins/globals.
    if isinstance(node, ast.Name):
        if node.id in _CALC_CONSTS:
            return _CALC_CONSTS[node.id]
        raise ValueError(f"name {node.id!r} is not a permitted constant")
    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _BIN_OPS:
            raise ValueError(f"operator {op_type.__name__} not allowed")
        left = _calc_eval(node.left)
        right = _calc_eval(node.right)
        if op_type is ast.Pow:
            # Bound the exponent magnitude BEFORE computing (DoS guard: 9**9**9).
            if abs(right) > _MAX_POW_EXPONENT:
                raise ValueError(
                    f"exponent {right} exceeds the maximum allowed ({_MAX_POW_EXPONENT})"
                )
            return _check_result_bounds(left ** right)
        return _check_result_bounds(_BIN_OPS[op_type](left, right))
    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _UNARY_OPS:
            raise ValueError(f"unary operator {op_type.__name__} not allowed")
        return _UNARY_OPS[op_type](_calc_eval(node.operand))
    # Calls: ONLY to a whitelisted function by bare name. No attribute access
    # (``math.sqrt`` / ``().__class__``), no keyword args, no *args/**kwargs.
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValueError("only direct calls to whitelisted functions are allowed")
        fname = node.func.id
        if fname not in _CALC_FUNCS:
            raise ValueError(f"function {fname!r} is not whitelisted")
        if node.keywords:
            raise ValueError("keyword arguments are not allowed")
        args = [_calc_eval(a) for a in node.args]
        # SECURITY (F1): the whitelisted pow()/exp() bypass the `**` operator's exponent
        # bound, so the magnitude check must be re-applied at the CALL site BEFORE computing —
        # pow(2, 5000) builds a 1506-digit int and pow(2, 999999999) / exp(1e9) hang or
        # overflow. Bound the exponent (pow, 2nd arg) and the exponent-of-e (exp, sole arg).
        if fname == "pow" and len(args) >= 2 and abs(args[1]) > _MAX_POW_EXPONENT:
            raise ValueError(
                f"pow() exponent {args[1]} exceeds the maximum allowed ({_MAX_POW_EXPONENT})"
            )
        if fname == "exp" and args and abs(args[0]) > _MAX_POW_EXPONENT:
            raise ValueError(
                f"exp() argument {args[0]} exceeds the maximum allowed ({_MAX_POW_EXPONENT})"
            )
        return _check_result_bounds(_CALC_FUNCS[fname](*args))
    # Everything else (Attribute, Subscript, comprehensions, lambdas, ...) is rejected.
    raise ValueError(f"expression element {type(node).__name__} is not allowed")


def calc(arguments: dict) -> dict:
    """Evaluate a math ``{"expression": "..."}`` via the SAFE AST evaluator.

    Returns ``{"result": <number>, "expression": <echoed>}``. Raises ValueError on a
    malformed/oversized expression or any non-whitelisted construct."""
    expr = arguments.get("expression")
    if not isinstance(expr, str):
        raise ValueError("'expression' must be a string")
    if len(expr) > _MAX_EXPR_LEN:
        raise ValueError(f"expression too long ({len(expr)} > {_MAX_EXPR_LEN})")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"invalid expression: {exc}") from exc
    # Final defensive bound on the top-level result (covers any path, incl. a bare literal).
    result = _check_result_bounds(_calc_eval(tree))
    return {"result": result, "expression": expr}


# ── units: a deterministic unit-conversion table ──────────────────────────────
# Length and mass convert through a base unit (metre / gram) via a fixed factor.
# Temperature is affine, so it gets its own (to_C, from_C) pair per unit.
_LENGTH_TO_M: dict[str, float] = {
    "m": 1.0, "km": 1000.0, "mi": 1609.344, "ft": 0.3048,
    "in": 0.0254, "cm": 0.01, "mm": 0.001,
}
_MASS_TO_G: dict[str, float] = {
    "g": 1.0, "kg": 1000.0, "lb": 453.59237, "oz": 28.349523125,
}
# Temperature: (to_celsius, from_celsius) so any pair converts via Celsius.
_TEMP: dict[str, tuple[Callable[[float], float], Callable[[float], float]]] = {
    "C": (lambda c: c, lambda c: c),
    "F": (lambda f: (f - 32.0) * 5.0 / 9.0, lambda c: c * 9.0 / 5.0 + 32.0),
    "K": (lambda k: k - 273.15, lambda c: c + 273.15),
}


def units(arguments: dict) -> dict:
    """Convert ``{"value": <num>, "from": "<unit>", "to": "<unit>"}`` across the
    deterministic table. Unknown or incompatible (cross-dimension) units → ValueError.

    Returns ``{"result": <num>, "from": <unit>, "to": <unit>, "value": <num>}``."""
    value = arguments.get("value")
    src = arguments.get("from")
    dst = arguments.get("to")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("'value' must be a number")
    if not isinstance(src, str) or not isinstance(dst, str):
        raise ValueError("'from' and 'to' must be unit strings")

    if src in _LENGTH_TO_M and dst in _LENGTH_TO_M:
        result = value * _LENGTH_TO_M[src] / _LENGTH_TO_M[dst]
    elif src in _MASS_TO_G and dst in _MASS_TO_G:
        result = value * _MASS_TO_G[src] / _MASS_TO_G[dst]
    elif src in _TEMP and dst in _TEMP:
        celsius = _TEMP[src][0](value)
        result = _TEMP[dst][1](celsius)
    else:
        # Either an unknown unit or a cross-dimension pair (e.g. m -> kg).
        raise ValueError(f"cannot convert from {src!r} to {dst!r} (unknown or incompatible units)")
    return {"result": result, "from": src, "to": dst, "value": value}


# ── registry ──────────────────────────────────────────────────────────────────
# server name -> {"capability": "tool.x", <tool_name>: callable}. Each server advertises
# exactly one capability (so capability discovery is a clean server<->capability map);
# the callables are the deterministic functions above.
TOOLS: dict[str, dict[str, Any]] = {
    "local-calc": {"capability": "tool.calc", "calc": calc},
    "local-units": {"capability": "tool.units", "units": units},
}


def capability_for(server: str) -> str | None:
    """Return the capability a local server advertises, or None if not a local server."""
    entry = TOOLS.get(server)
    return entry["capability"] if entry else None


def server_for_capability(cap: str) -> str | None:
    """Return the local server that serves ``cap`` (e.g. "tool.calc"), or None."""
    for server, entry in TOOLS.items():
        if entry["capability"] == cap:
            return server
    return None


async def local_caller(server_cfg: dict, tool: str, arguments: dict) -> Any:
    """Transport ``caller`` for ``tools.mcp.call_mcp_tool`` — dispatches an in-process
    local tool. Pure compute: NO network, NO filesystem.

    ``server_cfg`` is the merged mcp_servers entry; we key off ``server_cfg["name"]``.
    Unknown server or tool → ``McpToolError`` (so a misroute fails closed, consistent
    with the executor's other gate failures)."""
    server = server_cfg.get("name", "")
    entry = TOOLS.get(server)
    if entry is None:
        raise McpToolError(f"local tool server '{server}' is not registered")
    func = entry.get(tool)
    if not callable(func):
        raise McpToolError(f"local tool '{tool}' is not available on server '{server}'")
    try:
        # The registered tools are sync, pure-compute functions; call directly.
        return func(arguments)
    except (ValueError, ArithmeticError) as exc:
        # A tool-level error — a bad expression/unit (ValueError) OR an arithmetic fault
        # like ZeroDivisionError ("1/0") / OverflowError (a math.* overflow). Both are
        # ArithmeticError; wrap BOTH as McpToolError so the governed path surfaces ONE error
        # type and stays fail-closed instead of leaking a raw arithmetic exception (F3).
        raise McpToolError(f"local tool '{server}/{tool}' rejected arguments: {exc}") from exc


def local_server_configs() -> list[dict]:
    """Return the ``settings.mcp_servers`` entries for the local tool servers.

    These get merged into settings.mcp_servers so the McpAuthPolicy gateway treats the
    local servers as CONFIGURED (gate 2). ``auth_mode: "service_rebac"`` is our semantic
    (service credential, no user token); the gateway's ``allowed_auth_methods`` is
    ``["bearer"]`` (a real gateway auth method) and ``require_tls`` is False with an empty
    ``url`` because the call never leaves the process."""
    configs: list[dict] = []
    for server, entry in TOOLS.items():
        tool_names = [k for k in entry if k != "capability"]
        configs.append({
            "name": server,
            "url": "",
            "allowed_auth_methods": ["bearer"],
            "require_tls": False,
            "auth_mode": "service_rebac",
            "capability": entry["capability"],
            "tools": tool_names,
        })
    return configs


def ensure_local_servers_registered() -> None:
    """Idempotently make the local servers usable by the governed executor — in BOTH the
    settings list AND the executor's CACHED gateway.

    The gateway requires every server be in settings.mcp_servers (gate 2). Two states must be
    reconciled, and they are INDEPENDENT:

      (a) settings.mcp_servers is missing a local server → append it.
      (b) the executor's CACHED gateway (``tools.mcp._server_cfg``, built once and reused) is
          missing a local server even though settings now lists it. This happens when another
          test/suite monkeypatched settings.mcp_servers, the executor built+cached a gateway
          from THAT value, and pytest later reverted settings — leaving a warm gateway that
          predates our servers. The old code returned early in this case (names already in
          settings) and never reset the cache, so run_local_tool would resolve the stale
          gateway, not find ``local-calc``/``local-units``, and raise McpToolError
          ("server not configured").

    Reset the cache whenever EITHER hole exists, so the gateway rebuilds from the merged
    settings. FAILURE DIRECTION IS SAFE EITHER WAY: a stale gateway only ever causes a
    legitimate call to fail CLOSED (gate 2 rejects an unconfigured-looking server) — it can
    NEVER make an unconfigured server pass. This fix is purely about reliability (no spurious
    fail-closed for our own registered tools); it does not loosen any gate. Safe to call
    repeatedly; idempotent once the gateway is fresh."""
    import json

    from config import settings
    from tools import mcp as mcp_tools

    raw = (settings.mcp_servers or "").strip()
    existing: list[dict] = []
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                existing = parsed
        except json.JSONDecodeError:
            existing = []

    local_names = {c["name"] for c in local_server_configs()}
    existing_names = {s.get("name") for s in existing if isinstance(s, dict)}
    to_add = [c for c in local_server_configs() if c["name"] not in existing_names]

    # (a) Backfill any local server missing from settings.mcp_servers.
    if to_add:
        settings.mcp_servers = json.dumps(existing + to_add)
        mcp_tools.reset_cache()
        return

    # (b) Settings already lists every local server, but the cached gateway may predate them
    #     (warm cache built from a since-reverted settings value). If the cache is warm and
    #     missing ANY local server, drop it so the next call rebuilds from current settings.
    cached_gateway = getattr(mcp_tools, "_gateway", None)
    if cached_gateway is not None:
        cached_names = set(getattr(mcp_tools, "_server_cfg", {}) or {})
        if not local_names.issubset(cached_names):
            mcp_tools.reset_cache()


async def run_local_tool(server: str, tool: str, arguments: dict) -> Any:
    """Run a LOCAL governed tool end-to-end through ALL governance gates and execute it.

    Delegates to ``tools.mcp.call_mcp_tool`` with ``local_caller`` as the transport, so the
    policy default-deny, the McpAuthPolicy gateway, and the §4.2 no-credential boundary all
    apply before the tool runs. This is the function the agent (and the /a2a/tool endpoint)
    calls to actually execute a tool. Ensures the local servers are registered first."""
    from tools.mcp import call_mcp_tool

    ensure_local_servers_registered()
    return await call_mcp_tool(server, tool, arguments, caller=local_caller)
