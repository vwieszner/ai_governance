"""Governed MCP tool executor (Phase-1 item 11).

One executor node for ALL MCP tools — individual tools/servers are CONFIG
(``settings.mcp_servers``) + a policy decision, never new nodes. Every call passes three
gates before the request leaves the process:

  1. policy engine  — `_enforce("mcp.call", {server, tool})`; default-deny means an action
     not allow-listed (or a context a deny rule matches) is refused.
  2. MCP gateway    — the toolkit's `McpAuthPolicy` (per-server allowlist + required auth
     method + TLS). An UNCONFIGURED server is rejected (fail-closed).
  3. (caller) OpenFGA — results are treated like retrieval: the caller maps them to
     authorization objects and filters per-user before anything reaches the LLM.

SECURITY — the user's RAW token is NEVER forwarded to the MCP server (the M2 assertion-
relay lesson). Per-server ``auth_mode`` selects how the call authenticates:
  - "oauth_obo"     : token-exchange (on-behalf-of) at the IdP for a server-scoped token,
                      so the SOURCE enforces the user's own permissions; or
  - "service_rebac" : a service credential + agent-side OpenFGA filtering of results.
The actual transport is injected (``caller``) so this module stays testable and
protocol-agnostic; a real deployment passes an MCP/HTTP client.
"""
from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

import structlog

from config import settings

log = structlog.get_logger(__name__)

_gateway: Any = None          # toolkit McpAuthPolicy, built once from settings.mcp_servers
_server_cfg: dict[str, dict] = {}


def _load_servers() -> tuple[Any, dict[str, dict]]:
    """Build the McpAuthPolicy gateway + a name->config map from settings.mcp_servers."""
    global _gateway, _server_cfg
    if _gateway is not None:
        return _gateway, _server_cfg
    from agent_os.mcp_auth_enforcement import McpAuthPolicy, McpServerEntry

    policy = McpAuthPolicy()
    cfg: dict[str, dict] = {}
    raw = (settings.mcp_servers or "").strip()
    if raw:
        for s in json.loads(raw):
            policy.add_server(McpServerEntry(
                name=s["name"],
                url=s.get("url", ""),
                allowed_auth_methods=s.get("allowed_auth_methods", ["oauth"]),
                require_tls=s.get("require_tls", True),
                min_tls_version=s.get("min_tls_version", "1.2"),
            ))
            cfg[s["name"]] = s
    _gateway, _server_cfg = policy, cfg
    return _gateway, _server_cfg


def reset_cache() -> None:
    """Test hook: drop the cached gateway so a new settings.mcp_servers is picked up."""
    global _gateway, _server_cfg
    _gateway, _server_cfg = None, {}


class McpToolError(Exception):
    pass


async def call_mcp_tool(
    server: str,
    tool: str,
    arguments: dict | None = None,
    *,
    caller: Callable[[dict, str, dict], Awaitable[Any]] | None = None,
) -> Any:
    """Invoke an MCP tool through the governance gates. Raises McpToolError / PermissionError
    on any gate failure (fail-closed). ``caller(server_cfg, tool, arguments)`` performs the
    actual transport; without it the function validates + refuses (no silent no-op)."""
    from agent.nodes import _enforce  # local import: avoids a heavy import cycle at module load

    args = arguments or {}
    # Gate 1: policy engine (default-deny).
    await _enforce("mcp.call", {"server": server, "tool": tool})

    # Gate 2: MCP gateway — server must be configured + its auth method allowed.
    gateway, cfg = _load_servers()
    sc = cfg.get(server)
    if sc is None:
        log.warning("mcp_server_not_configured", server=server, agt_audit=True)
        raise McpToolError(f"MCP server '{server}' is not configured (fail-closed)")
    auth_method = sc.get("allowed_auth_methods", ["oauth"])[0]
    result = gateway.check(server, auth_method, sc.get("url", ""))
    if not getattr(result, "allowed", False):
        log.warning("mcp_gateway_denied", server=server, reason=getattr(result, "reason", ""),
                    agt_audit=True)
        raise McpToolError(f"MCP gateway denied '{server}': {getattr(result, 'reason', '')}")

    log.info("mcp_call", server=server, tool=tool, auth_mode=sc.get("auth_mode", "oauth_obo"),
             agt_audit=True)
    if caller is None:
        # No transport wired (e.g. unit/validation): the call is governed-OK but not executed.
        raise McpToolError("no MCP transport configured for this call")
    return await caller(sc, tool, args)
