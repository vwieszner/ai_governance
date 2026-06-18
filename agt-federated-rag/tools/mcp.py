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

CANONICAL PER-SERVER AUTH (the documented default — THREAT_MODEL §4.2). A live MCP server +
IdP OBO endpoint isn't available to build against here, so this is the CONTRACT a deployment's
injected ``caller`` MUST implement, per the server's ``auth_mode``:

  oauth_obo  (server is an OAuth 2.0 resource server) — the caller performs an RFC 8693
    token EXCHANGE at the IdP: it presents the AGENT's own credential together with the
    user's subject token and receives a NEW, audience-restricted access token scoped to the
    target MCP server. ONLY that exchanged token is sent. The user's original token is the
    INPUT to the exchange at the IdP — it is never placed on the wire to the MCP server. The
    MCP server (the resource owner) then enforces the user's OWN permissions. This is the
    preferred mode whenever the server speaks OAuth.

  service_rebac  (legacy / non-OAuth server) — the caller authenticates with a SERVICE
    credential (the agent's identity, not the user's) and the agent mediates authorization
    itself: results are mapped to OpenFGA authorization objects and filtered per-user (ReBAC)
    before anything reaches the LLM (gate 3 below). The user's token never leaves the agent.

In BOTH modes the raw user token stops at the agent boundary. This module enforces that
boundary structurally: ``call_mcp_tool`` has no user-token parameter, so the executor CANNOT
forward one, and it guards the outbound ``arguments`` against an accidentally-threaded
credential (see ``_assert_no_user_credential``). Token acquisition lives in the injected
``caller`` precisely so the no-forward invariant is provable at THIS layer.
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


# Argument keys that would smuggle a raw user credential into the outbound call. The executor
# never threads a user token (it has no such parameter), but a buggy caller could put one in
# the tool ARGUMENTS — this catches that fail-closed so the no-forward invariant (§4.2) holds
# structurally, not just by convention.
_CREDENTIAL_ARG_KEYS = frozenset({
    "authorization", "access_token", "id_token", "refresh_token", "bearer", "token",
    "user_token", "jwt", "assertion", "api_key", "apikey", "password", "secret",
})


def _assert_no_user_credential(arguments: dict) -> None:
    """Refuse to execute if the tool arguments carry a raw credential (fail-closed).

    Guards the §4.2 'never forward the raw user token' invariant at the OUTBOUND boundary:
    auth belongs in the injected ``caller`` (OBO exchange / service credential), NEVER in the
    tool arguments. Case-insensitive key match; raises ``McpToolError`` on a hit."""
    for k in arguments:
        if isinstance(k, str) and k.strip().lower() in _CREDENTIAL_ARG_KEYS:
            raise McpToolError(
                f"refusing to forward MCP arguments containing a credential field {k!r} — "
                f"auth must be acquired by the caller (OBO/service credential), not passed "
                f"through tool arguments (THREAT_MODEL §4.2)."
            )


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
    # Boundary invariant (§4.2): the outbound arguments must not smuggle a user credential —
    # auth is the caller's job (OBO exchange / service credential), never tool arguments.
    _assert_no_user_credential(args)
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
