"""Governed MCP tool executor (Phase-1 item 11).

One executor node for ALL MCP tools — individual tools/servers are CONFIG
(``settings.mcp_servers``) + a policy decision, never new nodes. Every call passes three
gates before the request leaves the process:

  1. policy engine  — `_enforce("mcp.call", {server, tool, tool_category, agent_trust_score})`;
     default-deny means an action not allow-listed (or a context a deny rule matches) is
     refused. ``tool_category`` (see TOOL CATEGORIES below) feeds block-code-execution,
     block-filesystem-writes and require-classified-tool; ``agent_trust_score`` (the agent
     on whose behalf the call runs) feeds block-low-trust-agents.
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

TOOL CATEGORIES (deterministic, rule-based — never an LLM). ``tool_category(server, tool)``
resolves, in order:
  1. EXPLICIT — the server's ``tool_categories`` map in ``settings.mcp_servers``, e.g.
     ``{"name": "jira", ..., "tool_categories": {"search": "read"}}``. The operator's
     declaration is authoritative (it can classify ``execute_query`` as ``read``). A value
     outside KNOWN_CATEGORIES resolves to ``unclassified``.
  2. LOCAL — an in-process governed tool (tools.local_tools.TOOLS, pure compute, no network
     or filesystem) is ``compute``.
  3. NAME PATTERN — a conservative fallback over the tool name's tokens: exec / shell /
     run_command / eval / subprocess-like names → a code-execution category; write / delete /
     move / rename + file-like names (or rm / mv / unlink / mkdir) → a filesystem category.
  4. otherwise ``unclassified``.
FAIL-CLOSED: only ``read`` and ``compute`` are allowed by policy (require-classified-tool
denies every other value, incl. ``unclassified``), so a tool nobody classified — e.g. a newly
added external MCP server without ``tool_categories`` — is refused until an operator
declares what it does. The pattern fallback can only ever ADD a deny, never allow.
"""
from __future__ import annotations

import json
import re
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


# ── Tool categories (see module docstring) ───────────────────────────────────
CODE_EXECUTION_CATEGORIES = frozenset({"shell_exec", "code_eval", "subprocess", "os_command"})
FILESYSTEM_WRITE_CATEGORIES = frozenset({"file_write", "file_delete", "file_move"})
SAFE_CATEGORIES = frozenset({"read", "compute"})       # the only ones policy allows
UNCLASSIFIED = "unclassified"
KNOWN_CATEGORIES = CODE_EXECUTION_CATEGORIES | FILESYSTEM_WRITE_CATEGORIES | SAFE_CATEGORIES

_SHELL_TOKENS = frozenset({"shell", "bash", "sh", "zsh", "powershell", "pwsh", "cmd",
                           "terminal"})
_CODE_TOKENS = frozenset({"code", "python", "script", "js", "javascript", "repl"})
_RUN_TOKENS = frozenset({"run", "exec", "execute", "eval", "evaluate", "interpret"})
_FILE_TOKENS = frozenset({"file", "files", "fs", "filesystem", "dir", "directory", "folder",
                          "path"})
_FS_ACTIONS = (
    ("file_delete", frozenset({"delete", "remove", "rm", "unlink", "rmdir", "erase", "purge"})),
    ("file_move", frozenset({"move", "mv", "rename"})),
    ("file_write", frozenset({"write", "save", "create", "append", "overwrite", "put",
                              "upload", "mkdir", "touch", "edit"})),
)
_FS_STANDALONE = {"rm": "file_delete", "rmdir": "file_delete", "unlink": "file_delete",
                  "mv": "file_move", "mkdir": "file_write", "touch": "file_write"}


def _name_tokens(tool: str) -> list[str]:
    split_camel = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", tool)
    return [t for t in re.split(r"[^a-z0-9]+", split_camel.lower()) if t]


def infer_category_from_name(tool: str) -> str | None:
    """Conservative name-pattern classification (step 3). Returns a DANGEROUS category or
    None — it never infers a safe one. Over-matching is intended (``execute_query`` →
    os_command); an operator who knows better declares the tool explicitly."""
    tokens = _name_tokens(tool)
    tset = set(tokens)
    compact = "".join(tokens)
    if "subprocess" in compact or "popen" in compact or tset & {"spawn", "fork"}:
        return "subprocess"
    if tset & _SHELL_TOKENS or any(x in compact for x in ("shell", "bash", "powershell")):
        return "shell_exec"
    if "eval" in compact or (tset & _CODE_TOKENS and tset & _RUN_TOKENS):
        return "code_eval"
    if "exec" in compact or any(x in compact for x in ("runcommand", "runcmd", "syscall")) or (
            "run" in tset and tset & {"command", "program", "binary"}) or "system" in tset:
        return "os_command"
    for category, actions in _FS_ACTIONS:
        if tset & actions and (tset & _FILE_TOKENS or any(
                a + f in compact or f + a in compact
                for a in actions for f in ("file", "dir", "folder"))):
            return category
    for tok in tokens:
        if tok in _FS_STANDALONE:
            return _FS_STANDALONE[tok]
    for category, actions in _FS_ACTIONS:   # e.g. "writefile" with no separator
        if any(a + f in compact for a in actions for f in ("file", "dir", "folder")):
            return category
    return None


def _configured_server(server: str) -> dict | None:
    raw = (settings.mcp_servers or "").strip()
    if not raw:
        return None
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return None
    for s in entries if isinstance(entries, list) else []:
        if isinstance(s, dict) and s.get("name") == server:
            return s
    return None


def tool_category(server: str, tool: str) -> str:
    """The ``tool_category`` policy field for an mcp.call (module docstring: TOOL
    CATEGORIES). Always returns a string; ``unclassified`` is denied by policy."""
    sc = _configured_server(server)
    declared = (sc or {}).get("tool_categories")
    if isinstance(declared, dict) and tool in declared:
        value = declared[tool]
        if value in KNOWN_CATEGORIES:
            return str(value)
        log.warning("mcp_tool_category_invalid", server=server, tool=tool, agt_audit=True)
        return UNCLASSIFIED
    # In-process governed tool: only when the server is not configured as something remote.
    if sc is None or not sc.get("url"):
        from tools.local_tools import TOOLS
        entry = TOOLS.get(server)
        if entry is not None and tool != "capability" and callable(entry.get(tool)):
            return "compute"
    return infer_category_from_name(tool) or UNCLASSIFIED


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
    agent_trust_score: float,
    caller: Callable[[dict, str, dict], Awaitable[Any]] | None = None,
) -> Any:
    """Invoke an MCP tool through the governance gates. Raises McpToolError / PermissionError
    on any gate failure (fail-closed). ``caller(server_cfg, tool, arguments)`` performs the
    actual transport; without it the function validates + refuses (no silent no-op).

    ``agent_trust_score`` is REQUIRED (no default): the trust of the agent on whose behalf
    the call runs — the signing peer's registry score for a delegated /a2a/tool call,
    ``agent.nodes.LOCAL_AGENT_TRUST_SCORE`` for a local user's call."""
    from agent.nodes import _enforce  # local import: avoids a heavy import cycle at module load

    args = arguments or {}
    # Boundary invariant (§4.2): the outbound arguments must not smuggle a user credential —
    # auth is the caller's job (OBO exchange / service credential), never tool arguments.
    _assert_no_user_credential(args)
    # Gate 1: policy engine (default-deny).
    await _enforce("mcp.call", {
        "server": server,
        "tool": tool,
        "tool_category": tool_category(server, tool),
        "agent_trust_score": agent_trust_score,
    })

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
