"""Governed MCP tool executor tests (Phase-1 item 11).

Pins the gates: policy default-deny, the McpAuthPolicy gateway (unconfigured server
rejected fail-closed), a configured+allowed server passing through to the injected
transport, and that the raw user token is never part of the call.
"""
from __future__ import annotations

import asyncio

import pytest

from tools import mcp as mcp_tools


def _patch_enforce_ok(monkeypatch):
    async def ok(action, ctx):
        return None
    monkeypatch.setattr("agent.nodes._enforce", ok)


def test_unconfigured_server_is_rejected_fail_closed(monkeypatch):
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")  # none configured
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(mcp_tools.call_mcp_tool("jira", "search", {"q": "x"}, agent_trust_score=1.0))


def test_policy_denial_blocks_before_gateway(monkeypatch):
    async def deny(action, ctx):
        raise PermissionError("policy denied")
    monkeypatch.setattr("agent.nodes._enforce", deny)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers",
                        '[{"name":"jira","url":"https://mcp/jira","allowed_auth_methods":["oauth2"]}]')
    mcp_tools.reset_cache()
    with pytest.raises(PermissionError):
        asyncio.run(mcp_tools.call_mcp_tool("jira", "search", {"q": "x"}, agent_trust_score=1.0))


def test_configured_server_passes_through_to_transport(monkeypatch):
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers",
                        '[{"name":"jira","url":"https://mcp/jira","allowed_auth_methods":["oauth2"],'
                        '"require_tls":true,"auth_mode":"oauth_obo"}]')
    mcp_tools.reset_cache()

    seen = {}
    async def transport(server_cfg, tool, args):
        seen["cfg"], seen["tool"], seen["args"] = server_cfg, tool, args
        return {"issues": []}

    out = asyncio.run(mcp_tools.call_mcp_tool("jira", "search", {"q": "bug"}, caller=transport, agent_trust_score=1.0))
    assert out == {"issues": []}
    assert seen["tool"] == "search" and seen["args"] == {"q": "bug"}
    # transport receives only server config + tool + args — no token/credential is threaded in
    assert "token" not in seen["cfg"] and "access_token" not in seen["args"]


def test_no_transport_is_governed_but_not_executed(monkeypatch):
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers",
                        '[{"name":"jira","url":"https://mcp/jira","allowed_auth_methods":["oauth2"]}]')
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):       # validates OK, refuses to silently no-op
        asyncio.run(mcp_tools.call_mcp_tool("jira", "search", agent_trust_score=1.0))


def test_credential_in_arguments_is_refused_fail_closed(monkeypatch):
    # §4.2 boundary invariant: a raw user credential smuggled into the tool ARGUMENTS is
    # refused before any transport runs — auth is the caller's job (OBO/service credential),
    # never tool arguments. Fail-closed: the call raises and the transport is NEVER invoked.
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers",
                        '[{"name":"jira","url":"https://mcp/jira","allowed_auth_methods":["oauth2"],'
                        '"auth_mode":"oauth_obo"}]')
    mcp_tools.reset_cache()

    called = {"n": 0}
    async def transport(server_cfg, tool, args):
        called["n"] += 1
        return {}

    for leaky in ({"q": "x", "access_token": "SECRET"}, {"Authorization": "Bearer x"},
                  {"user_token": "jwt"}):
        with pytest.raises(mcp_tools.McpToolError):
            asyncio.run(mcp_tools.call_mcp_tool("jira", "search", leaky, caller=transport, agent_trust_score=1.0))
    assert called["n"] == 0                            # transport never ran (fail-closed)


def test_clean_arguments_still_pass_through(monkeypatch):
    # Positive control: the credential guard does not reject ordinary arguments.
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers",
                        '[{"name":"jira","url":"https://mcp/jira","allowed_auth_methods":["oauth2"],'
                        '"auth_mode":"oauth_obo"}]')
    mcp_tools.reset_cache()

    async def transport(server_cfg, tool, args):
        return {"ok": True}

    out = asyncio.run(mcp_tools.call_mcp_tool("jira", "search", {"q": "bug", "limit": 10},
                                              caller=transport, agent_trust_score=1.0))
    assert out == {"ok": True}
