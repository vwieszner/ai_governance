"""The four formerly-inert deny rules, proven at their REAL call sites.

block-code-execution / block-filesystem-writes / block-low-trust-agents / cap-chunk-retrieval
never fired before: no call site sent tool_category, agent_trust_score or
requested_chunk_count, and the AGT PolicyEvaluator treats an absent field as "no match".
These tests drive the actual call sites (retrieve_local, run_query → the compiled graph,
call_mcp_tool, run_local_tool) through the REAL agent.nodes._enforce and the real policy
files — nothing here stubs the policy decision. The /a2a/query and /a2a/tool handlers are
covered in test_a2a_tool.py.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from agent import nodes
from tools import local_tools
from tools import mcp as mcp_tools

# ── tool_category: explicit config → local compute → name pattern → unclassified ──


@pytest.mark.parametrize("tool,expected", [
    ("run_shell", "shell_exec"), ("bash", "shell_exec"), ("execShellCommand", "shell_exec"),
    ("powershell_invoke", "shell_exec"),
    ("exec", "os_command"), ("execute_query", "os_command"), ("run_command", "os_command"),
    ("runCommand", "os_command"), ("system", "os_command"),
    ("eval", "code_eval"), ("python_eval", "code_eval"), ("run_python", "code_eval"),
    ("execute_code", "code_eval"),
    ("subprocess_run", "subprocess"), ("popen", "subprocess"), ("spawn_process", "subprocess"),
    ("write_file", "file_write"), ("writeFile", "file_write"), ("writefile", "file_write"),
    ("save_to_path", "file_write"), ("mkdir", "file_write"),
    ("delete_file", "file_delete"), ("rm", "file_delete"), ("remove_directory", "file_delete"),
    ("move_file", "file_move"), ("rename_file", "file_move"), ("mv", "file_move"),
])
def test_name_pattern_flags_dangerous_tools(tool, expected):
    assert mcp_tools.infer_category_from_name(tool) == expected


@pytest.mark.parametrize("tool", ["search", "read_file", "list_issues", "get_page", "scan",
                                  "create_ticket", "summarize", "lookup"])
def test_name_pattern_never_infers_a_safe_category(tool):
    # The fallback only ever ADDS a deny; anything it does not flag stays unclassified.
    assert mcp_tools.infer_category_from_name(tool) is None


def _servers(monkeypatch, entries):
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", json.dumps(entries))
    mcp_tools.reset_cache()


_JIRA = {"name": "jira", "url": "https://mcp/jira", "allowed_auth_methods": ["oauth2"],
         "require_tls": True, "auth_mode": "oauth_obo"}


def test_tool_category_resolution_order(monkeypatch):
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    _servers(monkeypatch, [{**_JIRA, "tool_categories": {
        "search": "read", "execute_query": "read", "nuke": "shell_exec", "odd": "safe"}}])
    tc = mcp_tools.tool_category
    assert tc("jira", "search") == "read"              # explicit
    assert tc("jira", "execute_query") == "read"       # explicit beats the name pattern
    assert tc("jira", "nuke") == "shell_exec"          # explicit dangerous
    assert tc("jira", "odd") == "unclassified"         # unknown explicit value → fail closed
    assert tc("jira", "run_shell") == "shell_exec"     # undeclared → pattern
    assert tc("jira", "list_issues") == "unclassified"  # undeclared, no pattern → fail closed
    assert tc("pii-scan", "scan") == "compute"         # in-process local tool
    assert tc("pii-scan", "capability") == "unclassified"
    assert tc("nowhere", "lookup") == "unclassified"


def test_remote_server_named_like_a_local_tool_is_not_compute(monkeypatch):
    # A REMOTE server (non-empty url) reusing a local server name is not treated as the
    # in-process pure-compute tool.
    _servers(monkeypatch, [{**_JIRA, "name": "pii-scan"}])
    assert mcp_tools.tool_category("pii-scan", "scan") == "unclassified"


# ── mcp.call through call_mcp_tool + the REAL _enforce ──────────────────────────


def _transport(calls):
    async def transport(server_cfg, tool, args):
        calls.append(tool)
        return {"ok": True}
    return transport


@pytest.mark.parametrize("tool,denial", [
    ("run_shell_command", "Unrestricted code execution"),
    ("python_eval", "Unrestricted code execution"),
    ("delete_file", "Filesystem writes not permitted"),
    ("write_file", "Filesystem writes not permitted"),
    ("search", "not classified as read or compute"),       # no tool_categories declared
])
def test_call_mcp_tool_denies_by_category(monkeypatch, tool, denial):
    _servers(monkeypatch, [_JIRA])
    calls: list = []
    with pytest.raises(PermissionError, match=denial):
        asyncio.run(mcp_tools.call_mcp_tool("jira", tool, {"q": "x"}, agent_trust_score=1.0,
                                            caller=_transport(calls)))
    assert calls == []                                   # the transport never ran


def test_call_mcp_tool_declared_read_tool_runs(monkeypatch):
    _servers(monkeypatch, [{**_JIRA, "tool_categories": {"search": "read"}}])
    calls: list = []
    out = asyncio.run(mcp_tools.call_mcp_tool("jira", "search", {"q": "x"},
                                              agent_trust_score=1.0, caller=_transport(calls)))
    assert out == {"ok": True} and calls == ["search"]


def test_call_mcp_tool_low_trust_agent_denied(monkeypatch):
    _servers(monkeypatch, [{**_JIRA, "tool_categories": {"search": "read"}}])
    calls: list = []
    with pytest.raises(PermissionError, match="trust score below"):
        asyncio.run(mcp_tools.call_mcp_tool("jira", "search", {"q": "x"},
                                            agent_trust_score=0.59, caller=_transport(calls)))
    assert calls == []


def test_call_mcp_tool_none_trust_is_missing_context(monkeypatch):
    _servers(monkeypatch, [{**_JIRA, "tool_categories": {"search": "read"}}])
    with pytest.raises(PermissionError, match="missing governance context"):
        asyncio.run(mcp_tools.call_mcp_tool("jira", "search", {}, agent_trust_score=None,
                                            caller=_transport([])))


def test_trust_score_is_a_required_argument():
    # No default: a caller that forgets it fails loudly instead of inheriting a local value.
    with pytest.raises(TypeError):
        asyncio.run(mcp_tools.call_mcp_tool("jira", "search", {}))
    with pytest.raises(TypeError):
        asyncio.run(local_tools.run_local_tool("pii-scan", "scan", {"text": "x"}))


@pytest.mark.parametrize("server,tool,args", [
    ("pii-scan", "scan", {"text": "ping alice@example.com"}),
    ("compliance-lookup", "lookup", {"topic": "transparency"}),
    ("risk-score", "assess", {"description": "credit scoring for loan approval"}),
    ("data-classify", "classify", {"text": "Card 4242424242424242 on file"}),
    ("fin-check", "screen", {"amount": 50000, "currency": "USD", "counterparty": "Volkov"}),
])
def test_every_local_tool_still_runs_through_real_policy(monkeypatch, server, tool, args):
    """No real flow newly denied: every in-process governed tool is `compute` and runs for a
    local user (and for a trusted peer), through the real _enforce."""
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    assert asyncio.run(local_tools.run_local_tool(
        server, tool, args, agent_trust_score=nodes.LOCAL_AGENT_TRUST_SCORE))
    assert asyncio.run(local_tools.run_local_tool(server, tool, args, agent_trust_score=0.7))
    with pytest.raises(PermissionError, match="trust score below"):
        asyncio.run(local_tools.run_local_tool(server, tool, args, agent_trust_score=0.5))


# ── rag.retrieve through retrieve_local + the REAL _enforce ─────────────────────


class _FakeRetriever:
    trusted = True

    def __init__(self, name, chunk_limit=None, *, declare=True):
        self.name = name
        if declare:
            self.chunk_limit = chunk_limit
        self.calls = 0

    async def retrieve(self, query, allowed_chunk_ids=None, limit=None):
        self.calls += 1
        return [{"chunk_id": f"{self.name}-1", "text": "t", "metadata": {}, "score": 1.0}]


def _wire_retrievers(monkeypatch, retrievers):
    async def fake():
        return retrievers
    monkeypatch.setattr(nodes, "_get_retrievers", fake)


def _state(trust=nodes.LOCAL_AGENT_TRUST_SCORE, **over):
    st = {"query": "What is the retention policy?", "user_id": "alice",
          "agent_trust_score": trust}
    st.update(over)
    return st


def test_retrieve_local_allows_default_sized_local_query(monkeypatch):
    rs = [_FakeRetriever("qdrant", 10), _FakeRetriever("neo4j", 5)]
    _wire_retrievers(monkeypatch, rs)
    out = asyncio.run(nodes.retrieve_local(_state()))
    assert out["fused_chunks"] and all(r.calls == 1 for r in rs)


def test_retrieve_local_cap_chunk_retrieval_fires(monkeypatch):
    rs = [_FakeRetriever("qdrant", 40), _FakeRetriever("raas", 11)]   # 51 > 50
    _wire_retrievers(monkeypatch, rs)
    with pytest.raises(PermissionError, match="Chunk retrieval cap exceeded"):
        asyncio.run(nodes.retrieve_local(_state()))
    assert all(r.calls == 0 for r in rs)                  # denied BEFORE any retrieval


def test_retrieve_local_exactly_50_chunks_allowed(monkeypatch):
    _wire_retrievers(monkeypatch, [_FakeRetriever("qdrant", 40), _FakeRetriever("raas", 10)])
    assert asyncio.run(nodes.retrieve_local(_state()))["fused_chunks"]


def test_retrieve_local_undeclared_chunk_limit_fails_closed(monkeypatch):
    _wire_retrievers(monkeypatch, [_FakeRetriever("qdrant", 10),
                                   _FakeRetriever("custom", declare=False)])
    with pytest.raises(PermissionError, match="missing governance context"):
        asyncio.run(nodes.retrieve_local(_state()))


def test_retrieve_local_low_trust_agent_fires(monkeypatch):
    rs = [_FakeRetriever("qdrant", 10)]
    _wire_retrievers(monkeypatch, rs)
    with pytest.raises(PermissionError, match="Agent trust score below minimum threshold"):
        asyncio.run(nodes.retrieve_local(_state(trust=0.59)))
    assert rs[0].calls == 0
    assert asyncio.run(nodes.retrieve_local(_state(trust=0.6)))["fused_chunks"]


def test_retrieve_local_without_trust_in_state_fails_closed(monkeypatch):
    _wire_retrievers(monkeypatch, [_FakeRetriever("qdrant", 10)])
    st = _state()
    del st["agent_trust_score"]
    with pytest.raises(PermissionError, match="missing governance context"):
        asyncio.run(nodes.retrieve_local(st))


def test_requested_chunk_count_of_the_real_configured_retrievers(monkeypatch):
    from config import RaasEndpoint
    from rag import retriever as R

    monkeypatch.setattr(R.settings, "retriever_backends", ["qdrant", "neo4j"])
    monkeypatch.setattr(R.settings, "raas_endpoints",
                        [RaasEndpoint(name="acme", url="https://raas.example", top_k=7)])
    built = R.build_retrievers()
    assert [r.name for r in built] == ["qdrant", "neo4j", "acme"]
    expected = R.settings.qdrant_final_k + R.settings.neo4j_top_k + 7
    assert R.requested_chunk_count(built) == expected
    assert R.requested_chunk_count([]) == 0
    assert R.requested_chunk_count([_FakeRetriever("x", True)]) is None      # bool ≠ int
    assert R.requested_chunk_count([_FakeRetriever("x", -1)]) is None


# ── run_query → compiled graph → retrieve_local: the trust score survives LangGraph ──


class _Reached(Exception):
    """Raised by check_auth's first dependency: proves retrieve_local was ALLOWED."""


def _wire_graph(monkeypatch):
    from types import SimpleNamespace

    from agent import graph

    async def allow_graph(action, ctx):   # kill-switch gate off (run_query reads .allowed)
        return SimpleNamespace(allowed=True, decision="allow")
    monkeypatch.setattr(graph, "govern_action", allow_graph)
    _wire_retrievers(monkeypatch, [_FakeRetriever("qdrant", 10)])

    async def reached():
        raise _Reached
    monkeypatch.setattr(nodes, "_get_openfga", reached)
    return graph


def test_run_query_threads_peer_trust_into_retrieval_and_denies(monkeypatch):
    graph = _wire_graph(monkeypatch)
    with pytest.raises(PermissionError, match="Agent trust score below minimum threshold"):
        asyncio.run(graph.run_query(query="q4 revenue?", user_id="alice",
                                    allow_remote=False, agent_trust_score=0.55))


def test_run_query_local_trust_passes_retrieval(monkeypatch):
    graph = _wire_graph(monkeypatch)
    with pytest.raises(_Reached):        # got past rag.retrieve into check_auth
        asyncio.run(graph.run_query(query="q4 revenue?", user_id="alice",
                                    agent_trust_score=nodes.LOCAL_AGENT_TRUST_SCORE))
