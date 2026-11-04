"""M-GOV: FR-4 governance-control proving tests (IMPLEMENTATION_PLAN.md M-GOV).

The AGT PolicyEvaluator (per-node `_enforce`) is THE governance gate. These hermetic
tests load the REAL YAML policies (agent/policies) and pin the two security-critical
properties: (1) default-DENY — an action with no matching allow rule is denied; (2) the
output-DLP credential-leak HARD-DENY — a structured secret in the LLM output is blocked
(fail-closed, whole answer withheld), while a clean answer — even one that merely
discusses secrets/tokens in prose — passes (fail-safe, no over-blocking).
"""
from __future__ import annotations

from pathlib import Path

_POLICY_DIR = str(Path(__file__).resolve().parents[1] / "agent" / "policies")


def _evaluator():
    from agent_os.policies import PolicyEvaluator  # type: ignore[import]
    ev = PolicyEvaluator()
    ev.load_policies(_POLICY_DIR)
    return ev


def _allowed(ev, action: str, **ctx) -> bool:
    return ev.evaluate({"action": action, **ctx}).allowed


def test_policy_engine_default_deny():
    # FR-4.1: an action with no matching allow rule is DENIED (no implicit allow).
    ev = _evaluator()
    assert not _allowed(ev, "totally.unknown.action")
    assert not _allowed(ev, "rag.exfiltrate.everything")


def test_output_dlp_blocks_structured_credentials():
    # FR-4: the output choke point HARD-DENIES structured secrets in the answer.
    ev = _evaluator()
    leaks = [
        "your key is AKIAIOSFODNN7EXAMPLE use it",
        "token sk-abc123def456ghi789jkl012mno345pqr",
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----",
        "set api_key=supersecretvalue12345 in the env",
    ]
    for leak in leaks:
        assert not _allowed(ev, "agent.output_check", llm_output=leak), f"NOT blocked: {leak[:30]}"


def test_output_dlp_allows_clean_answer_and_does_not_overblock():
    # Fail-safe: a legitimate answer passes — including prose that merely USES the words
    # "secret"/"token"/"password" without a structured secret value.
    ev = _evaluator()
    assert _allowed(ev, "agent.output_check",
                    llm_output="Our data retention policy is 7 years and applies to all systems.")
    assert _allowed(ev, "agent.output_check",
                    llm_output="Access requires the data owner's approval; your token is validated at login "
                               "and the secret rotation policy is quarterly.")


# ── Decision matrix: engine-migration parity contract ─────────────────────────
#
# AGT main removes agent_os.policies.PolicyEvaluator in favour of the ACS
# AgentControl runtime (manifests from `agt migrate`). This matrix pins the
# CURRENT decision — allow/deny AND the deciding rule — for every rule in
# agent/policies at both sides of its boundary, using the contexts the real call
# sites send (agent/nodes.py, api/main.py, tools/mcp.py). Point `_evaluator` at
# the new engine and this table is the parity check: a row that changes is either
# a migration bug or a semantic change to accept consciously, never silently.
#
# Columns: (id, action, context, allowed, deciding rule)
_TRUSTED_PEER = {"peer_did_verified": True, "transport_encrypted": True,
                 "peer_trust_score": 0.9, "peer_execution_ring": "TRUSTED",
                 "peer_circuit_state": "CLOSED"}
# Contexts exactly as the call sites build them for a LOCAL user (agent/nodes.retrieve_local
# with the default qdrant(10)+neo4j(5) fan-out; tools/mcp.call_mcp_tool for a local tool).
_LOCAL_RETRIEVE = {"query_length": 20, "qdrant_collection": "knowledge_base",
                   "requested_chunk_count": 15, "agent_trust_score": 1.0, "user_id": "alice"}
_LOCAL_MCP = {"server": "pii-scan", "tool": "scan", "tool_category": "compute",
              "agent_trust_score": 1.0}
_DECISIONS = [
    # base-policy: allow-listed actions (contexts as sent by the call sites)
    ("retrieve", "rag.retrieve", _LOCAL_RETRIEVE, True, "allow-rag-retrieve"),
    ("authz", "auth.check_permission", {"chunk_count": 5}, True, "allow-auth-check"),
    ("generate", "llm.generate", {"context_char_count": 1000}, True, "allow-llm-generate"),
    ("approval", "approval.start_workflow", {"pending_chunk_count": 2}, True,
     "allow-approval-start"),
    ("peer-send", "peer.send_message", _TRUSTED_PEER, True, "allow-peer-send"),
    ("peer-callback", "peer.receive_callback", _TRUSTED_PEER, True,
     "allow-peer-receive-callback"),
    ("mcp", "mcp.call", _LOCAL_MCP, True, "allow-mcp-call"),
    ("format", "agent.format_response", {}, True, "allow-format-response"),
    # base-policy: deny rules (priority beats the action allow-rule)
    ("trust-0.6-ok", "rag.retrieve", {"agent_trust_score": 0.6}, True, "allow-rag-retrieve"),
    ("trust-0.59", "rag.retrieve", {"agent_trust_score": 0.59}, False, "block-low-trust-agents"),
    ("goal-replace", "goal.replace", {}, False, "block-goal-override"),
    ("prompt-override", "system_prompt.override", {}, False, "block-goal-override"),
    ("shell-tool", "mcp.call", {"tool_category": "shell_exec"}, False, "block-code-execution"),
    ("file-write", "mcp.call", {"tool_category": "file_write"}, False,
     "block-filesystem-writes"),
    # data-access-policy: caps at both sides of each boundary
    ("query-4096", "rag.retrieve", {"query_length": 4096}, True, "allow-rag-retrieve"),
    ("query-4097", "rag.retrieve", {"query_length": 4097}, False, "reject-oversized-query"),
    ("query-empty", "rag.retrieve", {"query_length": 0}, False, "reject-empty-query"),
    ("chunks-50", "rag.retrieve", {"requested_chunk_count": 50}, True, "allow-rag-retrieve"),
    ("chunks-51", "rag.retrieve", {"requested_chunk_count": 51}, False, "cap-chunk-retrieval"),
    ("bad-collection", "rag.retrieve", {"qdrant_collection": "evil"}, False,
     "block-untrusted-collection"),
    ("ctx-24000", "llm.generate", {"context_char_count": 24000}, True, "allow-llm-generate"),
    ("ctx-24001", "llm.generate", {"context_char_count": 24001}, False, "cap-llm-context"),
    # peer-comms-policy: each deny rule against an otherwise-trusted peer
    ("peer-unverified", "peer.send_message", {**_TRUSTED_PEER, "peer_did_verified": False},
     False, "require-peer-did-verified"),
    ("peer-plaintext", "peer.send_message", {**_TRUSTED_PEER, "transport_encrypted": False},
     False, "require-iatp-encryption"),
    ("peer-circuit-open", "peer.send_message", {**_TRUSTED_PEER, "peer_circuit_state": "OPEN"},
     False, "block-when-circuit-open"),
    ("peer-low-trust", "peer.send_message", {**_TRUSTED_PEER, "peer_trust_score": 0.5},
     False, "block-low-trust-peer"),
    ("peer-untrusted-ring", "peer.send_message",
     {**_TRUSTED_PEER, "peer_execution_ring": "SANDBOX"}, False, "require-trusted-ring"),
    # Formerly inert rules, with the FULL contexts the call sites now send (local user =
    # LOCAL_AGENT_TRUST_SCORE 1.0; delegated = the signing peer's registry trust).
    ("retrieve-delegated-0.6", "rag.retrieve", {**_LOCAL_RETRIEVE, "agent_trust_score": 0.6},
     True, "allow-rag-retrieve"),
    ("retrieve-delegated-0.59", "rag.retrieve", {**_LOCAL_RETRIEVE, "agent_trust_score": 0.59},
     False, "block-low-trust-agents"),
    ("retrieve-chunks-15", "rag.retrieve", {**_LOCAL_RETRIEVE, "requested_chunk_count": 15},
     True, "allow-rag-retrieve"),
    ("retrieve-chunks-51", "rag.retrieve", {**_LOCAL_RETRIEVE, "requested_chunk_count": 51},
     False, "cap-chunk-retrieval"),
    ("mcp-read", "mcp.call", {**_LOCAL_MCP, "tool_category": "read"}, True, "allow-mcp-call"),
    ("mcp-delegated-0.59", "mcp.call", {**_LOCAL_MCP, "agent_trust_score": 0.59}, False,
     "block-low-trust-agents"),
    ("mcp-os-command", "mcp.call", {**_LOCAL_MCP, "tool_category": "os_command"}, False,
     "block-code-execution"),
    ("mcp-code-eval", "mcp.call", {**_LOCAL_MCP, "tool_category": "code_eval"}, False,
     "block-code-execution"),
    ("mcp-file-delete", "mcp.call", {**_LOCAL_MCP, "tool_category": "file_delete"}, False,
     "block-filesystem-writes"),
    ("mcp-file-move", "mcp.call", {**_LOCAL_MCP, "tool_category": "file_move"}, False,
     "block-filesystem-writes"),
    ("mcp-unclassified", "mcp.call", {**_LOCAL_MCP, "tool_category": "unclassified"}, False,
     "require-classified-tool"),
    ("mcp-unknown-category", "mcp.call", {**_LOCAL_MCP, "tool_category": "network_post"},
     False, "require-classified-tool"),
]


def test_policy_decision_matrix():
    ev = _evaluator()
    for case_id, action, ctx, allowed, rule in _DECISIONS:
        d = ev.evaluate({"action": action, **ctx})
        assert (d.allowed, d.matched_rule) == (allowed, rule), (
            f"{case_id}: got ({d.allowed}, {d.matched_rule!r}), "
            f"pinned ({allowed}, {rule!r})")


def test_absent_field_semantics_are_pinned():
    # ENGINE semantics, pinned on purpose: in the PolicyEvaluator a deny rule whose field
    # is ABSENT does not match, so the action's allow rule wins. The app no longer relies
    # on this: agent.nodes._enforce refuses an action whose REQUIRED_CONTEXT is missing
    # (test_enforce_denies_missing_required_context below). AGT's ACS migration changes
    # `ne`/`not_in` on an absent field to fail CLOSED at the engine too — when this test
    # fails after migration, that is the expected (safer) change: update it deliberately.
    ev = _evaluator()
    assert _allowed(ev, "peer.send_message")
    assert _allowed(ev, "peer.send_message", peer_did_verified=True,
                    transport_encrypted=True, peer_trust_score=0.9)  # ring absent
    assert _allowed(ev, "rag.retrieve", query_length=10)  # collection absent


# ── Required governance context (closes the absent-field gap at the app layer) ──

_FULL_CONTEXT = {
    "rag.retrieve": dict(_LOCAL_RETRIEVE),
    "mcp.call": dict(_LOCAL_MCP),
    "llm.generate": {"context_char_count": 1000},
    "agent.output_check": {"llm_output": "Our retention policy is 7 years."},
    "peer.send_message": dict(_TRUSTED_PEER),
}


def test_enforce_denies_missing_required_context():
    """Through the REAL _enforce + real policies: a complete context is allowed; dropping ANY
    required field is a deny (previously the allow rule won when the field was absent)."""
    import asyncio

    import pytest

    from agent import nodes

    assert set(_FULL_CONTEXT) == set(nodes.REQUIRED_CONTEXT)
    for action, ctx in _FULL_CONTEXT.items():
        asyncio.run(nodes._enforce(action, dict(ctx)))            # allowed
        for field in nodes.REQUIRED_CONTEXT[action]:
            partial = {k: v for k, v in ctx.items() if k != field}
            with pytest.raises(PermissionError, match="missing governance context"):
                asyncio.run(nodes._enforce(action, partial))
            with pytest.raises(PermissionError, match="missing governance context"):
                asyncio.run(nodes._enforce(action, {**ctx, field: None}))


def test_required_context_matches_every_call_site():
    """Every _enforce/enforce call for an action in REQUIRED_CONTEXT must pass a LITERAL dict
    containing all its required fields — so the runtime check never fires on a real flow,
    and a future call site that forgets a field fails here, in CI."""
    import ast

    from agent.nodes import REQUIRED_CONTEXT

    root = Path(__file__).resolve().parents[1]
    files = ["agent/nodes.py", "agent/specialists.py", "api/main.py", "tools/mcp.py"]
    seen: dict[str, int] = {}
    problems = []
    for rel in files:
        for n in ast.walk(ast.parse((root / rel).read_text(encoding="utf-8"))):
            if not isinstance(n, ast.Call):
                continue
            name = n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
            if name not in ("_enforce", "enforce") or len(n.args) < 2:
                continue
            if not isinstance(n.args[0], ast.Constant) or n.args[0].value not in REQUIRED_CONTEXT:
                continue
            action = n.args[0].value
            seen[action] = seen.get(action, 0) + 1
            if not isinstance(n.args[1], ast.Dict):
                problems.append(f"{rel}:{n.lineno} {action}: context is not a literal dict")
                continue
            keys = {k.value for k in n.args[1].keys if isinstance(k, ast.Constant)}
            lacking = set(REQUIRED_CONTEXT[action]) - keys
            if lacking:
                problems.append(f"{rel}:{n.lineno} {action}: missing {sorted(lacking)}")
    assert not problems, problems
    assert set(seen) == set(REQUIRED_CONTEXT), f"no call site found for {set(REQUIRED_CONTEXT) - set(seen)}"


# ── Formerly inert deny rules: they now fire through the REAL _enforce ────────────
# Each row is the context a real call site builds (see the wiring tests in
# test_inert_rules_wired.py for the call sites themselves). Run through agent.nodes._enforce
# — REQUIRED_CONTEXT check + the real policy files — not just the bare evaluator.
_ENFORCE_ROWS = [
    ("rag.retrieve", _LOCAL_RETRIEVE, None),
    ("rag.retrieve", {**_LOCAL_RETRIEVE, "agent_trust_score": 0.59},
     "Agent trust score below minimum threshold"),
    ("rag.retrieve", {**_LOCAL_RETRIEVE, "requested_chunk_count": 51},
     "Chunk retrieval cap exceeded"),
    ("rag.retrieve", {**_LOCAL_RETRIEVE, "requested_chunk_count": 50}, None),
    ("mcp.call", _LOCAL_MCP, None),
    ("mcp.call", {**_LOCAL_MCP, "agent_trust_score": 0.59},
     "Agent trust score below minimum threshold"),
    ("mcp.call", {**_LOCAL_MCP, "tool_category": "shell_exec"},
     "Unrestricted code execution not permitted"),
    ("mcp.call", {**_LOCAL_MCP, "tool_category": "subprocess"},
     "Unrestricted code execution not permitted"),
    ("mcp.call", {**_LOCAL_MCP, "tool_category": "file_write"},
     "Filesystem writes not permitted"),
    ("mcp.call", {**_LOCAL_MCP, "tool_category": "unclassified"},
     "not classified as read or compute"),
]


def test_formerly_inert_rules_fire_through_real_enforce():
    import asyncio

    import pytest

    from agent import nodes

    for action, ctx, denial in _ENFORCE_ROWS:
        if denial is None:
            asyncio.run(nodes._enforce(action, dict(ctx)))
        else:
            with pytest.raises(PermissionError, match=denial):
                asyncio.run(nodes._enforce(action, dict(ctx)))
