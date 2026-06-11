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
