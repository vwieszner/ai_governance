"""Specialized governed sub-agents — orchestration, governance (every call policy-gated), cap."""
from __future__ import annotations

import pytest

from agent import specialists as S


class _FakeLLM:
    """Canned responses keyed on the specialist prompt, so the team is testable without a model."""

    def __init__(self, critic: str = "GROUNDED\nlooks supported") -> None:
        self.critic = critic
        self.prompts: list[str] = []

    async def ainvoke(self, prompt: str):
        self.prompts.append(prompt)

        class _R:
            content = ""

        r = _R()
        if "Decompose this question" in prompt:
            r.content = "retention period\nscope of policy"
        elif "extract the facts relevant" in prompt:
            r.content = "Retention is 7 years [Source: data_retention_policy]."
        elif "Write a complete" in prompt:
            r.content = "Customer data is retained for 7 years [Source: data_retention_policy]."
        elif "Review whether the answer" in prompt:
            r.content = self.critic
        else:
            r.content = "?"
        return r


@pytest.mark.asyncio
async def test_team_runs_and_every_call_is_governed():
    llm = _FakeLLM()
    actions: list[str] = []

    async def enforce(action, ctx):
        actions.append(action)
        assert ctx.get("user_id") == "alice|ns"          # governance binds the user

    out = await S.compose_answer(query="How long is customer data retained?",
                                 context="[Source: data_retention_policy] 7 years.",
                                 llm=llm, enforce=enforce, user_id="alice|ns", max_aspects=2)

    assert "7 years" in out["answer"]
    assert out["plan"] == ["retention period", "scope of policy"]
    assert out["critique"]["grounded"] is True
    # GOVERNED: every specialist LLM call passed the default-deny policy as llm.generate.
    assert actions and all(a == "llm.generate" for a in actions)
    # planner(1) + researcher(2 aspects) + synthesizer(1) + critic(1) = 5 governed calls
    assert len(actions) == 5


@pytest.mark.asyncio
async def test_aspect_cap_bounds_cost():
    llm = _FakeLLM()
    actions: list[str] = []

    async def enforce(action, ctx):
        actions.append(action)

    out = await S.compose_answer(query="q", context="c", llm=llm, enforce=enforce,
                                 user_id="u", max_aspects=1)
    assert len(out["plan"]) == 1                          # planner output capped to 1 aspect
    assert len(actions) == 4                              # planner + 1 researcher + synth + critic


@pytest.mark.asyncio
async def test_ungrounded_answer_is_flagged():
    llm = _FakeLLM(critic="UNGROUNDED\nclaims not supported by the context")

    async def enforce(action, ctx):
        return None

    out = await S.compose_answer(query="q", context="ctx", llm=llm, enforce=enforce,
                                 user_id="u", max_aspects=1)
    assert out["critique"]["grounded"] is False
