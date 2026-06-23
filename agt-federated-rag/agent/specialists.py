"""Specialized governed sub-agents — multi-agent reasoning *within* a division.

When ``settings.specialist_agents_enabled`` is on, ``generate_answer`` composes the answer with
a team of specialist sub-agents instead of a single LLM call:

    PLANNER      decomposes the question into a few focused aspects
    RESEARCHER   extracts the facts for each aspect FROM THE AUTHORIZED CONTEXT (per aspect)
    SYNTHESIZER  writes the final, cited answer from those findings
    CRITIC       checks the answer is grounded in the context (self-review)

GOVERNANCE — the layer never weakens the model. It is the analogue of the reranker on the
generation side:

  * it operates ONLY on the already-AUTHORIZED context (the chunks ``check_auth`` allowed) — no
    sub-agent retrieves new data, so the team cannot widen access or exfiltrate beyond what the
    user may already see;
  * every sub-agent's LLM call passes the default-deny policy (the injected ``enforce`` →
    ``llm.generate``) and is AUDITED (``agt_audit=True`` with the role), so the multi-agent path
    is as governed as the single-agent path — every model call is on the policy + audit trail;
  * the composed answer still flows downstream through ``format_response`` → output DLP.

Cost is bounded: the planner's decomposition is capped (``max_specialist_aspects``) and the whole
layer is OFF by default (one LLM call). ``enforce`` and ``llm`` are injected (no import of
agent.nodes), which keeps this module decoupled and unit-testable with stubs.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable

import structlog

from config import settings

log = structlog.get_logger(__name__)

# enforce(action, context) — the default-deny policy gate (agent.nodes._enforce in production).
Enforce = Callable[[str, dict[str, Any]], Awaitable[None]]


async def _llm_text(llm: Any, prompt: str) -> str:
    resp = await llm.ainvoke(prompt)
    return resp.content if hasattr(resp, "content") else str(resp)


async def _governed_call(role: str, prompt: str, *, llm: Any, enforce: Enforce, user_id: str) -> str:
    """One specialist LLM call, GOVERNED: pass the default-deny policy, audit, then invoke."""
    await enforce("llm.generate", {"user_id": user_id, "context_char_count": len(prompt)})
    log.info("specialist_call", role=role, user_id=user_id, agt_audit=True)
    return await _llm_text(llm, prompt)


async def plan(query: str, *, llm: Any, enforce: Enforce, user_id: str, max_aspects: int) -> list[str]:
    prompt = (
        f"Decompose this question into at most {max_aspects} focused aspects to research, "
        "one per line, no numbering or extra text.\n\n"
        f"Question: {query}"
    )
    out = await _governed_call("planner", prompt, llm=llm, enforce=enforce, user_id=user_id)
    aspects = [ln.strip(" -*\t") for ln in out.splitlines() if ln.strip()]
    return aspects[:max_aspects] or [query]


async def research(aspect: str, context: str, *, llm: Any, enforce: Enforce, user_id: str) -> str:
    prompt = (
        "Using ONLY the context below, extract the facts relevant to the aspect. Cite sources "
        "inline as [Source: <name>]. If the context does not cover it, reply exactly "
        "'no relevant information'.\n\n"
        f"Aspect: {aspect}\n\nContext:\n{context}"
    )
    return await _governed_call("researcher", prompt, llm=llm, enforce=enforce, user_id=user_id)


async def synthesize(query: str, findings: list[str], context: str, *,
                     llm: Any, enforce: Enforce, user_id: str) -> str:
    joined = "\n\n".join(f"- {f}" for f in findings if f and "no relevant information" not in f.lower())
    prompt = (
        "Write a complete, well-structured answer to the question using ONLY the findings and "
        "context below. Ground every claim with an inline [Source: <name>] citation. If the "
        "material does not answer the question, say so plainly.\n\n"
        f"Question: {query}\n\nResearched findings:\n{joined or '(none)'}\n\nContext:\n{context}"
    )
    return await _governed_call("synthesizer", prompt, llm=llm, enforce=enforce, user_id=user_id)


async def critique(query: str, answer: str, context: str, *,
                   llm: Any, enforce: Enforce, user_id: str) -> dict[str, Any]:
    prompt = (
        "Review whether the answer is fully grounded in the context. Reply with GROUNDED or "
        "UNGROUNDED on the first line, then a one-line reason.\n\n"
        f"Question: {query}\n\nAnswer:\n{answer}\n\nContext:\n{context}"
    )
    out = await _governed_call("critic", prompt, llm=llm, enforce=enforce, user_id=user_id)
    first = (out.strip().splitlines() or [""])[0].upper()
    grounded = "UNGROUNDED" not in first
    return {"grounded": grounded, "note": out.strip()[:400]}


async def compose_answer(*, query: str, context: str, llm: Any, enforce: Enforce, user_id: str,
                         max_aspects: int | None = None) -> dict[str, Any]:
    """Run the specialist team over the AUTHORIZED context and return the composed answer +
    metadata. Each step is governed + audited (see _governed_call)."""
    n = max_aspects if max_aspects is not None else settings.max_specialist_aspects
    aspects = await plan(query, llm=llm, enforce=enforce, user_id=user_id, max_aspects=n)
    findings = []
    for a in aspects:
        findings.append(await research(a, context, llm=llm, enforce=enforce, user_id=user_id))
    answer = await synthesize(query, findings, context, llm=llm, enforce=enforce, user_id=user_id)
    review = await critique(query, answer, context, llm=llm, enforce=enforce, user_id=user_id)
    if not review["grounded"]:
        log.warning("specialist_answer_ungrounded", user_id=user_id, agt_audit=True)
    log.info("specialist_compose_done", aspects=len(aspects), grounded=review["grounded"],
             user_id=user_id)
    return {"answer": answer, "plan": aspects, "critique": review}
