"""Retrieval-quality eval — does the RIGHT document come back, not just the right governance label.

``run_scenarios.py`` asserts the governance FLOW (LOCAL_ALLOWED / DENIED / ...); it never checks
that retrieval surfaced the correct document. So an embedding swap, a threshold regression, or a
chunking change can tank recall with every governance test still green. This harness closes that:
a small golden set (query -> the seeded doc that answers it) scored with recall@k + MRR.

Two layers:
  * PURE SCORING (recall_at_k / reciprocal_rank / summarize) — deterministic, unit-tested, no
    infra. This is the regression-able core.
  * LIVE RUNNER (run_live) — drives a deployed division's /query and reads which sources the
    answer cited ([Source: <name>], emitted by the citation gate), then scores them. Needs a
    running division + LLM, so it runs on demand, not in CI.

Run live (with a port-forward to the division's agent + a user token)::

    python scenarios/eval_retrieval.py --agent-url http://localhost:9200 --token "$TOK"
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import urllib.request
from typing import Any, Callable

# query -> the seeded corpus doc (by source/title) that should answer it. Grounded in
# agt-federated-rag/tests/docs/{cluster-a,cluster-b}.
GOLD: list[dict[str, str]] = [
    {"query": "How long do we retain customer data and what is the policy?",
     "expected": "data_retention_policy"},
    {"query": "What were the Q4 financial results?", "expected": "q4_financial_results"},
    {"query": "What security incidents have occurred and how were they handled?",
     "expected": "security_incidents"},
    {"query": "Describe the system's technical architecture.",
     "expected": "technical_architecture"},
    {"query": "What is the employee compensation data?", "expected": "hr_compensation_data"},
]

_SOURCE_RE = re.compile(r"\[Source:\s*([^\]]+?)\s*\]", re.IGNORECASE)


# ── pure scoring (unit-tested, no infra) ────────────────────────────────────────────────
def recall_at_k(retrieved: list[str], expected: str, k: int) -> float:
    """1.0 if the expected source is in the top-k retrieved sources, else 0.0."""
    return 1.0 if expected in retrieved[:k] else 0.0


def reciprocal_rank(retrieved: list[str], expected: str) -> float:
    """1/rank of the expected source (0.0 if absent) — the per-query MRR term."""
    for i, s in enumerate(retrieved, start=1):
        if s == expected:
            return 1.0 / i
    return 0.0


def summarize(per_query: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-query {expected, retrieved} rows into recall@1/@3 + MRR."""
    if not per_query:
        return {"n": 0, "recall@1": 0.0, "recall@3": 0.0, "mrr": 0.0}
    r1 = [recall_at_k(r["retrieved"], r["expected"], 1) for r in per_query]
    r3 = [recall_at_k(r["retrieved"], r["expected"], 3) for r in per_query]
    rr = [reciprocal_rank(r["retrieved"], r["expected"]) for r in per_query]
    return {
        "n": len(per_query),
        "recall@1": round(statistics.fmean(r1), 3),
        "recall@3": round(statistics.fmean(r3), 3),
        "mrr": round(statistics.fmean(rr), 3),
    }


# ── live runner ─────────────────────────────────────────────────────────────────────────
def sources_from_answer(answer: str) -> list[str]:
    """The sources an answer cited, in first-seen order (de-duplicated)."""
    out: list[str] = []
    for m in _SOURCE_RE.findall(answer or ""):
        s = m.strip()
        if s and s.lower() != "unknown" and s not in out:
            out.append(s)
    return out


def _query_answer(agent_url: str, token: str, query: str) -> str:
    """POST /query and consume the SSE stream to its final answer text."""
    body = json.dumps({"query": query}).encode()
    req = urllib.request.Request(f"{agent_url.rstrip('/')}/query", data=body,
                                 headers={"Authorization": f"Bearer {token}",
                                          "Content-Type": "application/json"}, method="POST")
    answer = ""
    with urllib.request.urlopen(req, timeout=180) as r:
        for raw in r:
            line = raw.decode("utf-8", "replace").strip()
            if line.startswith("data:"):
                try:
                    ev = json.loads(line[5:].strip())
                except Exception:
                    continue
                if isinstance(ev, dict) and ev.get("answer"):
                    answer = ev["answer"]
    return answer


def run_live(retrieve: Callable[[str], list[str]], gold: list[dict[str, str]] | None = None) -> dict[str, Any]:
    """Run the golden set through ``retrieve`` (query -> retrieved source list) and score it.
    ``retrieve`` is injected so the harness is transport-agnostic and unit-testable."""
    gold = gold or GOLD
    per_query = []
    for g in gold:
        retrieved = retrieve(g["query"])
        per_query.append({"query": g["query"], "expected": g["expected"], "retrieved": retrieved})
    return {"summary": summarize(per_query), "detail": per_query}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Retrieval-quality eval (recall@k + MRR)")
    ap.add_argument("--agent-url", required=True, help="e.g. http://localhost:9200 (port-forwarded)")
    ap.add_argument("--token", required=True, help="a user bearer token for the division")
    args = ap.parse_args(argv)

    def _retrieve(q: str) -> list[str]:
        return sources_from_answer(_query_answer(args.agent_url, args.token, q))

    result = run_live(_retrieve)
    s = result["summary"]
    print(f"recall@1={s['recall@1']}  recall@3={s['recall@3']}  mrr={s['mrr']}  (n={s['n']})")
    for d in result["detail"]:
        hit = "OK " if d["expected"] in d["retrieved"][:3] else "MISS"
        print(f"  [{hit}] {d['expected']:<24} <- {d['query'][:50]}  got={d['retrieved'][:3]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
