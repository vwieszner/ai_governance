"""Generate a large, content-grounded scenario corpus across every governance situation.

Each scenario = (persona, target division pane, natural-language query, expected flow,
situation, doc, why). Queries are PARAPHRASED around the real content of the seeded docs
so they exercise genuine hybrid vector retrieval (dense + sparse + RRF) — not keyword/
hardcoded matching. Outputs:
  - scenarios/scenarios.json   (machine-readable; run_scenarios.py consumes it)
  - scenarios/SCENARIOS.md     (human catalog, grouped by situation)

The expected flows follow the seeded OpenFGA grants (infra/divisions/{alpha,beta}.yml):
  alice @ alpha:
    data_retention_policy   viewer            -> LOCAL_ALLOWED            (local authorized)
    hr_compensation_data    pending_approval  -> LOCAL_NEEDS_APPROVAL     (local needs approval)
    technical_architecture  viewer (on beta)  -> REMOTE_APPROVED          (cross-division authorized)
    q4_financial_results    pending_approval  -> REMOTE_NEEDS_APPROVAL    (cross-division needs approval)
    security_incidents      (no grant)        -> REMOTE_DENIED            (denied, no leak)
    <chit-chat>             n/a               -> LOCAL_DENIED             (out of scope)
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent

# ── Question templates (varied phrasings → exercise the embedder) ─────────────
TEMPLATES = [
    "What does the policy say about {t}?",
    "Tell me about {t}.",
    "Can you explain {t}?",
    "How are we handling {t}?",
    "I need details on {t}.",
    "What's our position on {t}?",
    "Summarise {t} for me.",
    "Give me the specifics of {t}.",
    "What are the rules around {t}?",
    "Walk me through {t}.",
    "Remind me how {t} works.",
    "Could you look up {t}?",
    "What do we do regarding {t}?",
    "Is there guidance on {t}?",
]

# ── Per-doc TOPICS (real content of each seeded doc) ──────────────────────────
DOCS = {
    "data_retention_policy": dict(
        pane="alpha", division="Division Alpha", situation="local_authorized",
        flow="LOCAL_ALLOWED", persona="alice",
        why="alice holds a `viewer` relation on this chunk in alpha's OpenFGA -> immediate local answer",
        topics=[
            "how long active customer records are kept",
            "retention of inactive customer records",
            "how long customer emails and chat are stored",
            "whether payment card data is stored",
            "how many years payroll records are retained after someone leaves",
            "retention of performance reviews after employment ends",
            "how long recruitment records for rejected candidates are kept",
            "retention period for health and benefits records",
            "how long the general ledger and invoices are retained",
            "tax record retention requirements",
            "expense report retention",
            "how long server and application logs are kept online",
            "security event log retention",
            "how long daily and monthly backups are retained",
            "source code repository retention",
            "GDPR erasure and right-to-be-forgotten handling",
            "how quickly personal data is purged after an erasure request",
            "the procedure for destroying digital and paper records",
            "who must approve exceptions to scheduled data destruction",
            "how often the data retention policy is reviewed",
            "who owns the data retention policy",
            "the classification level of the retention policy",
            "which people and vendors the retention policy applies to",
            "data retention for third-party vendors",
        ],
    ),
    "hr_compensation_data": dict(
        pane="alpha", division="Division Alpha", situation="local_needs_approval",
        flow="LOCAL_NEEDS_APPROVAL", persona="alice",
        why="alice holds a `pending_approval` relation (not viewer) -> a durable approval is opened to the data owner",
        topics=[
            "the salary band for a junior engineer",
            "associate level operations pay",
            "the compensation range for sales roles",
            "marketing salary bands",
            "senior engineering compensation",
            "the commission plan and OTE for sales",
            "C-suite executive compensation",
            "annual base pay by level",
            "bonus structure and targets",
            "how salary bands differ between engineering and operations",
            "who is allowed to see compensation data",
            "the pay range for a principal engineer",
            "total compensation for senior management",
            "equity or stock components of pay",
        ],
    ),
    "technical_architecture": dict(
        pane="alpha", division="Division Beta (federated)", situation="cross_division_authorized",
        flow="REMOTE_APPROVED", persona="alice",
        why="alice is cross-granted `viewer` in BETA's OpenFGA -> alpha delegates, beta re-authorizes, immediate federated answer",
        topics=[
            "the Kubernetes cluster topology",
            "which cloud regions the platform runs in",
            "the node pools used for ML inference",
            "how services communicate securely",
            "the service mesh in use",
            "the CNI plugin and version",
            "how high availability is achieved",
            "the ingress setup",
            "the availability zones in us-east-1",
            "the EKS version running",
            "the microservices architecture overview",
            "how data residency compliance is handled in the architecture",
            "the general-purpose node instance types",
            "GPU instances used for inference",
            "the cluster mesh configuration",
            "how mTLS is enforced between services",
            "the overall platform design",
            "which clusters host which workloads",
        ],
    ),
    "q4_financial_results": dict(
        pane="alpha", division="Division Beta (federated)", situation="cross_division_needs_approval",
        flow="REMOTE_NEEDS_APPROVAL", persona="alice",
        why="alice holds `pending_approval` in BETA's store -> beta opens an approval to bob (data owner) before release",
        topics=[
            "total revenue for Q4 2025",
            "year-over-year revenue growth",
            "quarter-over-quarter growth",
            "what drove the record quarter",
            "the ACME Pro tier launch impact",
            "full year 2025 financial results",
            "enterprise ARR expansion",
            "Q4 profit margins",
            "the executive summary of Q4 results",
            "how the Pro tier affected revenue",
            "net income for the quarter",
            "the financial highlights for the board",
        ],
    ),
    "security_incidents": dict(
        pane="alpha", division="Division Beta (federated)", situation="denied_no_leak",
        flow="REMOTE_DENIED", persona="alice",
        why="alice has NO relation on this chunk in beta -> denied; she can't even tell the document exists (control case)",
        topics=[
            "open security incidents",
            "unremediated vulnerabilities",
            "the security incident register",
            "any recent breaches",
            "active threats being tracked",
            "the most severe incident on record",
            "incidents involving customer data",
            "the CISO's incident handling notes",
            "historical security incidents",
            "any compromised systems",
        ],
    ),
}

# ── Out-of-scope / chit-chat (intent classifier -> answered locally, no data) ─
OUT_OF_SCOPE = [
    "How are you today?", "What's the weather like?", "Tell me a joke.",
    "Good morning!", "What's your name?", "How was your weekend?",
    "What's the capital of France?", "Can you write me a poem?",
    "What's 2 plus 2?", "Who won the world cup in 2018?",
    "Do you like coffee?", "What time is it?", "Recommend a good movie.",
    "What's the meaning of life?", "How do I bake bread?",
    "Tell me something interesting.", "What's your favourite colour?",
    "Are you a robot?", "Sing me a song.", "What should I have for lunch?",
    "How tall is Mount Everest?", "Translate hello into Spanish.",
    "What's a fun fact?", "Give me a motivational quote.",
]


def _gen_doc_scenarios(doc: str, cfg: dict) -> list[dict]:
    out = []
    # Cross-product templates x topics, but cap per-doc so the corpus stays balanced.
    combos = list(itertools.product(cfg["topics"], TEMPLATES))
    for i, (topic, tmpl) in enumerate(combos):
        out.append({
            "id": f"{doc}-{i:03d}",
            "situation": cfg["situation"],
            "persona": cfg["persona"],
            "pane": cfg["pane"],
            "target": cfg["division"],
            "doc": doc,
            "query": tmpl.format(t=topic),
            "expected_flow": cfg["flow"],
            "why": cfg["why"],
        })
    return out


def build() -> list[dict]:
    scenarios: list[dict] = []
    for doc, cfg in DOCS.items():
        scenarios.extend(_gen_doc_scenarios(doc, cfg))
    for i, q in enumerate(OUT_OF_SCOPE):
        scenarios.append({
            "id": f"out_of_scope-{i:03d}",
            "situation": "out_of_scope",
            "persona": "alice",
            "pane": "alpha",
            "target": "Division Alpha (local)",
            "doc": None,
            "query": q,
            "expected_flow": "LOCAL_DENIED",
            "why": "intent classifier labels this non-company / chit-chat -> answered locally, no retrieval, no cross-division call",
        })
    return scenarios


def main() -> None:
    scenarios = build()
    (OUT / "scenarios.json").write_text(json.dumps(scenarios, indent=2), encoding="utf-8")

    # Human catalog grouped by situation.
    by_sit: dict[str, list[dict]] = {}
    for s in scenarios:
        by_sit.setdefault(s["situation"], []).append(s)
    SIT_TITLE = {
        "local_authorized": "✅ Local authorized — immediate answer",
        "cross_division_authorized": "✅ Cross-division authorized — immediate federated answer (no approval)",
        "local_needs_approval": "⏳ Local needs-approval — opens an approval to the data owner",
        "cross_division_needs_approval": "⏳ Cross-division needs-approval — beta opens an approval to bob",
        "denied_no_leak": "🚫 Denied (no leak) — control case; user can't tell the doc exists",
        "out_of_scope": "💬 Out of scope — chit-chat answered locally, no data, no cross-division call",
    }
    lines = [
        "# Scenario catalog — every governance situation",
        "",
        f"**{len(scenarios)} scenarios**, generated by `generate_scenarios.py`, grounded in the real",
        "content of the seeded documents (so each query exercises genuine hybrid vector retrieval,",
        "not keyword matching). Run them live with `python scenarios/run_scenarios.py` to verify the",
        "expected governed flow for each.",
        "",
        "Personas: **alice** (logs in to Division Alpha, left pane) · **bob** (Division Beta, right pane,",
        "data owner + approver). Send each query as the listed persona.",
        "",
    ]
    for sit, title in SIT_TITLE.items():
        items = by_sit.get(sit, [])
        if not items:
            continue
        lines.append(f"## {title}")
        lines.append("")
        lines.append(f"_{len(items)} scenarios — expected flow `{items[0]['expected_flow']}`. {items[0]['why']}_")
        lines.append("")
        # Show a generous sample inline (first 25), note the rest are in scenarios.json.
        for s in items[:25]:
            lines.append(f"- **{s['persona']}** → _{s['query']}_")
        if len(items) > 25:
            lines.append(f"- …and {len(items) - 25} more in `scenarios.json`.")
        lines.append("")
    (OUT / "SCENARIOS.md").write_text("\n".join(lines), encoding="utf-8")

    # Summary to stdout.
    print(f"generated {len(scenarios)} scenarios")
    for sit in SIT_TITLE:
        print(f"  {sit:32s} {len(by_sit.get(sit, []))}")
    print(f"wrote {OUT / 'scenarios.json'} and {OUT / 'SCENARIOS.md'}")


if __name__ == "__main__":
    main()
