# docs/archive — historical documents

These files are **kept for history only**. They are superseded and may contain claims that no
longer reflect (or never accurately reflected) the codebase. For verified current state, read
**`PROJECT_STATUS.md`** at the repo root.

| File | What it is | Why archived |
|---|---|---|
| `IMPLEMENTATION_PLAN.md` | The multi-division milestone plan (M0–M8 + review gates). | **Fully executed** as of 2026-06-17; no pending work. Some references are stale (k8s/Helm never built — deployment is Docker Compose; decision D-2 superseded). |
| `SESSION_STATUS.md` | Prior engineering handoff log (sessions 1–4). | Claims "M0–M8 + e2e complete & proven live" — the 2026-06-17 audit shows this over-claims (FR-3.6, FR-6, discovery, CRL, `/audit`). |
| `TEMPLATE_TASKS.md` | The earlier "production-grade template" task list (14 tasks). | Superseded by the multi-division product framing (PRD + plan). |
| `SECURITY_AUDIT.md` | Dated static security audit (2026-06). | Point-in-time; current posture lives in `THREAT_MODEL.md`. |
| `redteam-legacy/RED_FINDINGS.md` | Red-team probe results. | References the **retired** dual A2A+AGT topology (ports `:8000/:8002/:8010/:8012`, removed `federated-rag/` dir). |
| `redteam-legacy/BLUE_FIXES.md` | Blue-team triage log. | Same retired topology. |
| `redteam-legacy/GOVERNANCE_AUDIT.md` | Governance-correctness audit of both solutions. | Same retired topology (the A2A solution no longer exists). |

The **current** security review gate lives in `redteam/M0_REVIEW_{security,prod,quality}.md`
(repo root `redteam/`), not here. Everything in this folder is safe to delete if you don't want
the history.
