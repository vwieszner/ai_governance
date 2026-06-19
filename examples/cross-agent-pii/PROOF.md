# PROOF — what we prove, how to reproduce it, and what it costs

One authoritative answer to the three questions: **what does this system prove**, **how do
you reproduce it from scratch**, and **what is the performance**. Every number below was run
live; nothing here is estimated.

---

## 1. What we prove — TWO governance layers

**A) DATA-ACCESS governance (federated RAG).** A user in one division asks a question; the
answer is gated **per chunk** by OpenFGA — `allowed` / `needs-approval` / `denied` — and the
cross-division path carries a DID-signed `/a2a/query` with the user's verifiable identity, so
the *receiving* division re-authorizes against its OWN store.
Proven by [`scenarios/run_scenarios.py`](../../scenarios/run_scenarios.py) — a **1,116-scenario**
corpus, **30/30** stratified live pass (see [`scenarios/SCENARIOS.md`](../../scenarios/SCENARIOS.md)).

**B) TOOL-SHARING governance (cross-agent tool delegation).** A department runs its OWN tools
locally and securely **borrows** other departments' tools over the DID-signed `/a2a/tool`
channel — and the *owner* re-authorizes the delegated user (the call is governed, not
bypassed). **This is the new layer**, and the rest of this doc focuses on it.

`source = local` ⇒ the department ran its own tool. `source = peer` (with a `peer_did`) ⇒ it
delegated over the signed `/a2a/tool` channel and **the peer authorized the delegated user** —
visible in the peer's audit log as `a2a_tool_executed` with `user_id` + `source_division`. The
delegated user is re-authorized by the owner; it is never bypassed.

---

## 2. The live cross-department scenarios (3 departments on kind-agt)

Three self-sufficient departments, each with its OWN data (Qdrant + OpenFGA) and its OWN
governed tools, collaborating both ways:

- **gamma** — Security / Legal — serves `tool.pii`, `tool.compliance`
- **delta** — Risk / Data-Gov — serves `tool.risk`, `tool.classify`
- **epsilon** — Finance — serves `tool.fincheck`

Reproduce (asserts each of the 6; last run: **6 passed, 0 failed**):

```bash
python examples/cross-agent-pii/prove_live.py
```

| Sender | Capability | Result | Proves |
|---|---|---|---|
| epsilon (Finance) | `tool.fincheck` | **LOCAL** | runs its OWN AML tool |
| epsilon | `tool.pii` | **PEER → gamma** | borrows Security/Legal's DLP tool |
| gamma (Security/Legal) | `tool.fincheck` | **PEER → epsilon** | borrows Finance's AML tool |
| gamma | `tool.pii` | **LOCAL** | runs its OWN PII tool |
| delta (Risk/Data-Gov) | `tool.risk` | **LOCAL** | runs its OWN EU AI Act risk tool |
| delta | `tool.compliance` | **PEER → gamma** | borrows Security/Legal's compliance tool |

Each row is a `POST /solve` to the **sender's** agent. The mix of LOCAL and PEER results on the
same capability (e.g. `tool.fincheck` is LOCAL for epsilon but PEER for gamma) is the proof that
ownership + delegation are both real and governed.

---

## 3. Stand up the clusters from scratch

Prereqs: a cluster context (`kind create cluster --name agt`) and `./.env` with `NVIDIA_API_KEY`.
Driver: [`scripts/bootstrap_k8s.py`](../../scripts/bootstrap_k8s.py).

```bash
# One division, turnkey (builds the image fresh by default).
python scripts/bootstrap_k8s.py --divisions gamma
#   apply overlay -> create Secret -> wait data plane -> provision (OpenFGA store/model +
#   Keycloak realm/users/roles + doc ingest + DID) -> complete Secret -> restart -> verify /health.
#   --no-build (with --source-tag <tag>) reuses an existing image instead of rebuilding.

# The full multi-department federated mesh (3 departments, two-way tool sharing):
python scripts/bootstrap_k8s.py --divisions gamma,delta,epsilon --federate
#   --federate cross-wires DID trust + auto-computes the full PEER_TOOL_MAP routing table:
#   each department routes every capability it does NOT serve to whichever peer serves it.
```

Each department is a **physically isolated stack**: its OWN Postgres/OpenFGA, Keycloak realm,
Temporal, Qdrant, Redis, agent + worker — and its OWN tools (`AGT_LOCAL_TOOLS`) + data. The
peer routing needs **no discovery broker** (it is configured, resolved against the
federation-wired `PEER_TRUST_MAP` trust anchor).

> **TLS-intercepting AV / proxy host:** the API embedder makes an external HTTPS call from the
> pod. If your host re-signs TLS (corporate MITM, some AV), mount the host CA bundle into the
> pods — see **k8s/README.md → "If your host does TLS interception"**.

---

## 4. Use the template — three extension points

The whole point is that it extends by **config**, not orchestration code. Each point is written
up with exact files + commands in **[`README.md`](README.md)**:

1. **Add a TOOL** — register it in `tools/local_tools.py`, assign via `AGT_LOCAL_TOOLS`, route
   via `PEER_TOOL_MAP` (or let `--federate` auto-route it).
2. **Add a RETRIEVAL CONNECTOR** — an external retrieval-as-a-service backend via the
   `RAAS_ENDPOINTS` env, fused into the department's retrieval, still per-chunk OpenFGA-authorized.
3. **Add a DEPARTMENT** — a new `infra/divisions/<id>.yml` + overlay, then
   `bootstrap_k8s.py --divisions <id> --federate` (the **epsilon** Finance department is the
   worked example).

---

## 5. Benchmarks / performance

Governance overhead is **sub-millisecond** and negligible next to LLM / retrieval latency.
Reproduce (from `agt-federated-rag/`):

```bash
RAG_ENV_FILE=__none__ python -m bench.bench_tools all
```

| Path | p50 | What it includes |
|---|---|---|
| **Local governed tool call** | **~206 µs** | raw tool fn ~62 µs + **~144 µs governance** (policy default-deny + MCP gateway + §4.2 credential guard) |
| **Secure cross-agent `/a2a/tool` round-trip** | **~2.4 ms** | sign → POST → verify + trust + assertion + policy + run → signed response → verify (in-process ASGI; excludes real network) |

So borrowing a peer's tool under full governance costs single-digit milliseconds in-process,
and a department's own governed tool call is a fraction of a millisecond.

**Test suite** (from `agt-federated-rag/`):

```bash
RAG_ENV_FILE=__none__ python -m pytest -q     # 368 passed, 1 skipped
```

---

## Reproduce-everything checklist

| Claim | Command |
|---|---|
| Data-access governance (1,116-scenario corpus, 30/30) | [`scenarios/run_scenarios.py`](../../scenarios/run_scenarios.py) · [`scenarios/SCENARIOS.md`](../../scenarios/SCENARIOS.md) |
| 6 live cross-department tool scenarios (6/6) | `python examples/cross-agent-pii/prove_live.py` |
| Stand up the federated 3-department mesh | `python scripts/bootstrap_k8s.py --divisions gamma,delta,epsilon --federate` |
| Tool latency benchmarks | `RAG_ENV_FILE=__none__ python -m bench.bench_tools all` |
| Full test suite (368 passed, 1 skipped) | `RAG_ENV_FILE=__none__ python -m pytest -q` |
