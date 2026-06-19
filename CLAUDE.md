# Working rules for this repo (read before doing anything)

## Hard rules — non-negotiable
1. **Reuse, never rebuild.** Before creating any new file/script/UI, check if one already exists for that purpose (grep, read the map below). Do NOT build a parallel implementation. The browser interface is `ui/` — never make a second one.
2. **Never claim "done" / "tested" / "works" without showing it running.** Run it, paste the real output. Unit tests passing ≠ the feature works end-to-end. A live demo is the bar.
3. **No scope drift.** Do the one thing asked. Don't "also add…" mid-task. If something else is needed, finish the task first, then mention it.
4. **Autonomous by default.** Don't ask the user to confirm obvious steps or "what exists" — read the repo and act. Only ask when a real decision is genuinely theirs.
5. **Secrets:** `.env`, `.env.*`, `infra/generated/`, `.tools/` are gitignored — never commit them, never print full secret values.

## Repo map (so you don't rebuild things that exist)
- **Browser chat UI** = `ui/` (Vite, dev server `:5173`). Talks to the per-division agents via a proxy (`/api/agt-a`→alpha `:9000`, `/api/agt-b`→beta `:9100`; `/auth/a`,`/auth/b`→Keycloak). This is the RAG/data-access chat (ask a question → governed retrieval → answer; cross-division federation + approvals).
  - Restart: `clusters.ps1 start alpha beta` (host agents; Compose infra is usually already up) then `cd ui; npm run start`. Logins: alice/Alpha, bob/Beta (seed passwords in `infra/generated/<div>/secrets.json`).
- **Agent backend** = `agt-federated-rag/` (FastAPI `api/main.py`, LangGraph `agent/`, retrieval `rag/`, mesh/DID `mesh/`, tools `tools/`). Tests: `RAG_ENV_FILE=__none__ python -m pytest -q` from that dir.
- **Cross-department tool delegation** = `POST /solve` (`api/main.py`) → `agent/nodes.solve_with_tools` → local tool or DID-signed `/a2a/tool` to a peer. Tools live in `tools/local_tools.py` (pii/compliance/risk/classify/fincheck), assigned per-division via `AGT_LOCAL_TOOLS`, routed via `PEER_TOOL_MAP`. Reproducible proofs: `examples/cross-agent-pii/prove_live.py` (asserts 6 live scenarios) and `try_tool.py` (CLI playground). Doc: `examples/cross-agent-pii/PROOF.md`.
- **Docker Compose** (local dev / the chat backend): per-division stacks via `scripts/onboard_division.py`; start/stop host agents via `scripts/clusters.ps1`; full bring-up `scripts/bootstrap.ps1`.
- **Kubernetes** (kind cluster `kind-agt`): `k8s/` kustomize (base + overlays per division) + turnkey `scripts/bootstrap_k8s.py --divisions <ids> [--federate]` (builds image fresh by default; provisions + ingests + DID + health; `--federate` wires cross-division trust + the tool routing table). Divisions on the cluster: gamma/delta/epsilon.
- **Docs**: `README.md` (map), `ARCHITECTURE.md` (validated Mermaid diagrams), `PROJECT_STATUS.md` (what's done, test reality), `k8s/README.md` (deploy + TLS-interception note), `scenarios/` (1,116 data-access scenarios + `run_scenarios.py`), `bench/` (perf).

## Environment gotchas (real, will bite you)
- **Norton TLS interception**: this host runs Norton, which MITMs TLS. Linux pods don't trust its CA, so pod→external-HTTPS fails. Fix on k8s: mount the host CA bundle over `/usr/lib/ssl/cert.pem` (see `k8s/README.md` "If your host does TLS interception"). On the host, the app's `truststore.inject_into_ssl()` already trusts the OS store. Norton also flags unsigned PowerShell that spawns hidden processes — prefer plain Python orchestration.
- **k8s embeddings**: the in-pod FastEmbed model download is blocked (Norton + size), so k8s divisions use the served API embedder (`EMBEDDING_PROVIDER=api`, NVIDIA NIM `nv-embedqa-e5-v5`, asymmetric `input_type`, `truncate=END`, `QDRANT_SCORE_THRESHOLD≈0.25`). Set `EMBEDDING_PROVIDER=api` in the env when ingesting on the host too.
- **Root `.env` pollution**: keep root `.env` to global keys only (`NVIDIA_API_KEY`). Per-division secrets (POSTGRES/KEYCLOAK/OPENFGA tokens) there get auto-read by docker compose and override the per-division `--env-file` → broken onboarding.
- **kubectl over the proxy is flaky** — retry on TLS aborts; the kind context uses `--insecure-skip-tls-verify`.

## Conventions
- Python via `.venv/Scripts/python.exe`. Match surrounding code style. Ruff clean.
- Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Branch off main before committing unless told otherwise; commit/push only when asked.
- Governance tools (DLP/PII, AML, risk, compliance) are intentionally DETERMINISTIC rule-based logic, not LLMs (auditable). The RAG/data layer DOES use a real LLM + hybrid vector search.
