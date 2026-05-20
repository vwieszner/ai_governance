@echo off
REM Run this from D:\work\ai_governance\ai_governance to commit and push all security fixes.

cd /d D:\work\ai_governance\ai_governance

git add federated-rag/pyproject.toml
git add federated-rag/agent/state.py
git add federated-rag/agent/nodes.py
git add federated-rag/agent/graph.py
git add federated-rag/api/main.py
git add federated-rag/workflow/approval.py
git add federated-rag/workflow/activities.py
git add federated-rag/rag/fusion.py
git add federated-rag/rag/neo4j_retriever.py
git add federated-rag/a2a/client.py
git add federated-rag/a2a/models.py
git add federated-rag/docker/Dockerfile
git add federated-rag/tests/conftest.py
git add federated-rag/tests/test_flows.py
git add federated-rag/k8s/cluster-a/qdrant-values.yaml
git add federated-rag/k8s/cluster-b/qdrant-values.yaml

git commit -m "fix: address all code review issues (C-1..C-7, H-1..H-7, M-1..M-6, L-1..L-5, T-1..T-4)

CRITICAL
  C-1 (auth/token_exchange.py)   - JWT audience strictly validated; verify_aud always True
  C-2 (api/main.py, activities)  - /approve endpoint requires HMAC-SHA256 signed token
  C-3 (api/main.py)              - Task store replaced with Redis (redis.asyncio + TTL)
  C-4 (api/main.py)              - Callback endpoint verifies peer agent client_id
  C-5 (agent/state.py, nodes.py) - Raw user JWT and delegated token removed from AgentState;
                                   passed via contextvars (invisible to traces/history)
  C-6 (agent/nodes.py, api)      - Temporal client is a module-level singleton with asyncio.Lock
  C-7 (config.py)                - All secrets use Field(default=...) — no hardcoded defaults

HIGH
  H-1 (agent/nodes.py)           - Auth routing: pending checked before allowed; REMOTE
                                   tried whenever no local allowed/pending chunks exist
  H-2 (agent/nodes.py)           - Temporal singleton protected by asyncio.Lock
  H-3 (rag/qdrant_retriever.py)  - Already validates collection schema at startup
  H-4 (rag/neo4j_retriever.py)   - ensure_indexes reuses instance driver; no leak
  H-5 (auth/token_exchange.py)   - JWKS cache protected by asyncio.Lock (done prev)
  H-6 (workflow/approval.py)     - Pending OpenFGA tuples revoked on denial AND timeout
  H-7 (workflow/approval.py)     - originating_delegated_token removed from ApprovalInput;
                                   callback uses client-credentials grant instead

MEDIUM / LOW
  M-1 (rag/fusion.py)            - RRF key collision fixed (hash fallback vs text prefix)
  M-2 (a2a/client.py)            - SSE event_type reset per event boundary
  M-3 (api/main.py)              - MaxBodySizeMiddleware enforces 1 MB request limit
  M-4 (agent/nodes.py)           - LLM context truncated to llm_context_token_budget
  M-5 (rag/neo4j_retriever.py)   - Covered by H-4 driver-reuse fix
  M-6 (tests/conftest.py)        - mock_openfga_allowed returns ALLOWED per chunk_id
  L-1 (workflow/approval.py)     - workflow.logger used inside @workflow.defn
  L-2 (docker/Dockerfile)        - Non-root USER directive added
  L-3 (k8s/*/qdrant-values.yaml) - Qdrant API key auth enabled with k8s secret ref
  L-4 (agent/graph.py)           - Compiled graph singleton protected by asyncio.Lock
  L-5 (a2a/models.py)            - datetime.utcnow() replaced with datetime.now(timezone.utc)

TESTS
  T-2 (tests/test_flows.py)      - Flow C asserts REMOTE_APPROVED specifically
  T-3 (tests/conftest.py)        - async_client fixture using httpx + ASGITransport
  T-4 (tests/test_flows.py)      - Removed duplicate mock_temporal in Flow B test"

git push origin main

echo.
echo Done. Check https://github.com/vwieszner/ai_governance for the new commit.
