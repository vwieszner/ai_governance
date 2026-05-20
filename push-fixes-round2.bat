@echo off
echo Committing round-2 security and quality fixes...
cd /d D:\work\ai_governance\ai_governance

git add federated-rag/workflow/activities.py
git add federated-rag/agent/nodes.py
git add federated-rag/auth/openfga.py
git add federated-rag/rag/neo4j_retriever.py
git add federated-rag/a2a/client.py
git add federated-rag/api/main.py
git add federated-rag/rag/ingest.py
git add federated-rag/workflow/approval.py

git commit -m "fix: second-pass security and reliability fixes (S-3/S-8/S-10/S-11, R-2/R-4/R-5/R-6, Q-2/Q-5/Q-6/Q-7)

Security:
- S-3:  SSRF guard in send_a2a_callback — validate peer_agent_url against
        configured allowlist before any HTTP call (activities.py)
- S-4:  Explicit httpx timeout on send_a2a_callback POST (activities.py)
- S-8:  All four synchronous singletons (_qdrant, _graph, _openfga, _llm)
        converted to async with asyncio.Lock double-checked locking (nodes.py)
- S-10: inp.query truncated to 500 chars before Slack block insertion (activities.py)
- S-11: asyncio.Lock added to OpenFGAAuth._get_client() to prevent check-then-set
        race at cold-start (openfga.py)

Reliability:
- R-2:  handle_peer_result validates delegated token is non-empty before calling
        peer A2A endpoint; returns REMOTE_DENIED if missing (nodes.py)
- R-4:  start_approval catches WorkflowAlreadyStartedError for idempotent retries (nodes.py)
- R-5:  threading.Lock added to GraphRAGRetriever._ensure_init() — all init code
        moved inside the lock so thread-pool callers cannot race (neo4j_retriever.py)
- R-6:  send_task() now consumes the SSE stream instead of calling resp.json()
        on an SSE response body; stops at first terminal task state (client.py)

Quality:
- Q-2:  _CorrelationIdMiddleware: echoes/generates X-Request-ID, binds to
        structlog context, returns header on every response (main.py)
- Q-5:  original_len saved before truncation so log records pre-truncation size (nodes.py)
- Q-6:  Neo4j driver in ingest_to_neo4j wrapped in try/finally (ingest.py)
- Q-7:  ApprovalInput.timeout_seconds snapshotted at workflow-start time;
        workflow uses inp.timeout_seconds instead of reading live settings,
        making Temporal replay deterministic (approval.py + nodes.py)"

git push origin main
echo Done.
