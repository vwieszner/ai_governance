@echo off
echo Committing round-3 security and quality fixes...
cd /d D:\work\ai_governance\ai_governance

git add federated-rag/auth/token_exchange.py
git add federated-rag/rag/fusion.py
git add federated-rag/rag/qdrant_retriever.py
git add federated-rag/rag/ingest.py
git add federated-rag/agent/nodes.py
git add federated-rag/workflow/activities.py
git add federated-rag/workflow/approval.py
git add federated-rag/a2a/client.py
git add federated-rag/api/main.py
git add federated-rag/config.py
git add federated-rag/tests/conftest.py
git add federated-rag/pyproject.toml

git commit -m "fix: third-pass security and code quality fixes (C3-1/C3-2/C3-3, H3-2..H3-6, M3-1..M3-6, L3-1/L3-2/L3-4, N3-2/N3-4/N3-5)

Critical:
- C3-1: _jwks_lock now instantiated at module level (not lazily) — removes
        the check-then-set race in _get_jwks_lock() that could silently create
        duplicate lock objects and bypass thundering-herd protection (token_exchange.py)
- C3-2: RRF fallback chunk_id now uses SHA-256 (16 hex chars) instead of
        Python's hash() — hash() is non-deterministic across processes due to
        PYTHONHASHSEED and can produce collisions in the same process (fusion.py)
- C3-3: JWTError no longer logged with str(e) — python-jose includes raw JWT
        and decoded claim payloads in many error messages (PII/token leak) (main.py)

High:
- H3-2: Slack httpx client in _slack_notify now has explicit 10 s timeout (activities.py)
- H3-3: _get_service_account_token client now has explicit 10 s client-level timeout (activities.py)
- H3-4: handle_peer_result now catches exceptions from get_task and returns
        REMOTE_DENIED with a safe message instead of propagating a raw 500 (nodes.py)
- H3-5: Task ownership check is now deny-by-default — absent owner_id returns
        404 instead of allowing access (main.py)
- H3-6: start_approval no longer falls back to denied_chunk_ids; raises an
        error instead to prevent phantom approval flows (nodes.py)

Medium:
- M3-1: X-Request-ID header value sanitized to [a-zA-Z0-9-] max 64 chars to
        prevent header injection via CRLF sequences (main.py)
- M3-2: HybridQdrantRetriever.client() now uses asyncio.Lock with double-checked
        locking — same pattern applied to all other async singletons (qdrant_retriever.py)
- M3-3: reason param capped to 500 chars at /approve endpoint and in approval
        workflow to prevent oversized Slack payloads (main.py, approval.py)
- M3-4: send_task() SSE accumulation now merges history with latest full snapshot
        rather than overwriting with a later partial update (client.py)
- M3-5: exchange_token() validates target_audience against peer_agent_url before
        performing the OAuth exchange (token_exchange.py)
- M3-6: deprecated session-scoped event_loop fixture removed; replaced with
        asyncio_mode=auto + asyncio_default_fixture_loop_scope=session in
        pyproject.toml (conftest.py, pyproject.toml)

Low / Nits:
- L3-1: /tasks/send returns 400 if message has no text part (main.py)
- L3-2: user query logged at DEBUG not INFO to prevent PII in telemetry (nodes.py)
- L3-4: ingest_to_neo4j tracks per-chunk failures and raises if all chunks fail (ingest.py)
- N3-2: deferred imports (A2AClient, ApprovalWorkflow, WorkflowAlreadyStartedError)
        moved to top-level module imports (nodes.py)
- N3-4: dead _REQUIRED_SECRETS constant replaced with comment (config.py)
- N3-5: asyncio.ensure_future replaced with asyncio.create_task (main.py)"

git push origin main
echo Done.
