@echo off
cd /d D:\work\ai_governance\ai_governance

git add federated-rag/api/main.py
git add federated-rag/auth/token_exchange.py
git add federated-rag/auth/openfga.py
git add federated-rag/rag/ingest.py
git add federated-rag/rag/qdrant_retriever.py
git add federated-rag/a2a/client.py
git add federated-rag/agent/nodes.py
git add federated-rag/workflow/activities.py
git add federated-rag/workflow/worker.py
git add federated-rag/config.py
git add federated-rag/pyproject.toml
git add federated-rag/tests/test_flows.py

git commit -m "fix: round-5 expert review — 19 findings across reliability, security, correctness

HIGH
  HIGH-1  api/main.py        — Redis singleton: asyncio.Lock + double-checked locking;
                               _store_task/_load_task catch all Redis errors → 503
  HIGH-2  api/main.py        — _store_callback_url dead write documented; made non-fatal
  HIGH-4  a2a/client.py      — SSE stream wall-clock deadline (300 s) so a stuck peer
                               cannot leak the coroutine and its HTTP connection forever

MEDIUM
  MED-1   rag/qdrant_retriever.py — retrieve() returns payload chunk_id, not str(point.id)
                                    (critical ACL bug: OpenFGA uses app-level chunk_id)
  MED-2   a2a/client.py      — SSE parser buffers data: lines and emits on blank-line
                               delimiter (fixes multi-line SSE payload handling)
  MED-3   auth/openfga.py    — revoke_pending_approval swallows tuple-not-found so
                               Temporal retries are idempotent
  MED-4   agent/nodes.py     — routing: only escalate to REMOTE when no local data exists;
                               DENIED with local data no longer incorrectly routes to peer
  MED-5   workflow/activities.py — _approval_url uses urlencode + quote (percent-encode
                                   query-string values; prevent header injection)
  MED-6   rag/ingest.py      — ingest_documents wrapped in try/finally; qdrant.close()
                               and graph.close() always called even if pipeline raises
  MED-7   auth/token_exchange.py — JWKS key lookup checks alg field to prevent key
                                   confusion when multiple keys share the same kid

LOW / NIT
  LOW-1   agent/nodes.py     — format_response returns generic message on error;
                               raw error strings no longer leak to API consumers
  LOW-2   rag/ingest.py      — split_text raises ValueError when overlap >= chunk_size
                               (prevents infinite loop in the chunker)
  LOW-3   api/main.py        — /approve response no longer echoes request_id or decision
  LOW-5   api/main.py        — validate_token raises 401 when sub claim is absent
  LOW-7   pyproject.toml     — removed unused authlib dependency
  NIT-1   agent/nodes.py     — user_id logged at DEBUG not INFO (PII reduction)
  NIT-2   tests/test_flows.py — test_approval_workflow_approve patches workflow.approval.*
                               (not workflow.activities.*) and fake_execute returns None
  NIT-3   workflow/worker.py — SIGTERM/SIGINT handler sets shutdown event for graceful drain
  NIT-4   config.py          — qdrant_api_key uses Field(default='') not Field(default=...)
                               (local Qdrant instances have no API key)"

git push origin main

echo.
echo Round-5 fixes pushed successfully.
pause
