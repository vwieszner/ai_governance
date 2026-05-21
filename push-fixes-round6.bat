@echo off
cd /d D:\work\ai_governance\ai_governance

git add federated-rag/rag/qdrant_retriever.py
git add federated-rag/auth/token_exchange.py
git add federated-rag/auth/openfga.py
git add federated-rag/workflow/activities.py
git add federated-rag/agent/nodes.py
git add federated-rag/tests/test_flows.py
git add federated-rag/pyproject.toml

git commit -m "fix: round-6 expert review — 14 findings across correctness, security, tests, deps

HIGH
  H-4  rag/qdrant_retriever.py  — _to_qdrant_id() converts chunk_id to UUID5
                                   via uuid.uuid5(NAMESPACE_OID, chunk_id) so
                                   Qdrant accepts the point ID (was 16-char hex,
                                   rejected server-side — every ingest silently dropped)
  H-1  auth/token_exchange.py   — audience allowlist now uses urlparse origin
                                   comparison (scheme+netloc) instead of string
                                   startswith(); crafted paths can no longer bypass

MEDIUM
  M-6  tests/test_flows.py      — test_approval_workflow_deny patches workflow.approval.*
                                   not workflow.activities.*; fake_execute returns None
  M-1  workflow/activities.py   — A2A callback payload now includes 'final': True for
                                   terminal states so peer SSE consumers close the stream
  M-3  auth/openfga.py          — revoke_pending_approval catches ApiException and checks
                                   exc.status == 404; broad string match removed so DNS /
                                   network / 5xx errors propagate to Temporal for retry
  M-5  tests/test_flows.py      — two new tests: test_exchange_token_audience_guard_rejects_invalid
                                   and _rejects_path_confusion verify the H-1 fix

LOW
  L-5  agent/nodes.py           — check_auth returns early with DENIED/REMOTE when
                                   chunk_ids is empty before calling batch_decide
  L-6  agent/nodes.py           — approval_request_id no longer echoed in user-visible
                                   status_message (internal ID was surfaced to callers)
  L-7  agent/nodes.py           — chunk_ids capped at 50 before Temporal workflow start
                                   to prevent oversized gRPC event history entries

NIT
  N-1  pyproject.toml           — presidio-analyzer/anonymizer + spacy moved to [pii] extra
  N-2  pyproject.toml           — opentelemetry + langfuse moved to [observability] extra
  N-3  pyproject.toml           — tenacity moved to [retry] extra
                                   (none of these are imported at runtime in the core agent)"

git push origin main

echo.
echo Round-6 fixes pushed successfully.
pause
