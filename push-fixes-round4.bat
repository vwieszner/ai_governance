@echo off
echo Committing round-4 code quality and best-practices fixes...
cd /d D:\work\ai_governance\ai_governance

git add federated-rag/api/main.py
git add federated-rag/workflow/activities.py
git add federated-rag/workflow/approval.py
git add federated-rag/agent/graph.py
git add federated-rag/agent/state.py
git add federated-rag/a2a/models.py
git add federated-rag/a2a/client.py
git add federated-rag/auth/openfga.py
git add federated-rag/auth/token_exchange.py
git add federated-rag/rag/neo4j_retriever.py
git add federated-rag/rag/qdrant_retriever.py
git add federated-rag/rag/fusion.py
git add federated-rag/rag/ingest.py
git add federated-rag/config.py
git add federated-rag/tests/conftest.py
git add federated-rag/tests/test_flows.py

git commit -m "fix: fourth-pass code quality and best-practices fixes (FA, GQ, TM, LG, PY, TS)

FastAPI (FA):
- FA-1: /tasks/send decorated with response_class=EventSourceResponse for correct OpenAPI schema
- FA-2: agent_card uses response_model=AgentCard + response_model_by_alias=True; returns object directly
- FA-3: get_task uses response_model=Task + response_model_by_alias=True; returns Task object
- FA-4: task_callback decorated with response_model=dict[str,bool]
- FA-5: handle_approval request: Request = None -> request: Request (was causing 422 on all calls)
- FA-6: Redis aclose() called in lifespan teardown — prevents socket leaks on pod termination
- FA-7: request.json() wrapped in try/except -> 422 on malformed JSON instead of 500

ASGI / General Quality (GQ):
- GQ-1: isinstance(part, dict) branch removed from send_task — unreachable after Pydantic validation
- GQ-3: receive_wrapper in _LimitBodySizeMiddleware no longer raises HTTPException (not caught
        by FastAPI outside the endpoint coroutine); now sends ASGI 413 response directly and
        raises private _BodyTooLargeError sentinel to abort processing cleanly
- GQ-4: _TERMINAL_STATES moved to module-level frozenset in a2a/client.py
- GQ-5: asyncio.Task parameterized as asyncio.Task[AgentState] in send_task
- GQ-6: qdrant_retriever uses settings.qdrant_dense_size instead of hardcoded 1024
- GQ-8: config.py slack_bot_token: str = '' -> str | None = None
- GQ-9/PY-9: ingest.py make_chunk_id: removed no-op f-string, return hash directly

Temporal (TM):
- TM-1: type: ignore[assignment] in approval.py replaced with explicit assert
- TM-2: grant_access_in_openfga and revoke_pending_in_openfga now use module-level
        OpenFGA singleton instead of creating a new client per activity call
- TM-3: send_a2a_callback raises RuntimeError on non-2xx so Temporal retries fire
- TM-5: _handle_timeout sends A2A callback to originating agent — prevents peer A2A
        task from staying stuck in INPUT_REQUIRED indefinitely

LangGraph (LG):
- LG-1: state.py documented why list fields have no Annotated reducers (sequential
        graph; adding operator.add would break replace semantics for check_auth etc.)
- LG-2: route_after_auth raises ValueError for unknown/None flow instead of silently
        routing to format_response and producing an empty response
- LG-4: import uuid moved to module top in agent/graph.py

Python best practices (PY):
- PY-1: AgentSkill and AgentCard list fields use Field(default_factory=...) not bare literals
- PY-2/PY-3: get_compiled_graph() and _compiled annotated with explicit types
- PY-5: unused 'from typing import Optional' removed from approval.py
- PY-6: redundant 'import asyncio' inside batch_decide removed (already module-level)
- PY-7: 'import asyncio' moved from method bodies to module top in neo4j_retriever.py
- PY-8: _SAFE_ID_CHARS regex compiled at module level (not on every request)
- PY-11: httpx.TimeoutException removed from except tuple in token_exchange.py
        (it is a subclass of httpx.HTTPError — was redundant)
- PY-12: forward reference string 'Settings' in config.py replaced by adding
         'from __future__ import annotations' at module top
- PY-15: dead deduplicate() function removed from fusion.py
- PY-16: redundant timeout=10.0 kwarg removed from _get_service_account_token post call

Testing (TS):
- TS-1: mock_token_validation now patches api.main.validate_token (the imported name)
        not auth.token_exchange.validate_token (the definition site)
- TS-3: Flow C assertion uses exact equality for peer answer, not weak 'or' fallback
- TS-4: Flow A asserts allowed_chunk_ids is non-empty
- TS-5: Flow B and D assert answer is strictly None, not None-or-empty-string"

git push origin main
echo Done.
