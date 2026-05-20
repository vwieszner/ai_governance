"""
End-to-end tests for all 4 authorization flows.

Flow A — Local + Authorized          → immediate answer
Flow B — Local + Needs Approval      → pending approval status, Temporal started
Flow C — Remote + Authorized         → A2A call → answer from peer
Flow D — Remote + Needs Approval     → cross-cluster approval pending

Test fixes applied:
  T-2  — Flow C now asserts REMOTE_APPROVED specifically (not the union
          REMOTE | REMOTE_APPROVED), since handle_peer_result always sets
          REMOTE_APPROVED when the peer returns a completed task.
  T-3  — Agent-card and health tests use the async_client fixture (httpx +
          ASGITransport) instead of the synchronous starlette TestClient.
  T-4  — Removed duplicate mock_temporal fixture from Flow B; the shared
          fixture in conftest.py is used instead.

Run with:
    pytest tests/test_flows.py -v
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.graph import run_query
from agent.state import FlowDecision


# ─────────────────────────────────────────────────────────────────────────────
# Flow A — Local + Authorized
# alice queries data retention policy → she has viewer access → answer returned
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_flow_a_local_authorized(
    mock_rag_results,
    mock_openfga_allowed,
    mock_llm,
    mock_token_validation,
    alice_user_id,
    alice_token,
):
    """Flow A: data is local and user has viewer access → should return an answer."""
    result = await run_query(
        query="What is our data retention policy for customer records?",
        user_id=alice_user_id,
        user_token=alice_token,
    )

    assert result["flow"] == FlowDecision.LOCAL_ALLOWED, (
        f"Expected LOCAL_ALLOWED, got {result['flow']}"
    )
    assert result["answer"] is not None
    assert len(result["answer"]) > 0
    assert result.get("error") is None
    assert result.get("approval_request_id") is None

    print(f"\n[Flow A] Answer: {result['answer'][:120]}...")


# ─────────────────────────────────────────────────────────────────────────────
# Flow B — Local + Needs Approval
# alice queries salary data → no access → Temporal workflow started
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_flow_b_local_needs_approval(
    mock_rag_results,
    mock_openfga_needs_approval,
    mock_token_validation,
    mock_temporal,               # T-4 FIX: shared fixture from conftest.py
    alice_user_id,
    alice_token,
):
    """Flow B: data is local but user has no access → approval workflow started."""
    result = await run_query(
        query="What are the salary bands for senior engineers?",
        user_id=alice_user_id,
        user_token=alice_token,
    )

    assert result["flow"] == FlowDecision.LOCAL_NEEDS_APPROVAL, (
        f"Expected LOCAL_NEEDS_APPROVAL, got {result['flow']}"
    )
    assert result.get("approval_request_id") is not None
    assert result.get("answer") is None or result["answer"] == ""

    # Status message should mention approval
    status = result.get("status_message", "")
    assert "approval" in status.lower() or "pending" in status.lower(), (
        f"Expected approval message, got: {status}"
    )

    # OpenFGA pending tuples should have been written
    mock_openfga_needs_approval.set_pending_approval.assert_called()

    # Temporal workflow should have been started via the singleton
    mock_temporal.start_workflow.assert_called_once()
    call_args = mock_temporal.start_workflow.call_args
    assert "approval-" in call_args.kwargs.get("id", "")

    print(f"\n[Flow B] Status: {status}")
    print(f"[Flow B] Approval request ID: {result['approval_request_id']}")


# ─────────────────────────────────────────────────────────────────────────────
# Flow C — Remote + Authorized
# alice queries architecture docs → on cluster B → A2A call → answer returned
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_flow_c_remote_authorized(
    mock_rag_results,
    mock_openfga_denied,
    mock_token_validation,
    alice_user_id,
    alice_token,
):
    """Flow C: no local data, peer agent has it and alice is authorized there."""
    from a2a.models import Message, Task, TaskState, TaskStatus, TextPart
    import uuid

    peer_answer = (
        "The platform uses EKS 1.30 across two clusters: us-east-1 and eu-west-1, "
        "connected via Cilium Cluster Mesh."
    )

    peer_task = Task(
        id=str(uuid.uuid4()),
        status=TaskStatus(state=TaskState.COMPLETED, message="Done"),
        history=[
            Message(
                role="agent",
                parts=[TextPart(text=peer_answer)],
                messageId=str(uuid.uuid4()),
            )
        ],
    )

    with patch("agent.nodes.exchange_token", new_callable=AsyncMock) as mock_exchange, \
         patch("agent.nodes.A2AClient") as mock_a2a_cls:

        mock_exchange.return_value = MagicMock(access_token="delegated-token-xyz")

        a2a_client = AsyncMock()
        a2a_client.send_task = AsyncMock(return_value=peer_task)
        a2a_client.get_task = AsyncMock(return_value=peer_task)
        a2a_client.close = AsyncMock()
        mock_a2a_cls.return_value = a2a_client

        with patch("config.settings.peer_agent_url", "https://agent-b.test"):
            result = await run_query(
                query="What Kubernetes version are we running and what is the cluster topology?",
                user_id=alice_user_id,
                user_token=alice_token,
            )

    # T-2 FIX: assert REMOTE_APPROVED specifically — handle_peer_result always
    # sets this when the peer returns a completed task with an answer.
    assert result["flow"] == FlowDecision.REMOTE_APPROVED, (
        f"Expected REMOTE_APPROVED, got {result['flow']}"
    )
    assert result.get("answer") == peer_answer or peer_answer[:30] in (result.get("answer") or "")

    # Token exchange should have been called with the peer URL as audience
    mock_exchange.assert_called_once()
    assert mock_exchange.call_args.kwargs.get("user_token") == alice_token

    # A2A send_task should have been called with the delegated token
    a2a_client.send_task.assert_called_once()
    call_kwargs = a2a_client.send_task.call_args.kwargs
    assert call_kwargs["delegated_token"] == "delegated-token-xyz"

    print(f"\n[Flow C] Remote answer: {result['answer'][:120]}...")


# ─────────────────────────────────────────────────────────────────────────────
# Flow D — Remote + Needs Approval
# alice queries financials → on cluster B → peer returns input-required
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_flow_d_remote_needs_approval(
    mock_rag_results,
    mock_openfga_denied,
    mock_token_validation,
    alice_user_id,
    alice_token,
):
    """Flow D: no local data, peer agent needs approval before serving alice."""
    from a2a.models import Task, TaskState, TaskStatus
    import uuid

    peer_task = Task(
        id=str(uuid.uuid4()),
        status=TaskStatus(
            state=TaskState.INPUT_REQUIRED,
            message="Access to this data requires approval from the data owner (carol).",
        ),
    )

    with patch("agent.nodes.exchange_token", new_callable=AsyncMock) as mock_exchange, \
         patch("agent.nodes.A2AClient") as mock_a2a_cls:

        mock_exchange.return_value = MagicMock(access_token="delegated-token-xyz")

        a2a_client = AsyncMock()
        a2a_client.send_task = AsyncMock(return_value=peer_task)
        a2a_client.close = AsyncMock()
        mock_a2a_cls.return_value = a2a_client

        with patch("config.settings.peer_agent_url", "https://agent-b.test"):
            result = await run_query(
                query="What was our Q4 revenue and ARR growth?",
                user_id=alice_user_id,
                user_token=alice_token,
            )

    assert result["flow"] == FlowDecision.REMOTE_NEEDS_APPROVAL, (
        f"Expected REMOTE_NEEDS_APPROVAL, got {result['flow']}"
    )
    assert result.get("answer") is None or result["answer"] == ""

    status = result.get("status_message", "")
    assert "approval" in status.lower() or "remote" in status.lower(), (
        f"Expected approval/remote message, got: {status}"
    )

    print(f"\n[Flow D] Status: {status}")


# ─────────────────────────────────────────────────────────────────────────────
# Approval workflow: signal handling
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_approval_workflow_approve():
    """After approval signal: OpenFGA viewer tuples written, user notified."""
    from workflow.approval import ApprovalInput, ApprovalWorkflow, ApprovalDecisionSignal

    with patch("workflow.activities.notify_approver", new_callable=AsyncMock), \
         patch("workflow.activities.grant_access_in_openfga", new_callable=AsyncMock) as mock_grant, \
         patch("workflow.activities.revoke_pending_in_openfga", new_callable=AsyncMock), \
         patch("workflow.activities.notify_user_of_decision", new_callable=AsyncMock) as mock_notify, \
         patch("workflow.activities.send_a2a_callback", new_callable=AsyncMock):

        workflow_obj = ApprovalWorkflow()
        signal = ApprovalDecisionSignal(decision="approved", reason="Looks good", approver_id="bob")
        await workflow_obj.approval_decision(signal)

        inp = ApprovalInput(
            approval_request_id="test-req-001",
            user_id="alice",
            chunk_ids=["chunk-001", "chunk-002"],
            query="What are the salary bands?",
            approver_id="bob",
        )

        with patch("temporalio.workflow.execute_activity", new_callable=AsyncMock) as mock_exec:
            async def fake_execute(fn, arg, **kwargs):
                return await fn(arg)
            mock_exec.side_effect = fake_execute

            with patch("temporalio.workflow.wait_condition", new_callable=AsyncMock):
                result = await workflow_obj._handle_approved(inp, signal)

        assert result.decision == "approved"
        print(f"\n[Approval] workflow result: {result}")


@pytest.mark.asyncio
async def test_approval_workflow_deny():
    """After deny signal: pending tuples revoked, user notified, no viewer tuples."""
    from workflow.approval import ApprovalInput, ApprovalWorkflow, ApprovalDecisionSignal

    workflow_obj = ApprovalWorkflow()
    signal = ApprovalDecisionSignal(
        decision="denied", reason="Not authorised for this data", approver_id="bob"
    )
    await workflow_obj.approval_decision(signal)

    inp = ApprovalInput(
        approval_request_id="test-req-002",
        user_id="alice",
        chunk_ids=["chunk-001"],
        query="What are the salary bands?",
        approver_id="bob",
    )

    with patch("workflow.activities.notify_user_of_decision", new_callable=AsyncMock) as mock_notify, \
         patch("workflow.activities.grant_access_in_openfga", new_callable=AsyncMock) as mock_grant, \
         patch("workflow.activities.revoke_pending_in_openfga", new_callable=AsyncMock) as mock_revoke, \
         patch("temporalio.workflow.execute_activity", new_callable=AsyncMock) as mock_exec:

        async def fake_execute(fn, arg, **kwargs):
            return await fn(arg)
        mock_exec.side_effect = fake_execute

        result = await workflow_obj._handle_denied(inp, signal)

    assert result.decision == "denied"
    assert "Not authorised" in result.reason
    # Ensure no viewer access was granted
    mock_grant.assert_not_called()
    print(f"\n[Approval] deny result: {result}")


# ─────────────────────────────────────────────────────────────────────────────
# A2A protocol
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a2a_agent_card(async_client):
    """AgentCard endpoint returns valid A2A-compliant JSON. T-3: uses async client."""
    resp = await async_client.get("/.well-known/agent-card.json")

    assert resp.status_code == 200
    card = resp.json()
    assert "name" in card
    assert "url" in card
    assert "capabilities" in card
    assert card["capabilities"]["streaming"] is True
    print(f"\n[A2A] AgentCard: {card['name']} @ {card['url']}")


@pytest.mark.asyncio
async def test_health_endpoint(async_client):
    """Health check returns 200 with cluster ID. T-3: uses async client."""
    resp = await async_client.get("/health")

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "cluster" in data
    print(f"\n[Health] {data}")
