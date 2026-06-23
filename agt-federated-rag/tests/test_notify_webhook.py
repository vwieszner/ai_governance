"""Outbound approval webhook — data-minimized payload + best-effort (never breaks the workflow)."""
from __future__ import annotations

import json

import pytest

import workflow.activities as A
from config import settings


def _input() -> "A.NotifyApproverInput":
    return A.NotifyApproverInput(
        approval_request_id="req-1",
        user_id="alice@example.com",
        chunk_ids=["secret-chunk-1", "secret-chunk-2"],
        query="What is bob's salary?",
        approver_id="bob@example.com",
        approver_slack_id=None,
        approver_email=None,
    )


@pytest.mark.asyncio
async def test_webhook_payload_is_data_minimized(monkeypatch):
    monkeypatch.setattr(settings, "notify_webhook_url", "http://hook.local/approvals")
    monkeypatch.setattr(settings, "approval_hmac_secret", "0" * 64)
    captured: dict = {}

    class _Resp:
        def raise_for_status(self): ...

    class _Client:
        def __init__(self, *a, **k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None):  # noqa: A002
            captured["url"], captured["json"] = url, json
            return _Resp()

    monkeypatch.setattr("httpx.AsyncClient", _Client)
    await A._webhook_notify(_input())

    p = captured["json"]
    assert captured["url"] == "http://hook.local/approvals"
    assert p["approval_request_id"] == "req-1"
    assert p["approver_id"] == "bob@example.com"
    assert "approve_url" in p and "deny_url" in p
    # DATA MINIMIZATION: the gated content must NOT leave the boundary in the webhook.
    body = json.dumps(p)
    assert "salary" not in body
    assert "secret-chunk" not in body
    assert "alice@example.com" not in body          # the requesting user is not disclosed either


@pytest.mark.asyncio
async def test_webhook_failure_does_not_raise(monkeypatch):
    monkeypatch.setattr(settings, "notify_webhook_url", "http://hook.local/approvals")
    monkeypatch.setattr(settings, "approval_hmac_secret", "0" * 64)

    class _Client:
        def __init__(self, *a, **k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k):
            raise RuntimeError("endpoint down")

    monkeypatch.setattr("httpx.AsyncClient", _Client)
    await A._webhook_notify(_input())   # must NOT raise — best-effort
