"""A2A client — calls the peer cluster agent via A2A protocol."""
from __future__ import annotations

import json
import uuid
from typing import Any, AsyncIterator

import httpx
import structlog

from a2a.models import (
    AgentCard,
    Message,
    Part,
    PushNotificationConfig,
    SendTaskRequest,
    Task,
    TaskState,
    TaskStatus,
    TextPart,
)
from config import settings

log = structlog.get_logger(__name__)


class A2AClient:
    """
    HTTP client for the A2A v1.0 protocol.

    Handles:
      - AgentCard discovery
      - tasks/send (streaming SSE)
      - tasks/get  (polling)
      - Delegated token injection (RFC 8693) in Authorization header
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._base_url = (base_url or str(settings.peer_agent_url or "")).rstrip("/")
        self._http = httpx.AsyncClient(timeout=timeout)

    # ── AgentCard ─────────────────────────────────────────────────────────────

    async def fetch_agent_card(self) -> AgentCard:
        url = f"{self._base_url}/.well-known/agent-card.json"
        resp = await self._http.get(url)
        resp.raise_for_status()
        return AgentCard.model_validate(resp.json())

    # ── Task send (streaming) ─────────────────────────────────────────────────

    async def send_task_streaming(
        self,
        query: str,
        delegated_token: str,
        context_id: str = "",
        push_notification_url: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Send a task to the peer agent and stream SSE events.

        Yields dicts with keys: event_type, data (parsed JSON).
        """
        task_id = str(uuid.uuid4())
        message = Message(
            role="user",
            parts=[TextPart(text=query)],
            messageId=str(uuid.uuid4()),
            taskId=task_id,
        )
        push = (
            PushNotificationConfig(url=push_notification_url)
            if push_notification_url
            else None
        )
        payload = SendTaskRequest(
            id=task_id,
            contextId=context_id,
            message=message,
            pushNotification=push,
        )

        headers = {
            "Authorization": f"Bearer {delegated_token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }

        url = f"{self._base_url}/tasks/send"
        async with self._http.stream(
            "POST",
            url,
            content=payload.model_dump_json(by_alias=True),
            headers=headers,
        ) as resp:
            resp.raise_for_status()
            # FIX M-2: event_type is reset per SSE event (event: + data: pair).
            # Using a local variable scoped to each event prevents the previous
            # event's type from leaking into the next data line when the server
            # sends data: lines without a preceding event: line.
            current_event_type: str = "message"
            async for line in resp.aiter_lines():
                if not line:
                    # Blank line signals end of one SSE event — reset type
                    current_event_type = "message"
                    continue
                if line.startswith("event:"):
                    current_event_type = line[len("event:"):].strip()
                elif line.startswith("data:"):
                    raw = line[len("data:"):].strip()
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        data = {"raw": raw}
                    yield {"event_type": current_event_type, "data": data}

    # ── Task send (non-streaming) ─────────────────────────────────────────────

    async def send_task(
        self,
        query: str,
        delegated_token: str,
        context_id: str = "",
        push_notification_url: str | None = None,
    ) -> Task:
        """
        Send a task and return when the peer reaches a terminal state.

        FIX R-6: /tasks/send ALWAYS responds with SSE, never plain JSON.
        The previous implementation called resp.json() directly on an SSE
        response body, which would parse "data: {...}" as raw text and raise
        a JSONDecodeError.  This implementation delegates to send_task_streaming
        and collects events until a terminal state is reached.

        Terminal states: completed, failed, canceled, input-required.
        """
        _TERMINAL_STATES = {"completed", "failed", "canceled", "input-required"}

        # Accumulated task representation — merged from every event's data dict
        accumulated: dict[str, Any] = {}

        async for event in self.send_task_streaming(
            query=query,
            delegated_token=delegated_token,
            context_id=context_id,
            push_notification_url=push_notification_url,
        ):
            data = event.get("data", {})
            if isinstance(data, dict):
                accumulated.update(data)
                # Stop as soon as we hit a terminal task state
                state = (data.get("status") or {}).get("state", "")
                if state in _TERMINAL_STATES:
                    break

        if not accumulated:
            raise ValueError(
                "No task data received from peer agent SSE stream — "
                "the peer may have closed the connection without sending any events."
            )

        return Task.model_validate(accumulated)

    # ── Task get ──────────────────────────────────────────────────────────────

    async def get_task(self, task_id: str, delegated_token: str) -> Task:
        headers = {"Authorization": f"Bearer {delegated_token}"}
        resp = await self._http.get(
            f"{self._base_url}/tasks/{task_id}",
            headers=headers,
        )
        resp.raise_for_status()
        return Task.model_validate(resp.json())

    async def close(self) -> None:
        await self._http.aclose()
