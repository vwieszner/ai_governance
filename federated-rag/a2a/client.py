"""A2A client — calls the peer cluster agent via A2A protocol."""
from __future__ import annotations

import json
import time
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

# GQ-4: module-level frozenset so it is defined once and is hashable/immutable.
# Previously defined inside send_task() on every call.
_TERMINAL_STATES: frozenset[str] = frozenset({
    "completed", "failed", "canceled", "input-required"
})


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
            # MED-2: buffer data: lines and emit on the blank-line SSE delimiter.
            # The previous implementation yielded on every data: line, which broke
            # multi-line SSE payloads (multiple data: lines per event) by emitting
            # multiple incomplete events instead of one coalesced event.
            current_event_type: str = "message"
            data_lines: list[str] = []
            async for line in resp.aiter_lines():
                if not line:
                    # Blank line = end of one SSE event
                    if data_lines:
                        raw = "\n".join(data_lines)
                        try:
                            data = json.loads(raw)
                        except json.JSONDecodeError:
                            data = {"raw": raw}
                        yield {"event_type": current_event_type, "data": data}
                    # Reset for next event
                    current_event_type = "message"
                    data_lines = []
                elif line.startswith("event:"):
                    current_event_type = line[len("event:"):].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[len("data:"):].strip())
                # Lines starting with ':' are SSE comments/keepalives — ignored per spec

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
        # GQ-4: _TERMINAL_STATES is now a module-level frozenset

        # HIGH-4: the httpx timeout covers connection + first byte, NOT total stream
        # duration.  Once streaming starts the async-for loop can run indefinitely
        # (e.g., peer approval workflow takes hours).  Enforce a wall-clock deadline
        # so a stuck peer cannot leak this coroutine and its HTTP connection forever.
        _SSE_STREAM_TIMEOUT = 300.0  # 5 min; Temporal activity deadline fires before this
        _deadline = time.monotonic() + _SSE_STREAM_TIMEOUT

        # Accumulated task representation — merged from every event's data dict
        accumulated: dict[str, Any] = {}

        async for event in self.send_task_streaming(
            query=query,
            delegated_token=delegated_token,
            context_id=context_id,
            push_notification_url=push_notification_url,
        ):
            if time.monotonic() > _deadline:
                raise TimeoutError(
                    f"Peer SSE stream did not reach a terminal state within "
                    f"{_SSE_STREAM_TIMEOUT:.0f}s — possible stuck workflow on peer"
                )
            data = event.get("data", {})
            if isinstance(data, dict):
                # M3-4: merge carefully — history is the latest full snapshot,
                # not a delta; replace it entirely. All other fields are updated
                # normally.  A plain accumulated.update(data) would clobber history
                # if a later event contains a partial update without the history key.
                if "history" in data:
                    accumulated["history"] = data["history"]
                for key, val in data.items():
                    if key != "history":
                        accumulated[key] = val
                # Stop as soon as we hit a terminal task state
                state = (accumulated.get("status") or {}).get("state", "")
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
