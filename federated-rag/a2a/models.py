"""
A2A v1.0 protocol data models.

Implements the core A2A spec:
  - AgentCard   (/.well-known/agent-card.json)
  - Task        (tasks/send, tasks/get)
  - TaskStatus  (submitted, working, input-required, completed, failed, canceled)
  - Message / Part
  - PushNotificationConfig
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


# ── AgentCard ─────────────────────────────────────────────────────────────────

class AgentCapabilities(BaseModel):
    streaming: bool = True
    push_notifications: bool = True
    state_transition_history: bool = True


class AgentSkill(BaseModel):
    id: str
    name: str
    description: str
    # PY-1: use Field(default_factory=...) — bare list literals are shared across
    # all instances that rely on the default, which can cause silent mutation bugs.
    input_modes: list[str] = Field(default_factory=lambda: ["text"])
    output_modes: list[str] = Field(default_factory=lambda: ["text"])


class AgentCard(BaseModel):
    schema_version: str = Field("1.0", alias="schemaVersion")
    name: str
    description: str
    url: str                                    # base URL of this agent
    version: str = "0.1.0"
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    skills: list[AgentSkill] = Field(default_factory=list)
    default_input_modes: list[str] = Field(default_factory=lambda: ["text"], alias="defaultInputModes")
    default_output_modes: list[str] = Field(default_factory=lambda: ["text"], alias="defaultOutputModes")

    model_config = {"populate_by_name": True}


# ── Task status ───────────────────────────────────────────────────────────────

class TaskState(str, Enum):
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"    # e.g. pending approval
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class TaskStatus(BaseModel):
    state: TaskState
    message: str | None = None           # human-readable state description
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Messages / Parts ──────────────────────────────────────────────────────────

class TextPart(BaseModel):
    type: Literal["text"] = "text"
    text: str


class DataPart(BaseModel):
    type: Literal["data"] = "data"
    data: dict[str, Any]
    mime_type: str = Field("application/json", alias="mimeType")
    model_config = {"populate_by_name": True}


Part = TextPart | DataPart


class Message(BaseModel):
    role: Literal["user", "agent"]
    parts: list[Part]
    message_id: str = Field("", alias="messageId")
    task_id: str | None = Field(None, alias="taskId")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"populate_by_name": True}


# ── Push notification config ──────────────────────────────────────────────────

class PushNotificationConfig(BaseModel):
    url: str                             # webhook URL to POST task updates to
    token: str | None = None             # bearer token for the webhook


# ── Task ──────────────────────────────────────────────────────────────────────

class Task(BaseModel):
    id: str
    context_id: str = Field("", alias="contextId")
    status: TaskStatus
    history: list[Message] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    push_notification: PushNotificationConfig | None = Field(None, alias="pushNotification")
    model_config = {"populate_by_name": True}


# ── Request / Response wrappers ───────────────────────────────────────────────

class SendTaskRequest(BaseModel):
    """Body for POST /tasks/send"""
    id: str | None = None                # if None, server generates one
    context_id: str = Field("", alias="contextId")
    message: Message
    push_notification: PushNotificationConfig | None = Field(None, alias="pushNotification")
    # Delegated token (RFC 8693) passed in Authorization header by the caller.
    # We read it from the header, not here, but the field is here for docs.
    model_config = {"populate_by_name": True}


class GetTaskRequest(BaseModel):
    """Query params for GET /tasks/{task_id}"""
    history_length: int = Field(0, alias="historyLength")
    model_config = {"populate_by_name": True}


class TaskStatusUpdateEvent(BaseModel):
    """SSE event payload."""
    id: str
    status: TaskStatus
    final: bool = False


class TaskArtifactUpdateEvent(BaseModel):
    """SSE artifact event payload."""
    id: str
    artifact: dict[str, Any]
