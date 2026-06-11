"""Discovery client — an agent registers itself + discovers peers at runtime (M3, FR-3.1/3.2).

register_self publishes this agent's endpoint + capabilities, DID-signed; discover finds
capable peers (excluding self). The data path still verifies each discovered peer's DID +
re-authorizes — discovery only tells you WHO to ask, never grants access.
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from config import settings
from mesh.agent_identity import get_did, get_public_jwk, sign_outbound_message

log = structlog.get_logger(__name__)


async def register_self(discovery_url: str, capabilities: list[str], timeout: float = 10.0) -> dict[str, Any]:
    """Publish this agent (endpoint + capabilities + issuer + public JWK) to the discovery
    service, DID-signed so the registry can prove key possession."""
    pub = await get_public_jwk()
    payload: dict[str, Any] = {
        "division_id": settings.division_id,
        "agent_url": str(settings.agent_url),
        "issuer": str(settings.oidc_issuer),
        "public_jwk": json.dumps(pub),
        "capabilities": list(capabilities),
    }
    signed = await sign_outbound_message(payload)
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post(discovery_url.rstrip("/") + "/register", json=signed)
        r.raise_for_status()
        log.info("discovery_self_registered", url=discovery_url, capabilities=list(capabilities))
        return r.json()


async def discover(discovery_url: str, capability: str | None = None, timeout: float = 10.0) -> list[dict[str, Any]]:
    """Return peers (optionally filtered by capability), excluding this agent."""
    did = await get_did()
    params: dict[str, str] = {"exclude_did": did}
    if capability:
        params["capability"] = capability
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.get(discovery_url.rstrip("/") + "/discover", params=params)
        r.raise_for_status()
        return list(r.json().get("peers", []))
