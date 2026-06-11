"""DID-secured discovery service (M3, FR-3.1/3.2/3.5).

Standalone FastAPI app. Agents POST a DID-signed registration; peers GET /discover to
find capable agents at runtime. Control-plane only — capability metadata + endpoints +
DIDs + issuers, never division data.

Run: ``RAG_ENV_FILE=.env.<id> python -m discovery.service`` (or uvicorn discovery.service:app).
"""
from __future__ import annotations

import os
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request

from discovery.registry import DiscoveryEntry, DiscoveryRegistry, RegistrationError, verify_registration

log = structlog.get_logger(__name__)
_registry = DiscoveryRegistry()
app = FastAPI(title="AGT Discovery Service", version="1.0.0", docs_url=None, redoc_url=None)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "discovery", "agents": len(_registry.all())}


@app.post("/register")
async def register(request: Request) -> dict[str, Any]:
    """Register (or refresh) an agent. Body is a DID-signed registration object with
    division_id / agent_url / issuer / public_jwk / capabilities + an _agentmesh envelope."""
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")
    try:
        signer_did = verify_registration(payload)          # fail closed on bad signature/DID
    except RegistrationError as exc:
        log.warning("discovery_registration_rejected", error=str(exc))
        raise HTTPException(status_code=401, detail=f"registration rejected: {exc}")

    division_id = str(payload.get("division_id", "")).strip()
    agent_url = str(payload.get("agent_url", "")).strip()
    issuer = str(payload.get("issuer", "")).strip()
    caps = [str(c) for c in (payload.get("capabilities") or []) if str(c).strip()]
    if not (division_id and agent_url and issuer):
        raise HTTPException(status_code=400, detail="division_id, agent_url, issuer are required")

    _registry.register(DiscoveryEntry(
        division_id=division_id, agent_did=signer_did, agent_url=agent_url,
        issuer=issuer, public_jwk=str(payload.get("public_jwk")), capabilities=caps,
    ))
    log.info("discovery_registered", division_id=division_id, agent_did=signer_did, capabilities=caps)
    return {"registered": True, "agent_did": signer_did, "capabilities": caps}


@app.get("/discover")
async def discover(
    capability: str | None = Query(default=None),
    exclude_did: str | None = Query(default=None),
) -> dict[str, Any]:
    """Find live agents (optionally by capability), excluding the caller's own DID."""
    peers = _registry.find(capability=capability, exclude_did=exclude_did)
    return {"capability": capability, "count": len(peers), "peers": [e.public_view() for e in peers]}


@app.get("/agents")
async def agents() -> dict[str, Any]:
    return {"count": len(_registry.all()), "agents": [e.public_view() for e in _registry.all()]}


def main() -> None:
    port = int(os.environ.get("DISCOVERY_PORT", "8600"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
