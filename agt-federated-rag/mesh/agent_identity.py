"""
AGT AgentMesh — DID-based zero-trust agent identity.

Replaces the RFC 8693 OIDC token exchange from federated-rag.
Instead of obtaining user-delegated tokens from Keycloak for cross-agent calls,
each agent has a cryptographic DID (Decentralized Identifier) with Ed25519 +
quantum-safe ML-DSA-65 credentials managed by AgentMesh.

Identity flow:
  1. On first start, generate a DID from the configured seed (deterministic).
  2. Register the DID with the AgentMesh registry (shared between clusters).
  3. When calling a peer agent, sign the outbound message with this DID.
  4. The peer verifies the signature against the registry before processing.

Trust scoring:
  AgentMesh maintains a trust score (0–1000) per agent based on observed
  behaviour.  Anomalies (rate spikes, policy violations, unexpected payloads)
  decay the score.  Our base-policy.yaml requires score >= 0.6 (600/1000).
"""
from __future__ import annotations

import asyncio
from typing import Any

import structlog
from agentmesh import AgentMesh, AgentIdentity  # type: ignore[import]
from agentmesh.lifecycle import LifecycleManager  # type: ignore[import]
from agentmesh.trust import TrustScore  # type: ignore[import]

from config import settings

log = structlog.get_logger(__name__)

# ── Module-level singleton (double-checked locking) ──────────────────────────
_mesh: AgentMesh | None = None
_identity: AgentIdentity | None = None
_mesh_lock: asyncio.Lock = asyncio.Lock()


async def get_mesh() -> AgentMesh:
    """Return (or initialise) the AgentMesh singleton."""
    global _mesh, _identity
    if _mesh is not None:
        return _mesh
    async with _mesh_lock:
        if _mesh is None:
            log.info("agentmesh_initialising", agent_name=settings.agent_name)
            _mesh = AgentMesh(
                agent_id=settings.agent_name,
                registry_url=settings.agent_mesh_registry_url,
                # Ed25519 + ML-DSA-65 credentials derived from the seed.
                # Using a deterministic seed means the DID is stable across
                # restarts and pod replacements.
                did_seed=bytes.fromhex(settings.agent_did_seed),
                trust_threshold=settings.agent_trust_threshold,
            )
            _identity = await _mesh.create_or_load_identity()
            log.info(
                "agentmesh_ready",
                did=_identity.did,
                trust_score=_identity.trust_score,
            )
    return _mesh


async def get_identity() -> AgentIdentity:
    """Return this agent's DID identity."""
    await get_mesh()
    assert _identity is not None
    return _identity


async def get_did() -> str:
    """Return this agent's DID string (e.g. did:mesh:cluster-a-rag-xxxx)."""
    identity = await get_identity()
    return identity.did


async def verify_peer_identity(peer_did: str) -> tuple[bool, float]:
    """
    Verify a peer agent's DID against the AgentMesh registry.

    Returns (verified: bool, trust_score: float 0.0–1.0).
    Called before processing any inbound peer message (peer-comms-policy.yaml).
    """
    mesh = await get_mesh()
    try:
        score: TrustScore = await mesh.verify_identity(peer_did)
        normalised = score.value / 1000.0   # convert 0–1000 to 0.0–1.0
        log.info("peer_identity_verified", peer_did=peer_did, trust_score=normalised)
        return True, normalised
    except Exception as exc:
        log.warning("peer_identity_verification_failed", peer_did=peer_did, error=str(exc))
        return False, 0.0


async def sign_outbound_message(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Sign an outbound message with this agent's DID credentials.

    The signature is embedded in the payload under the '_agentmesh' key.
    The peer's AgentMesh verifies this before evaluating the message.
    """
    mesh = await get_mesh()
    return await mesh.sign_message(payload)


async def rotate_credentials() -> None:
    """
    Rotate this agent's Ed25519 + ML-DSA-65 credentials.

    Should be called periodically (e.g. via a scheduled Kubernetes CronJob).
    AgentMesh updates the registry and invalidates the old credentials gracefully.
    """
    mesh = await get_mesh()
    lifecycle = LifecycleManager(mesh)
    await lifecycle.rotate_credentials()
    log.info("agentmesh_credentials_rotated")


async def report_trust_event(peer_did: str, event_type: str, details: dict[str, Any]) -> None:
    """
    Report a trust-relevant event about a peer agent to the AgentMesh registry.

    AgentMesh uses these events to update the peer's trust score.
    Examples: unexpected_payload, policy_violation, timeout, anomalous_rate.
    """
    mesh = await get_mesh()
    await mesh.report_event(peer_did=peer_did, event_type=event_type, details=details)
    log.info("trust_event_reported", peer_did=peer_did, event_type=event_type)
