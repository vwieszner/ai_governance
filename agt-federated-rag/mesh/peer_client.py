"""
AGT AgentMesh peer client — IATP-encrypted cross-cluster agent communication.

Replaces the custom A2AClient + RFC 8693 token exchange from federated-rag.

What changed vs. the original:
  - No raw user JWTs forwarded to peers (was RFC 8693; now DID-signed messages)
  - Transport is IATP (Inter-Agent Trust Protocol) — end-to-end encrypted with
    Ed25519 + ephemeral ECDH key exchange; no TLS termination at the proxy layer
  - Every outbound message is signed with this agent's DID
  - Every inbound message has its DID signature verified before processing
  - AgentMesh trust scoring gates both send and receive
  - Circuit breaker (Agent SRE) wraps every peer call
  - All decisions are recorded in the AGT audit log
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import structlog
from agentmesh import AgentMeshClient, IATProtocolError  # type: ignore[import]
from agentmesh.trust import TrustScore  # type: ignore[import]
from agent_sre import CircuitBreaker, CircuitState  # type: ignore[import]

from config import settings
from mesh.agent_identity import (
    get_mesh,
    sign_outbound_message,
    verify_peer_identity,
    report_trust_event,
)

log = structlog.get_logger(__name__)

# ── Per-peer circuit breakers (Agent SRE — ASI-08) ───────────────────────────
# Key: peer_agent_url string.  Created lazily on first use.
_circuit_breakers: dict[str, CircuitBreaker] = {}
_cb_lock: asyncio.Lock = asyncio.Lock()


async def _get_circuit_breaker(peer_url: str) -> CircuitBreaker:
    if peer_url not in _circuit_breakers:
        async with _cb_lock:
            if peer_url not in _circuit_breakers:
                _circuit_breakers[peer_url] = CircuitBreaker(
                    name=f"peer:{peer_url}",
                    failure_threshold=5,        # open after 5 consecutive failures
                    recovery_timeout_seconds=30, # attempt half-open after 30 s
                    success_threshold=2,         # close after 2 consecutive successes
                )
    return _circuit_breakers[peer_url]


# ── Response dataclass ─────────────────────────────────────────────────────────

@dataclass
class PeerResponse:
    """Normalised response from a peer agent call."""
    status: str           # "completed" | "input_required" | "failed"
    answer: str | None
    task_id: str
    peer_did: str
    trust_score: float


# ── Main peer call ─────────────────────────────────────────────────────────────

async def call_peer_agent(
    query: str,
    user_id: str,
    context_id: str,
    callback_url: str | None = None,
) -> PeerResponse:
    """
    Send a governed query to the peer agent via IATP.

    Security controls applied (all before the HTTP call is made):
      1. Verify peer DID against AgentMesh registry
      2. Check peer trust score >= threshold
      3. Check circuit breaker state (open → fail fast)
      4. Sign outbound message with this agent's DID
      5. IATP transport encryption enforced by AgentMesh SDK
      6. Audit log entry written for every call attempt

    The *user_id* is included in the signed payload so the peer can make
    its own OpenFGA authorization decision.  No raw user JWT is forwarded —
    the peer trusts the user_id claim because it is signed by a verified agent DID.
    """
    if not settings.peer_agent_url:
        raise RuntimeError("No peer agent URL configured")

    peer_url = str(settings.peer_agent_url)

    # ── Step 1: verify peer DID ───────────────────────────────────────────────
    peer_did = settings.peer_agent_did
    if not peer_did:
        raise ValueError("PEER_AGENT_DID not configured — cannot verify peer identity")

    verified, trust_score = await verify_peer_identity(peer_did)
    if not verified:
        log.error("peer_did_not_verified", peer_did=peer_did)
        raise IATProtocolError(f"Peer DID '{peer_did}' could not be verified")

    if trust_score < settings.agent_trust_threshold:
        log.error(
            "peer_trust_below_threshold",
            peer_did=peer_did,
            trust_score=trust_score,
            threshold=settings.agent_trust_threshold,
        )
        raise IATProtocolError(
            f"Peer trust score {trust_score:.2f} is below threshold {settings.agent_trust_threshold}"
        )

    # ── Step 2: circuit breaker check ────────────────────────────────────────
    cb = await _get_circuit_breaker(peer_url)
    if cb.state == CircuitState.OPEN:
        log.warning("peer_circuit_open", peer_url=peer_url)
        raise RuntimeError(f"Circuit breaker OPEN for peer {peer_url} — call rejected")

    # ── Step 3: build and sign message ───────────────────────────────────────
    payload = {
        "query": query,
        "user_id": user_id,       # signed claim — peer can trust this
        "context_id": context_id,
        "callback_url": callback_url,
        "source_cluster": settings.cluster_id,
    }
    signed_payload = await sign_outbound_message(payload)

    # ── Step 4: IATP call ─────────────────────────────────────────────────────
    mesh = await get_mesh()
    client = AgentMeshClient(
        mesh=mesh,
        peer_url=peer_url,
        peer_did=peer_did,
        # IATP enforces encryption and DID verification on the transport layer.
        # The SDK raises IATProtocolError if the peer cannot be verified or
        # if the channel cannot be encrypted.
        require_encryption=True,
        require_verified_peer=True,
    )

    log.info(
        "peer_call_sending",
        peer_url=peer_url,
        peer_did=peer_did,
        user_id=user_id,
        trust_score=trust_score,
    )

    try:
        async with cb:  # circuit breaker wraps the actual call
            response = await client.send_governed_message(
                payload=signed_payload,
                timeout_seconds=30.0,
            )
    except IATProtocolError as exc:
        log.error("peer_iatp_error", error=str(exc))
        await report_trust_event(
            peer_did=peer_did,
            event_type="iatp_error",
            details={"error": str(exc)},
        )
        raise
    except Exception as exc:
        log.error("peer_call_failed", error=str(exc))
        await report_trust_event(
            peer_did=peer_did,
            event_type="call_failure",
            details={"error": str(exc)},
        )
        raise

    log.info(
        "peer_call_success",
        peer_url=peer_url,
        status=response.get("status"),
    )

    return PeerResponse(
        status=response.get("status", "unknown"),
        answer=response.get("answer"),
        task_id=response.get("task_id", ""),
        peer_did=peer_did,
        trust_score=trust_score,
    )


async def get_peer_circuit_state(peer_url: str | None = None) -> CircuitState:
    """Return the circuit breaker state for the configured peer."""
    url = peer_url or str(settings.peer_agent_url or "")
    if not url:
        return CircuitState.CLOSED
    cb = await _get_circuit_breaker(url)
    return cb.state
