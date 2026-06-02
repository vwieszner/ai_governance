"""
AgentMesh peer client — cross-cluster agent-to-agent communication built on the
Microsoft Agent Governance Toolkit.

Real toolkit APIs used here:
  - ``agentmesh.ProtocolBridge``          — the actual peer message transport
                                            (a2a → iatp protocol bridging).
  - ``agentmesh.TrustBridge`` (via mesh)  — peer DID verification + trust score.
  - ``agentmesh.AgentMeshClient`` (via mesh.govern_action) — governance gate.
  - ``agent_os.circuit_breaker.CircuitBreaker`` — cascading-failure protection.

Security controls applied before any peer message is sent:
  1. Verify the peer DID + trust score against the AgentMesh registry.
  2. Check the circuit breaker (open → fail fast — ASI-08).
  3. Run the AGT governance gate for ``peer.send_message``.
  4. Sign the outbound message with this agent's DID credentials.
  5. Record the interaction in the TrustTracker (reward / penalty).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import structlog
from agentmesh import ProtocolBridge
from agentmesh.exceptions import AgentMeshError
from agent_os.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState

from config import settings
from mesh.agent_identity import (
    get_did,
    govern_action,
    report_trust_event,
    sign_outbound_message,
    verify_peer_identity,
)

log = structlog.get_logger(__name__)

# ── Per-peer circuit breakers (ASI-08) ────────────────────────────────────────
_circuit_breakers: dict[str, CircuitBreaker] = {}
_cb_lock: asyncio.Lock = asyncio.Lock()
_protocol_bridge: ProtocolBridge | None = None
_bridge_lock: asyncio.Lock = asyncio.Lock()


async def _get_circuit_breaker(peer_url: str) -> CircuitBreaker:
    """Return (creating once) the circuit breaker for a peer URL."""
    cb = _circuit_breakers.get(peer_url)
    if cb is not None:
        return cb
    async with _cb_lock:
        cb = _circuit_breakers.get(peer_url)
        if cb is None:
            cb = CircuitBreaker(
                config=CircuitBreakerConfig(
                    failure_threshold=5,            # open after 5 consecutive failures
                    recovery_timeout_seconds=30.0,  # attempt half-open after 30 s
                )
            )
            _circuit_breakers[peer_url] = cb
    return cb


async def _get_protocol_bridge() -> ProtocolBridge:
    """Return (creating once) the AgentMesh ProtocolBridge for peer transport."""
    global _protocol_bridge
    if _protocol_bridge is not None:
        return _protocol_bridge
    did = await get_did()
    async with _bridge_lock:
        if _protocol_bridge is None:
            _protocol_bridge = ProtocolBridge(
                agent_did=did,
                supported_protocols=["a2a", "iatp"],
            )
    return _protocol_bridge


@dataclass
class PeerResponse:
    """Normalised response from a peer agent call."""
    status: str            # "completed" | "input_required" | "failed"
    answer: str | None
    task_id: str
    peer_did: str
    trust_score: float


async def get_peer_circuit_state(peer_url: str | None = None) -> CircuitState:
    """Return the circuit-breaker state for the configured (or given) peer."""
    url = peer_url or str(settings.peer_agent_url or "")
    if not url:
        return CircuitState.CLOSED
    cb = await _get_circuit_breaker(url)
    return cb.get_state()


async def call_peer_agent(
    query: str,
    user_id: str,
    context_id: str,
    callback_url: str | None = None,
) -> PeerResponse:
    """
    Send a governed, signed query to the peer agent via the AgentMesh
    ProtocolBridge.

    The user_id is carried inside the signed payload so the peer can make its own
    OpenFGA authorization decision. No raw user JWT is forwarded — the peer
    trusts the user_id because the message is signed by this agent's verified DID.
    """
    if not settings.peer_agent_url:
        raise RuntimeError("No peer agent URL configured")
    peer_url = str(settings.peer_agent_url)

    peer_did = settings.peer_agent_did
    if not peer_did:
        raise ValueError("PEER_AGENT_DID not configured — cannot verify peer identity")

    # ── Step 1: verify peer DID + trust score against the AgentMesh registry ──
    verified, trust_score = await verify_peer_identity(peer_did)
    if not verified:
        log.error("peer_did_not_verified", peer_did=peer_did)
        raise AgentMeshError(f"Peer DID '{peer_did}' could not be verified")
    if trust_score < settings.agent_trust_threshold:
        log.error(
            "peer_trust_below_threshold",
            peer_did=peer_did,
            trust_score=trust_score,
            threshold=settings.agent_trust_threshold,
        )
        raise AgentMeshError(
            f"Peer trust score {trust_score:.2f} is below threshold "
            f"{settings.agent_trust_threshold}"
        )

    # ── Step 2: circuit breaker — fail fast if open ──────────────────────────
    cb = await _get_circuit_breaker(peer_url)
    if cb.get_state() == CircuitState.OPEN:
        log.warning("peer_circuit_open", peer_url=peer_url)
        raise RuntimeError(f"Circuit breaker OPEN for peer {peer_url} — call rejected")

    # ── Step 3: AGT governance gate for the outbound peer message ────────────
    gov = await govern_action(
        "peer.send_message",
        {
            "user_id": user_id,
            "peer_did": peer_did,
            "peer_trust_score": trust_score,
            "transport": "iatp",
        },
    )
    if not gov.allowed:
        log.warning("peer_send_governance_denied", peer_did=peer_did, decision=gov.decision)
        raise AgentMeshError(f"Governance denied peer.send_message: {gov.decision}")

    # ── Step 4: build + sign the outbound message ────────────────────────────
    payload: dict[str, Any] = {
        "query": query,
        "user_id": user_id,        # signed claim — the peer can trust this
        "context_id": context_id,
        "callback_url": callback_url,
        "source_cluster": settings.cluster_id,
    }
    signed_payload = await sign_outbound_message(payload)

    log.info("peer_call_sending", peer_url=peer_url, peer_did=peer_did, trust_score=trust_score)

    # ── Step 5: send via the AgentMesh ProtocolBridge (a2a → iatp) ───────────
    bridge = await _get_protocol_bridge()
    try:
        response = await asyncio.to_thread(
            bridge.send_message,
            peer_did,
            signed_payload,
            "a2a",     # source_protocol
            "iatp",    # target_protocol
        )
    except AgentMeshError as exc:
        cb.record_failure()
        log.error("peer_iatp_error", error=str(exc))
        await report_trust_event(peer_did, "iatp_error", {"error": str(exc)})
        raise
    except Exception as exc:  # noqa: BLE001 — any transport failure trips the breaker
        cb.record_failure()
        log.error("peer_call_failed", error=str(exc))
        await report_trust_event(peer_did, "call_failure", {"error": str(exc)})
        raise

    cb.record_success()
    await report_trust_event(peer_did, "call_success", {})

    data: dict[str, Any] = response if isinstance(response, dict) else {}
    log.info("peer_call_success", peer_url=peer_url, status=data.get("status"))
    return PeerResponse(
        status=str(data.get("status", "unknown")),
        answer=data.get("answer"),
        task_id=str(data.get("task_id", "")),
        peer_did=peer_did,
        trust_score=trust_score,
    )
