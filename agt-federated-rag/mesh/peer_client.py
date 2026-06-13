"""
AgentMesh peer client — cross-cluster agent-to-agent communication built on the
Microsoft Agent Governance Toolkit.

Transport: a real HTTP POST of a DID-signed message to the peer cluster's
``/a2a/query`` endpoint. AgentMesh supplies the *security envelope* (DID identity,
Ed25519 message signing, registry-backed trust scoring); HTTP is the wire. The
peer authenticates the call by verifying the Ed25519 signature. The delegated user's
identity travels as a DID-signed CLAIMS assertion (sub/email/email_verified/iss) —
NOT the user's raw bearer token (which a compromised peer could replay against the
user's home division). The peer binds the asserted issuer to this signer and re-runs
its own OpenFGA authorization for the delegated user.

Real toolkit APIs used here:
  - ``agentmesh.TrustBridge`` (via mesh)  — peer DID verification + trust score.
  - ``agentmesh.AgentMeshClient`` (via mesh.govern_action) — governance gate.
  - ``mesh.agent_identity.sign_outbound_message`` — Ed25519 message signing.
  - ``agent_os.circuit_breaker.CircuitBreaker`` — cascading-failure protection.

Security controls applied before any peer message is sent:
  1. Verify the peer DID + trust score against the AgentMesh registry.
  2. Check the circuit breaker (open → fail fast — ASI-08).
  3. Run the AGT governance gate for ``peer.send_message``.
  4. Sign the outbound message with this agent's DID credentials.
  5. Verify the peer's signature on the response (fail closed otherwise).
  6. Record the interaction in the TrustTracker (reward / penalty).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx
import structlog
from agentmesh.exceptions import AgentMeshError
from agent_os.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState

from config import settings
from mesh.agent_identity import (
    govern_action,
    report_trust_event,
    sign_outbound_message,
    verify_peer_identity,
    verify_signed_message,
)

log = structlog.get_logger(__name__)

# Path on the peer cluster that receives DID-signed federation queries.
_PEER_QUERY_PATH = "/a2a/query"

# Outbound HTTP timeout. The peer runs a full RAG + LLM pipeline on receipt, so
# this must exceed the peer's WORST-CASE LLM time — llm_timeout_seconds across
# the initial attempt plus every retry — or the caller would ReadTimeout while
# the peer is still working and (after failure_threshold such timeouts) open the
# circuit breaker against a slow-but-alive peer, failing even healthy calls fast.
# Derived from settings so it can't drift from the peer's LLM budget.
_PEER_HTTP_TIMEOUT = (
    settings.llm_timeout_seconds * (1 + settings.llm_max_retries) + 30.0
)

# ── Per-peer circuit breakers (ASI-08) ────────────────────────────────────────
_circuit_breakers: dict[str, CircuitBreaker] = {}
_cb_lock: asyncio.Lock = asyncio.Lock()


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
    user_assertion: dict | None = None,
    check_only: bool = False,
) -> PeerResponse:
    """
    Send a governed, DID-signed query to the peer agent over HTTP.

    The user's VALIDATED identity claims (user_assertion: sub/email/email_verified/iss)
    are carried inside the DID-signed, replay-protected payload so the peer can bind
    the asserted issuer to this signer and make its own OpenFGA authorization decision.
    No raw user bearer token is forwarded — so a compromised peer gets no credential it
    could replay against the user's home division. The plain user_id is diagnostic only.
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
        # M2: user_id is now diagnostic only — the receiver derives the authoritative
        # identity from the DID-signed user_assertion claims below, not this string.
        "user_id": user_id,
        # M2 (FR-3.6), security-hardened: the user's VALIDATED identity CLAIMS
        # (sub/email/email_verified/iss) — NOT a raw bearer token. Authenticity +
        # freshness come from the Ed25519 signature + ts/nonce on this envelope; the
        # receiver binds `iss` to this signer and re-authorizes via its own OpenFGA.
        "user_assertion": user_assertion or {},
        "context_id": context_id,
        "callback_url": callback_url,
        "source_cluster": settings.cluster_id,
        # M0 tenancy: the originating division, carried (and signed) in the A2A
        # envelope so the receiver can attribute + audit the cross-division call.
        "source_division": settings.division_id,
        # Approval-poll re-auth: signed in the envelope so the peer re-checks WITHOUT
        # restarting its approval workflow (no duplicate owner notifications per poll).
        "check_only": check_only,
    }
    signed_payload = await sign_outbound_message(payload)

    endpoint = peer_url.rstrip("/") + _PEER_QUERY_PATH
    log.info("peer_call_sending", peer_url=endpoint, peer_did=peer_did, trust_score=trust_score)

    # ── Step 5: real HTTP POST of the DID-signed message to the peer ─────────
    # AgentMesh provides the security envelope (DID + Ed25519 signature); HTTP is
    # the wire. The peer authenticates the call by verifying that signature.
    # M7: present this division's client cert on the outbound call when mTLS is enabled,
    # so the peer's CERT_REQUIRED server accepts us; None → plain HTTP (the demo posture).
    from transport.mtls import peer_tls_context
    _tls = peer_tls_context(settings)
    try:
        async with httpx.AsyncClient(
            timeout=_PEER_HTTP_TIMEOUT,
            verify=_tls if _tls is not None else True,
        ) as client:
            http_response = await client.post(endpoint, json=signed_payload)
        http_response.raise_for_status()
        response = http_response.json()
    except httpx.HTTPStatusError as exc:
        # Non-2xx from the peer (401 unverified signature, 403 governance, 5xx).
        cb.record_failure()
        log.error("peer_http_error", status_code=exc.response.status_code, error=str(exc))
        await report_trust_event(peer_did, "iatp_error", {"status": exc.response.status_code})
        raise AgentMeshError(
            f"Peer returned HTTP {exc.response.status_code}"
        ) from exc
    except Exception as exc:  # noqa: BLE001 — any transport failure trips the breaker
        cb.record_failure()
        # str() on httpx.ReadTimeout/ConnectTimeout is empty — log the exception
        # type so a timeout is distinguishable from a connection refusal etc.
        log.error("peer_call_failed", error_type=type(exc).__name__, error=repr(exc))
        await report_trust_event(peer_did, "call_failure", {"error": type(exc).__name__})
        raise

    # ── Step 6: verify the peer's signature on the response (fail closed) ─────
    # A valid HTTP 200 is not enough — the response body must carry the peer's
    # Ed25519 signature, verified against the configured peer public key. This
    # closes the loop: both directions of the exchange are DID-authenticated.
    if not isinstance(response, dict):
        cb.record_failure()
        await report_trust_event(peer_did, "unexpected_payload", {})
        raise AgentMeshError("Peer response was not a JSON object")

    resp_verified, resp_signer = await verify_signed_message(response)
    if not resp_verified or resp_signer != peer_did:
        cb.record_failure()
        log.error("peer_response_signature_invalid", peer_did=peer_did, signer=resp_signer)
        await report_trust_event(peer_did, "policy_violation", {"reason": "bad_response_signature"})
        raise AgentMeshError("Peer response signature could not be verified")

    cb.record_success()
    await report_trust_event(peer_did, "call_success", {})

    log.info("peer_call_success", peer_url=endpoint, status=response.get("status"))
    return PeerResponse(
        status=str(response.get("status", "unknown")),
        answer=response.get("answer"),
        task_id=str(response.get("task_id", "")),
        peer_did=peer_did,
        trust_score=trust_score,
    )
