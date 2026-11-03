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
import time
import uuid
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
# Path on the peer cluster that receives DID-signed delegated TOOL calls. The peer
# runs ITS OWN governed tool (policy gate + authorize the delegated user) and returns
# a DID-signed result. Same security envelope as _PEER_QUERY_PATH; different payload.
_PEER_TOOL_PATH = "/a2a/tool"

# FR-3.6: lifetime of the recipient-bound user assertion. The assertion travels
# inside the DID-signed, replay-protected envelope, so this short window is a
# second, RECIPIENT-SCOPED bound: even within the envelope's ±5-min freshness it
# limits how long a captured-and-re-presented assertion (e.g. one a compromised
# receiver tried to forward onward) could be accepted. Kept ≤ the envelope replay
# window so the two layers stay consistent.
_USER_ASSERTION_TTL_SECONDS = 300

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


def _breaker_key(peer_url: str) -> str:
    """Normalised breaker key for a peer's (trust-anchored) URL.

    Multi-peer: each ACTUAL target gets its own breaker, so a failing peer B opening its
    breaker never fails calls to a healthy peer C. Trailing-slash normalised so the legacy
    configured URL (pydantic renders ``http://h:9100/``) and the same peer's trust-anchor
    URL (``http://h:9100``) share ONE breaker instead of splitting its failure count."""
    return str(peer_url or "").rstrip("/")


async def _get_circuit_breaker(peer_url: str) -> CircuitBreaker:
    """Return (creating once) the circuit breaker for a peer URL."""
    peer_url = _breaker_key(peer_url)
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


@dataclass
class PeerToolResponse:
    """Normalised response from a delegated cross-agent TOOL call (/a2a/tool)."""
    status: str            # "completed" | "failed"
    result: Any            # the peer tool's signed result payload (or None on failure)
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


def resolve_trusted_peer_url(peer_did: str) -> str:
    """Return the DATA-PATH destination URL for ``peer_did`` from the LOCAL trust anchor.

    Multi-peer routing (FR-3 residual): when discovery selects a peer, the signed request
    must go to THAT peer — but WHERE it goes is taken ONLY from the operator-curated
    ``settings.peer_trust[peer_did]["agent_url"]``, never from the discovery broker's
    advertised ``agent_url`` (an open, self-asserted registry: trusting its URL would let a
    rogue registration steer signed traffic — broker-spoofed SSRF/redirect). The response is
    then verified against the same anchor's public key (verify_signed_message), so the
    destination and the verification key come from ONE trusted entry.

    FAIL CLOSED: a DID that is not a trust anchor, or an anchor with no agent_url, raises
    AgentMeshError before anything is signed or sent.
    """
    did = str(peer_did or "").strip()
    entry = settings.peer_trust.get(did) if did else None
    if not entry:
        log.warning("peer_target_untrusted_refused", peer_did=did)
        raise AgentMeshError(f"Peer DID '{did}' is not in the local trust map — refusing to route")
    url = str(entry.get("agent_url") or "").strip().rstrip("/")
    if not url:
        log.warning("peer_target_no_anchor_url_refused", peer_did=did)
        raise AgentMeshError(f"Trusted peer '{did}' has no agent_url in the trust map")
    return url


def _bind_user_assertion(claims: dict, *, audience: str) -> dict:
    """Build the RECIPIENT-BOUND, time-limited user assertion (FR-3.6).

    Takes the home division's already-validated identity claims (sub/email/
    email_verified/iss) and adds the binding fields that make the assertion
    verifiable and non-replayable AT THE RECEIVER:

      * ``aud`` — the TARGET division's DID. The receiver rejects the assertion
        unless ``aud`` equals its OWN DID, so an assertion minted for division B
        cannot be re-presented to division C (recipient binding).
      * ``iat`` / ``exp`` — issued-at and a short expiry (``_USER_ASSERTION_TTL_SECONDS``),
        so the assertion is only briefly acceptable even within the envelope window.
      * ``jti`` — a unique id (audit / future single-use tracking).

    These claims ride INSIDE the existing Ed25519 DID-signed, replay-protected
    envelope (sign_outbound_message), so they are already cryptographically
    authenticated as coming from this division's DID — no second signature or
    forwarded token is needed. ``iss`` is whatever the home claims carried; the
    receiver binds it to this signer's DID.
    """
    now = int(time.time())
    bound = dict(claims)
    bound["aud"] = audience
    bound["iat"] = now
    bound["exp"] = now + _USER_ASSERTION_TTL_SECONDS
    bound["jti"] = str(uuid.uuid4())
    return bound


async def _deliver_signed_payload(
    *,
    peer_url: str,
    peer_did: str,
    payload: dict[str, Any],
    govern_action_name: str,
    govern_context: dict[str, Any],
    endpoint_path: str,
) -> dict[str, Any]:
    """Shared cross-agent send+verify path for BOTH /a2a/query and /a2a/tool.

    Replicates the security controls in mesh.peer_client's module docstring, in order,
    for ANY signed peer payload so the two channels can never diverge in their envelope:

      1. verify the peer DID + trust score against the AgentMesh registry (fail closed);
      2. circuit breaker — fail fast if OPEN (ASI-08);
      3. AGT governance gate for the outbound action (``govern_action_name``);
      4. sign the outbound message with this agent's DID credentials;
      5. real HTTP POST of the signed message to ``endpoint_path``, presenting this
         division's client cert when mTLS is enabled (same transport.mtls context);
      6. verify the peer's Ed25519 signature on the response (signer == peer_did) — fail
         closed otherwise — and record success/failure in the TrustTracker + breaker.

    Returns the signature-VERIFIED response dict. Raises AgentMeshError / the original
    transport exception on any failure (every failure also trips the breaker + trust event),
    exactly as call_peer_agent did inline before this extraction.
    """
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
    gov = await govern_action(govern_action_name, {**govern_context,
                                                   "peer_did": peer_did,
                                                   "peer_trust_score": trust_score})
    if not gov.allowed:
        log.warning("peer_send_governance_denied", action=govern_action_name,
                    peer_did=peer_did, decision=gov.decision)
        raise AgentMeshError(f"Governance denied {govern_action_name}: {gov.decision}")

    # ── Step 4: sign the outbound message ────────────────────────────────────
    signed_payload = await sign_outbound_message(payload)
    endpoint = peer_url.rstrip("/") + endpoint_path
    log.info("peer_call_sending", peer_url=endpoint, peer_did=peer_did, trust_score=trust_score)

    # ── Step 5: real HTTP POST of the DID-signed message to the peer ─────────
    # M7: present this division's client cert on the outbound call when mTLS is enabled.
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
        cb.record_failure()
        log.error("peer_http_error", status_code=exc.response.status_code, error=str(exc))
        await report_trust_event(peer_did, "iatp_error", {"status": exc.response.status_code})
        raise AgentMeshError(f"Peer returned HTTP {exc.response.status_code}") from exc
    except Exception as exc:  # noqa: BLE001 — any transport failure trips the breaker
        cb.record_failure()
        log.error("peer_call_failed", error_type=type(exc).__name__, error=repr(exc))
        await report_trust_event(peer_did, "call_failure", {"error": type(exc).__name__})
        raise

    # ── Step 6: verify the peer's signature on the response (fail closed) ─────
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
    response["_trust_score"] = trust_score   # surface the gated trust score to the caller
    return response


async def call_peer_agent(
    query: str,
    user_id: str,
    context_id: str,
    callback_url: str | None = None,
    user_assertion: dict | None = None,
    check_only: bool = False,
    target_did: str | None = None,
) -> PeerResponse:
    """
    Send a governed, DID-signed query to the peer agent over HTTP.

    The user's VALIDATED identity claims (user_assertion: sub/email/email_verified/iss)
    are carried inside the DID-signed, replay-protected payload so the peer can bind
    the asserted issuer to this signer and make its own OpenFGA authorization decision.
    Before sending we make that assertion RECIPIENT-BOUND and time-limited (FR-3.6):
    we add ``aud`` = the target peer's DID, plus ``iat``/``exp``/``jti`` (see
    _bind_user_assertion). No raw user bearer token is forwarded — so a compromised
    peer gets no credential it could replay against the user's home division, and the
    `aud` binding means it cannot even forward this assertion to a THIRD division. The
    plain user_id is diagnostic only.

    Routing (multi-peer): ``target_did`` is the DID discovery selected. When given, the
    request goes to THAT peer — its URL comes from the local trust anchor
    (resolve_trusted_peer_url; an untrusted DID is refused before signing), the assertion
    ``aud`` is bound to it, the response must be signed by it (verified against its
    anchored key), and the circuit breaker is that peer's own. When omitted, the legacy
    single configured peer (PEER_AGENT_URL / PEER_AGENT_DID) is used exactly as before.
    """
    if target_did:
        peer_did = str(target_did)
        peer_url = resolve_trusted_peer_url(peer_did)   # fail closed: untrusted → AgentMeshError
    else:
        if not settings.peer_agent_url:
            raise RuntimeError("No peer agent URL configured")
        peer_url = str(settings.peer_agent_url)

        peer_did = settings.peer_agent_did
        if not peer_did:
            raise ValueError("PEER_AGENT_DID not configured — cannot verify peer identity")

    # Build the outbound query payload. Authenticity/freshness/trust + the response
    # signature check are handled uniformly by _deliver_signed_payload (which mirrors
    # the security envelope for BOTH /a2a/query and /a2a/tool — see its docstring).
    payload: dict[str, Any] = {
        "query": query,
        # M2: user_id is now diagnostic only — the receiver derives the authoritative
        # identity from the DID-signed user_assertion claims below, not this string.
        "user_id": user_id,
        # M2 (FR-3.6), security-hardened: the user's VALIDATED identity CLAIMS
        # (sub/email/email_verified/iss) — NOT a raw bearer token. Authenticity +
        # freshness come from the Ed25519 signature + ts/nonce on this envelope; the
        # receiver binds `iss` to this signer and re-authorizes via its own OpenFGA.
        # Wave 3: the assertion is RECIPIENT-BOUND (aud = this peer's DID) and
        # short-expiry (iat/exp/jti) so it is verifiable + non-replayable at the
        # receiver and cannot be re-presented to a third division.
        "user_assertion": _bind_user_assertion(user_assertion or {}, audience=peer_did),
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

    response = await _deliver_signed_payload(
        peer_url=peer_url,
        peer_did=peer_did,
        payload=payload,
        govern_action_name="peer.send_message",
        govern_context={"user_id": user_id, "transport": "iatp"},
        endpoint_path=_PEER_QUERY_PATH,
    )

    log.info("peer_call_success", peer_did=peer_did, status=response.get("status"))
    return PeerResponse(
        status=str(response.get("status", "unknown")),
        answer=response.get("answer"),
        task_id=str(response.get("task_id", "")),
        peer_did=peer_did,
        trust_score=float(response.get("_trust_score", 0.0)),
    )


async def call_peer_tool(
    peer_url: str,
    peer_did: str,
    capability: str,
    arguments: dict,
    *,
    user_assertion: dict,
    source_division: str,
    context_id: str | None = None,
) -> PeerToolResponse:
    """Delegate a single governed TOOL CALL to a peer over the DID-signed /a2a/tool channel.

    The peer runs ITS OWN governed tool (policy gate + authorizes the delegated user) and
    returns a DID-signed result. This is the SEND side; it mirrors call_peer_agent's send
    path exactly via the shared _deliver_signed_payload helper (peer DID + trust verify →
    circuit breaker → governance gate → sign → POST → verify response signature, fail closed).

    The delegated user's identity travels ONLY as ``user_assertion`` — the same
    RECIPIENT-BOUND, time-limited CLAIMS assertion call_peer_agent forwards (built by the
    orchestrator via _bind_user_assertion / mint_user_assertion with aud = this peer's DID).
    NO raw bearer token is ever placed on the wire, so a compromised peer gets no credential
    to replay, and the aud binding stops it re-presenting the assertion to a third division.

    Destination pinning (multi-peer): ``peer_url`` must equal the local trust anchor's URL for
    ``peer_did`` (resolve_trusted_peer_url). An untrusted DID, or a URL that differs from the
    anchor (e.g. one copied from a broker advertisement), is refused before anything is signed,
    so the bytes can only ever go where the operator-curated trust map says that DID lives.
    """
    anchored_url = resolve_trusted_peer_url(peer_did)   # fail closed: untrusted → AgentMeshError
    if str(peer_url or "").strip().rstrip("/") != anchored_url:
        log.warning("peer_tool_url_not_anchored_refused", peer_did=peer_did,
                    requested_url=peer_url, anchored_url=anchored_url)
        raise AgentMeshError(
            f"Destination for '{peer_did}' does not match its trust-anchor agent_url — refusing")
    peer_url = anchored_url

    payload: dict[str, Any] = {
        # The capability the peer must serve (e.g. "tool.calc"); the peer resolves it to its
        # own local server via server_for_capability — we never name the peer's server/tool.
        "capability": capability,
        "arguments": arguments,
        # FR-3.6: recipient-bound, time-limited user CLAIMS — never a raw token (see docstring).
        "user_assertion": user_assertion,
        "context_id": context_id or str(uuid.uuid4()),
        "source_cluster": settings.cluster_id,
        # M0 tenancy: the originating division, signed in the envelope for the peer's audit.
        "source_division": source_division,
    }

    response = await _deliver_signed_payload(
        peer_url=peer_url,
        peer_did=peer_did,
        payload=payload,
        govern_action_name="peer.send_message",
        govern_context={"transport": "iatp", "capability": capability},
        endpoint_path=_PEER_TOOL_PATH,
    )

    status = str(response.get("status", "unknown"))
    log.info("peer_tool_call_success", peer_did=peer_did, capability=capability, status=status)
    return PeerToolResponse(
        status=status,
        result=response.get("result"),
        task_id=str(response.get("task_id", "")),
        peer_did=peer_did,
        trust_score=float(response.get("_trust_score", 0.0)),
    )
