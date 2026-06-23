"""
AgentMesh identity — DID-based zero-trust agent identity, built on the
Microsoft Agent Governance Toolkit (``agentmesh-platform``).

Real toolkit APIs used here:
  - ``agentmesh.AgentIdentity``   — this agent's DID + Ed25519 credentials;
                                    ``sign()`` / ``verify_signature()`` / JWK export.
  - ``agentmesh.TrustBridge``     — peer trust verification (IATP handshake,
                                    registry-backed trust scoring).
  - ``agentmesh.AgentMeshClient`` — governed action execution.
  - ``agentmesh.TrustTracker``    — trust-event recording (reward / penalty).
  - ``agentmesh.lifecycle.LifecycleManager`` — credential rotation.

Identity flow:
  1. On first use, ``AgentIdentity.create()`` generates this agent's DID and
     Ed25519 keypair (deterministic name derived from the cluster id).
  2. Outbound messages are signed with the agent's private key
     (``sign_outbound_message``); the signature is embedded in an ``_agentmesh``
     envelope.
  3. Inbound peer messages are verified (``verify_signed_message``) against the
     peer's PUBLIC key — which is taken from trusted configuration
     (``peer_agent_public_jwk``), never from the message body.
  4. Peer identities are additionally checked against the AgentMesh registry via
     ``TrustBridge.verify_peer`` (trust score gate).
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Any

import structlog
from agentmesh import (
    AgentIdentity,
    AgentMeshClient,
    GovernanceResult,
    TrustTracker,
)
from agentmesh.exceptions import AgentMeshError
from agentmesh.lifecycle import LifecycleManager
from agentmesh.trust.handshake import (
    TIER_TRUSTED_THRESHOLD,
    IdentityRegistry,
)

from config import settings

log = structlog.get_logger(__name__)

# Stable agent id / DID name derived from the cluster — deterministic across
# restarts so the DID name is predictable for peer configuration.
_AGENT_ID: str = f"rag-agent-{settings.cluster_id}"

# ── Graph-level governance policy for AgentMeshClient ─────────────────────────
# A real agentmesh-format policy (not the library's built-in allow-all baseline)
# so the graph-level `govern_action` gate in agent.graph.run_query is an ENFORCING
# control, not a decorative no-op. Semantics:
#   • default_action: allow  → normal operation is preserved (every governed
#     action — agent.graph.invoke, peer.send_message — passes unless a deny rule
#     matches), so wiring this policy in cannot regress the working flows.
#   • kill-switch-deny-graph-invoke (priority 1000) → DENIES whenever the request
#     context carries `kill_switch_engaged: true`. run_query injects
#     `settings.agent_kill_switch_engaged` into the govern_action context, so an
#     operator can disable this agent by setting AGENT_KILL_SWITCH_ENGAGED=true.
#
# SCOPE / HONESTY: this is a DEPLOY-TIME operator disable lever — `settings` is
# built once at startup, so engaging the kill-switch means editing the env and
# RESTARTING the agent; it is NOT an instant runtime lever, and NOT an automatic
# trust-based self-trust trip (the mesh client's self-trust starts at 0.5 and only
# rises, so a trust-threshold rule could never function as a kill-switch — that
# automatic-trust-degradation control remains a design item). The real, fail-closed
# DATA-PATH enforcement is unchanged and lives elsewhere: per-node `_enforce`
# (Agent OS PolicyEvaluator, default-deny) + OpenFGA per-chunk ReBAC. This gate is
# defense-in-depth / an emergency off-switch on top of those.
_GRAPH_GOVERNANCE_POLICY = """\
apiVersion: governance.toolkit/v1
name: rag-graph-governance
agents:
  - "*"
default_action: allow
rules:
  - name: kill-switch-deny-graph-invoke
    description: Operator kill-switch engaged — deny graph invocation
    stage: pre_tool
    condition: kill_switch_engaged
    action: deny
    priority: 1000
"""

# Trust scores in the toolkit are integers on a 0–1000 scale; settings express
# the threshold as a 0.0–1.0 float. Convert at the boundary.
_TRUST_SCALE = 1000.0

# ── Module-level singletons (double-checked locking) ──────────────────────────
_identity: AgentIdentity | None = None
_mesh_client: AgentMeshClient | None = None
_trust_tracker: TrustTracker | None = None
_identity_registry: IdentityRegistry | None = None
_lock: asyncio.Lock = asyncio.Lock()

# ── Replay protection for DID-signed messages ─────────────────────────────────
# Every signed message carries a `ts` (unix seconds) and a `nonce` (uuid4) INSIDE
# the signed body, so both are covered by the Ed25519 signature and cannot be
# altered by a man-in-the-middle. On verify we reject a message whose timestamp
# is outside the freshness window OR whose (sender_did, nonce) has been seen
# before — defeating capture-and-replay even before TLS is in front of the mesh.
_REPLAY_MAX_AGE_SECONDS = 300          # accept messages within ±5 min of now
_SEEN_NONCE_MAX = 50_000               # hard cap on the seen-cache (memory bound)
# (sender_did, nonce) -> expiry_unix. A nonce need only be remembered for the
# freshness window: once `ts` ages out, the timestamp check rejects the replay,
# so the entry can be evicted.
_seen_nonces: dict[tuple[str, str], float] = {}
_seen_lock: asyncio.Lock = asyncio.Lock()

# Shared replay-nonce store. The in-process dict above only protects WITHIN one process — the
# moment the agent runs >1 replica behind a Service/LB, a captured envelope replayed to a
# DIFFERENT replica would pass (that replica never saw the nonce). Recording the nonce in the
# per-division Redis (atomic SET NX) closes that: the guard holds across replicas. If Redis is
# unreachable we DEGRADE to the in-process dict (single-replica still protected), never open.
_redis: Any = None
_redis_lock: asyncio.Lock = asyncio.Lock()


async def _get_redis() -> Any:
    global _redis
    if _redis is None:
        async with _redis_lock:
            if _redis is None:
                import redis.asyncio as aioredis
                _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


async def _seen_nonce_redis(sender_did: str, nonce: str) -> bool | None:
    """Atomically record (sender_did, nonce) in the shared store for the freshness window.
    Returns True if FRESH (first sighting), False if REPLAY (already recorded), or None if
    Redis is unavailable (caller then degrades to the in-process guard)."""
    try:
        r = await _get_redis()
        # SET key 1 NX EX <window>: returns truthy only if the key did NOT already exist.
        ok = await r.set(f"nonce:{sender_did}:{nonce}", "1", nx=True, ex=_REPLAY_MAX_AGE_SECONDS)
        return bool(ok)
    except Exception as exc:  # noqa: BLE001 — Redis down: degrade to the in-process guard
        log.warning("nonce_store_redis_unavailable", sender_did=sender_did, error=str(exc))
        return None


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic byte serialisation of a message for signing / verifying.

    The ``_agentmesh`` envelope is excluded so that the signer and the verifier
    operate over byte-identical input.
    """
    body = {k: v for k, v in payload.items() if k != "_agentmesh"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


# ── Identity ──────────────────────────────────────────────────────────────────

def _load_or_create_identity() -> AgentIdentity:
    """Load the persisted AgentMesh identity, or create and persist a new one.

    The identity (DID + Ed25519 keypair) MUST be stable across restarts and pod
    replacements, otherwise peers would have a stale public key configured. When
    ``agent_identity_path`` is set, the identity is persisted as a JWKS file
    (private key included) and reloaded on subsequent starts.
    """
    path = settings.agent_identity_path
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                jwks = json.load(fh)
            identity = AgentIdentity.from_jwks(jwks)
            log.info("agentmesh_identity_loaded", did=str(identity.did), path=path)
            return identity
        except Exception as exc:  # noqa: BLE001 — corrupt file → fall back to create
            log.error("agentmesh_identity_load_failed", path=path, error=str(exc))

    identity = AgentIdentity.create(
        name=_AGENT_ID,
        sponsor=settings.agent_sponsor_email,
        capabilities=["rag.query", "a2a.federate"],
        organization=settings.cluster_id,
        description=f"Federated RAG agent for {settings.cluster_id}",
    )
    log.info("agentmesh_identity_created", did=str(identity.did))

    if path:
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(identity.to_jwks(include_private=True), fh)
            # Private key on disk — restrict to owner-only (effective on POSIX).
            os.chmod(path, 0o600)
            log.info("agentmesh_identity_persisted", path=path)
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            log.error("agentmesh_identity_persist_failed", path=path, error=str(exc))
    elif settings.peer_agent_url:
        log.warning("agentmesh_identity_ephemeral_no_persistence_path")
    return identity


async def get_identity() -> AgentIdentity:
    """Return (loading/creating once) this agent's AgentMesh DID identity."""
    global _identity
    if _identity is not None:
        return _identity
    async with _lock:
        if _identity is None:
            _identity = _load_or_create_identity()
            log.info("agentmesh_identity_ready", did=str(_identity.did))
    return _identity


async def get_did() -> str:
    """Return this agent's DID string (e.g. ``did:mesh:...``)."""
    identity = await get_identity()
    return str(identity.did)


async def get_public_jwk() -> dict[str, Any]:
    """Return this agent's PUBLIC key as a JWK.

    Published by the /identity endpoint so a peer operator can copy it into
    their ``PEER_AGENT_PUBLIC_JWK`` configuration for callback verification.
    """
    identity = await get_identity()
    return identity.to_jwk(include_private=False)


async def get_mesh() -> AgentMeshClient:
    """Return (creating once) the AgentMesh governed-execution client."""
    global _mesh_client
    if _mesh_client is not None:
        return _mesh_client
    async with _lock:
        if _mesh_client is None:
            # Pass a real agentmesh-format policy (default-allow + a kill-switch
            # deny rule) instead of leaving the library to load its built-in
            # allow-all baseline — this makes the graph-level govern_action gate
            # in run_query an enforcing operator off-switch (see
            # _GRAPH_GOVERNANCE_POLICY for scope/honesty notes).
            _mesh_client = AgentMeshClient(
                agent_id=_AGENT_ID,
                capabilities=["rag.query", "a2a.federate"],
                policy_yaml=_GRAPH_GOVERNANCE_POLICY,
            )
            log.info("agentmesh_client_ready", agent_id=_AGENT_ID)
    return _mesh_client


def _build_identity_registry(self_identity: AgentIdentity) -> IdentityRegistry:
    """Build a local IdentityRegistry holding THIS agent and EVERY trusted peer.

    The AgentMesh trust handshake resolves peer DIDs (and their authoritative trust
    score) from an IdentityRegistry. M3 multi-peer: register every peer in the
    trusted-peers map (settings.peer_trust) — each reconstructed from its trusted public
    JWK — so the trust-score gate (verify_peer_identity) works for any of N trusted peers,
    not just one. (In single-peer deployments the map is the 1-entry PEER_AGENT_* map.)
    """
    reg = IdentityRegistry(require_attestation=False)
    reg.register(self_identity)
    for did, entry in settings.peer_trust.items():
        jwk = entry.get("public_jwk")
        if not jwk:
            continue
        try:
            peer_jwk = json.loads(jwk) if isinstance(jwk, str) else jwk
            peer_identity = AgentIdentity.from_jwk(peer_jwk)
            reg.register(peer_identity)
            log.info("peer_identity_registered", peer_did=str(peer_identity.did))
        except Exception as exc:  # noqa: BLE001 — bad/missing peer JWK must not crash startup
            log.warning("peer_identity_register_failed", peer_did=did, error=str(exc))
    return reg


async def _get_identity_registry() -> IdentityRegistry:
    """Return (creating once) the IdentityRegistry holding this agent + the peer.

    This is the source of truth for peer membership in the federation: the peer
    is registered out-of-band from its public JWK (see _build_identity_registry).
    Membership + active status is what verify_peer_identity checks — see the note
    there on why the registry handshake cannot run offline.
    """
    global _identity_registry
    if _identity_registry is not None:
        return _identity_registry
    identity = await get_identity()
    async with _lock:
        if _identity_registry is None:
            _identity_registry = _build_identity_registry(identity)
    return _identity_registry


async def _get_trust_tracker() -> TrustTracker:
    global _trust_tracker
    if _trust_tracker is not None:
        return _trust_tracker
    async with _lock:
        if _trust_tracker is None:
            _trust_tracker = TrustTracker()
    return _trust_tracker


# ── Message signing / verification ────────────────────────────────────────────

async def sign_outbound_message(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Sign an outbound message with this agent's DID credentials.

    Replay protection: a fresh ``ts`` (unix seconds) and ``nonce`` (uuid4) are
    added to the body BEFORE signing, so the signature covers them and the peer
    can reject stale or replayed messages (see verify_signed_message). Existing
    ``ts``/``nonce`` keys are always overwritten so a caller cannot accidentally
    (or maliciously) pin a stale value.

    Returns a new dict with the freshness fields plus an ``_agentmesh`` envelope
    holding the sender DID and the Ed25519 signature over the canonical message
    bytes. The peer verifies this with verify_signed_message() before processing.
    """
    identity = await get_identity()
    signed = dict(payload)
    signed["ts"] = int(time.time())
    signed["nonce"] = str(uuid.uuid4())
    signature = identity.sign(_canonical_bytes(signed))
    signed["_agentmesh"] = {
        "sender_did": str(identity.did),
        "signature": signature,
        "alg": "EdDSA",
    }
    return signed


async def verify_signed_message(payload: dict[str, Any]) -> tuple[bool, str | None]:
    """
    Cryptographically verify an inbound AgentMesh-signed message.

    SECURITY (review finding #1) — this is NOT verify_peer_identity().
    The Ed25519 signature in the ``_agentmesh`` envelope is verified against the
    peer's PUBLIC key, and that key is taken from trusted configuration
    (``settings.peer_agent_public_jwk``) — NEVER from the message body. A forged
    message that merely names a real DID, or that ships its own public key, is
    rejected. The verified signer DID must also equal the configured peer DID.

    Returns (verified, sender_did). Callers MUST fail closed on a False result.
    """
    block = payload.get("_agentmesh")
    if not isinstance(block, dict):
        log.warning("inbound_message_missing_agentmesh_block")
        return False, None
    sender_did = block.get("sender_did")
    signature = block.get("signature")
    if not sender_did or not signature:
        log.warning("inbound_message_incomplete_envelope")
        return False, None

    # M3 multi-peer: resolve the signer's PUBLIC key from the trusted-peers MAP (config)
    # keyed by the claimed DID — NEVER from the message body. A DID that is not a key in
    # the map is an UNTRUSTED peer → reject. This single membership check is THE data-path
    # trust decision and covers every caller of verify_signed_message (/a2a/query AND
    # /tasks/callback) uniformly. (The map is a 1-entry PEER_AGENT_* map in single-peer
    # deployments — one code path, no single-peer branch.)
    entry = settings.peer_trust.get(sender_did)
    if not entry or not entry.get("public_jwk"):
        log.warning("verify_signed_message_untrusted_peer", sender_did=sender_did)
        return False, None
    try:
        raw_jwk = entry["public_jwk"]
        peer_jwk = json.loads(raw_jwk) if isinstance(raw_jwk, str) else raw_jwk
        peer_identity = AgentIdentity.from_jwk(peer_jwk)
    except Exception as exc:  # noqa: BLE001 — bad/missing config must fail closed
        log.warning("verify_signed_message_bad_peer_jwk", error=str(exc))
        return False, None

    # The trusted key must derive the claimed DID (key/DID binding) — kept from single-peer.
    if str(peer_identity.did) != sender_did:
        log.warning(
            "verify_signed_message_did_mismatch",
            claimed=sender_did,
            configured_key_did=str(peer_identity.did),
        )
        return False, None

    try:
        verified = peer_identity.verify_signature(_canonical_bytes(payload), signature)
    except Exception as exc:  # noqa: BLE001 — any verify error → fail closed
        log.warning("verify_signed_message_verify_error", error=str(exc))
        return False, None
    if not verified:
        log.warning("verify_signed_message_signature_invalid", sender_did=sender_did)
        return False, None

    # ── Replay protection (signature already valid past this point) ──────────
    # The freshness check runs AFTER signature verification so that a forged
    # message can never insert an entry into the seen-nonce cache (which would
    # otherwise be a memory-exhaustion / cache-poisoning vector). ts + nonce are
    # part of the signed body, so a MITM cannot alter them without breaking the
    # signature.
    fresh = await _check_freshness_and_nonce(payload, sender_did)
    if not fresh:
        return False, None
    return True, sender_did


async def _check_freshness_and_nonce(payload: dict[str, Any], sender_did: str) -> bool:
    """Reject stale or replayed messages. Fail-closed on a missing/invalid ts/nonce.

    A message is accepted only if (1) it carries an integer ``ts`` within
    ±_REPLAY_MAX_AGE_SECONDS of now and (2) its (sender_did, nonce) has not been
    seen inside that window. Must be called only AFTER the Ed25519 signature has
    been verified, so the ts/nonce are authenticated and the cache cannot be
    poisoned by unauthenticated callers.
    """
    raw_ts = payload.get("ts")
    nonce = payload.get("nonce")
    if not isinstance(raw_ts, int) or not isinstance(nonce, str) or not nonce:
        log.warning("verify_signed_message_missing_freshness", sender_did=sender_did)
        return False

    now = time.time()
    if abs(now - raw_ts) > _REPLAY_MAX_AGE_SECONDS:
        log.warning(
            "verify_signed_message_stale",
            sender_did=sender_did,
            age_seconds=round(now - raw_ts, 1),
            max_age=_REPLAY_MAX_AGE_SECONDS,
        )
        return False

    # Shared (cross-replica) guard first: an atomic SET NX in the per-division Redis.
    redis_verdict = await _seen_nonce_redis(sender_did, nonce)
    if redis_verdict is True:
        return True                       # fresh, recorded in the shared store
    if redis_verdict is False:
        log.warning("verify_signed_message_replayed_nonce", sender_did=sender_did, store="redis")
        return False
    # redis_verdict is None -> Redis unavailable: degrade to the in-process guard below
    # (a single replica is still fully protected; only multi-replica loses cross-replica reach).
    key = (sender_did, nonce)
    async with _seen_lock:
        if key in _seen_nonces and _seen_nonces[key] > now:
            log.warning("verify_signed_message_replayed_nonce", sender_did=sender_did)
            return False
        # Lazy eviction of expired entries keeps the cache bounded under normal
        # load (a nonce older than the freshness window can't be replayed anyway).
        if len(_seen_nonces) >= _SEEN_NONCE_MAX:
            for k in [k for k, e in _seen_nonces.items() if e <= now]:
                _seen_nonces.pop(k, None)
        # If still at the cap after eviction, refuse to grow unbounded — a flood
        # of >50k distinct fresh nonces from the trusted peer inside 5 min is
        # itself anomalous. Fail-closed (memory-exhaustion defence, ASI-08).
        if len(_seen_nonces) >= _SEEN_NONCE_MAX:
            log.error("verify_signed_message_nonce_cache_full", sender_did=sender_did)
            return False
        # Remember this nonce only for as long as its ts could still be fresh.
        _seen_nonces[key] = now + _REPLAY_MAX_AGE_SECONDS
    return True


# ── Peer trust verification ───────────────────────────────────────────────────

async def verify_peer_identity(peer_did: str) -> tuple[bool, float]:
    """
    Verify a peer agent's DID against the AgentMesh IdentityRegistry.

    Returns (verified, trust_score) where trust_score is normalised to 0.0–1.0.
    Fails closed — an unknown / inactive peer or any error returns (False, 0.0).

    WHY REGISTRY MEMBERSHIP, NOT TrustBridge.verify_peer
    ----------------------------------------------------
    TrustBridge.verify_peer performs a *mutual* challenge/response handshake: it
    simulates the peer's side in-process by signing the challenge with the peer
    identity taken from the registry (handshake._get_peer_response → respond →
    peer_identity.sign()). In a real federation each cluster holds only the
    PEER's PUBLIC key (PEER_AGENT_PUBLIC_JWK), so that sign() raises
    "Private key not available for signing" and every peer is rejected — the
    library API cannot complete offline by design.

    The actual cross-network authentication in this architecture is the per-
    message Ed25519 signature: every outbound message is signed
    (sign_outbound_message) and every inbound message is cryptographically
    verified against the peer's public key (verify_signed_message), in BOTH
    directions. That is the real zero-trust control and it is enforced
    independently of this function (peer_client verifies the response signature;
    /a2a/query verifies the request signature).

    This function therefore answers the question it can answer offline: is the
    peer a known, active member of the trust registry? Registry membership is the
    out-of-band trust establishment — the operator deliberately copied the peer's
    DID + public JWK from its /identity endpoint into PEER_AGENT_PUBLIC_JWK, which
    makes the peer a trusted federation partner. The trust score is read from the
    registered identity if it carries one, otherwise it floors at the library's
    TIER_TRUSTED_THRESHOLD (a registered partner sits in the trusted tier).
    """
    try:
        registry = await _get_identity_registry()
        peer_identity = registry.get(peer_did)
    except Exception as exc:  # noqa: BLE001 — fail closed on any error
        log.warning("peer_identity_verification_failed", peer_did=peer_did, error=str(exc))
        return False, 0.0

    if peer_identity is None:
        log.warning("peer_identity_not_registered", peer_did=peer_did)
        return False, 0.0
    try:
        active = bool(peer_identity.is_active())
    except Exception:  # noqa: BLE001 — treat an unparseable status as inactive
        active = False
    if not active:
        log.warning(
            "peer_identity_inactive",
            peer_did=peer_did,
            status=getattr(peer_identity, "status", "unknown"),
        )
        return False, 0.0

    raw_score = getattr(peer_identity, "trust_score", None)
    if raw_score is None:
        raw_score = TIER_TRUSTED_THRESHOLD
    score = float(raw_score) / _TRUST_SCALE
    log.info("peer_identity_verified", peer_did=peer_did, verified=True, trust_score=score)
    return True, score


# ── Governed action execution ─────────────────────────────────────────────────

async def govern_action(action: str, context: dict[str, Any]) -> GovernanceResult:
    """
    Run an action through the AgentMesh governance engine.

    Returns a GovernanceResult; callers inspect ``.allowed`` and fail closed.
    """
    mesh = await get_mesh()
    return await asyncio.to_thread(mesh.execute_with_governance, action, context)


# ── Lifecycle ─────────────────────────────────────────────────────────────────

async def rotate_credentials() -> None:
    """
    Rotate this agent's Ed25519 credentials via the AgentMesh LifecycleManager.

    Intended to be called periodically (e.g. a Kubernetes CronJob). Best-effort:
    a rotation failure is logged, not raised, so a transient registry outage does
    not crash the scheduled job.
    """
    try:
        manager = LifecycleManager()
        await asyncio.to_thread(manager.rotate_credentials, _AGENT_ID)
        log.info("agentmesh_credentials_rotated", agent_id=_AGENT_ID)
    except AgentMeshError as exc:
        log.error("agentmesh_credential_rotation_failed", error=str(exc))
    except Exception as exc:  # noqa: BLE001
        log.error("agentmesh_credential_rotation_unexpected_error", error=str(exc))


async def report_trust_event(peer_did: str, event_type: str, details: dict[str, Any]) -> None:
    """
    Record a trust-relevant interaction with a peer in the AgentMesh
    TrustTracker. Failures (penalties) decay the peer's trust score.
    """
    # Negative event types are recorded as failed interactions (penalty).
    success = event_type not in {
        "iatp_error",
        "call_failure",
        "policy_violation",
        "timeout",
        "unexpected_payload",
        "anomalous_rate",
    }
    try:
        tracker = await _get_trust_tracker()
        await asyncio.to_thread(
            tracker.record_interaction,
            _AGENT_ID,
            peer_did,
            event_type,
            success,
        )
        log.info("trust_event_reported", peer_did=peer_did, event_type=event_type, success=success)
    except Exception as exc:  # noqa: BLE001 — telemetry must not break the caller
        log.warning("trust_event_report_failed", peer_did=peer_did, error=str(exc))
