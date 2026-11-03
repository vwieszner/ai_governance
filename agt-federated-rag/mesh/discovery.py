"""Client-side discover → negotiate → delegate helper (M3, FR-3.1/3.2/3.4).

This is the piece that turns the dead discovery service into a live delegation
input. When the agent must delegate (REMOTE flow, no local data), instead of
*blindly* forwarding to the configured ``peer_agent_url`` it:

  1. lazily registers SELF with the discovery broker (once per process) so other
     divisions can find us too;
  2. queries the broker for a peer that advertises the query's CAPABILITY;
  3. negotiates a lightweight "can you help with X?" confirmation with the
     candidate before committing to a full federated round-trip;
  4. resolves the chosen peer against this division's DATA-PATH trust anchor
     (``settings.peer_trust``) and returns a ``DelegationTarget`` describing it.

GRACEFUL DEGRADATION (NFR — don't regress existing federation): every failure
mode here — broker unreachable, broker returns nothing, negotiation declined,
discovered peer not in our trust map — falls back to the configured
``settings.peer_agent_url`` / ``peer_agent_did``. So a deployment with no
discovery broker still federates exactly as before; discovery only *improves*
target selection, it is never on the critical path for the demo's single peer.

ROUTING: this module decides WHETHER and TO WHOM to delegate and surfaces the
discovered peer for observability (FR-3.4). The node then hands the selected
DID to the signed transport (``mesh/peer_client.call_peer_agent(target_did=...)``),
which routes the bytes to THAT peer — resolving its URL and verification key
from the local ``peer_trust`` anchor, never from the broker entry. The data
path independently re-verifies the peer DID + re-authorizes, so a rogue broker
entry can never widen access (control-plane only).

Discovery broker URL + this agent's advertised capabilities are read from the
environment (DISCOVERY_URL / AGENT_CAPABILITIES) rather than config.Settings,
because the Settings schema is owned elsewhere; unset → discovery is simply
skipped and we fall back to the configured peer.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import structlog

from config import settings
from discovery.client import discover as _discover_peers
from discovery.client import register_self as _register_self

log = structlog.get_logger(__name__)

# Env-driven knobs (Settings schema is owned by another agent — read directly).
_DISCOVERY_URL_ENV = "DISCOVERY_URL"
_CAPABILITIES_ENV = "AGENT_CAPABILITIES"   # comma-separated capabilities this agent serves

# Lazy self-registration latch — register with the broker at most once per process,
# from the first delegation on our own code path (NOT in api/main.py lifespan, which
# this module does not own). Best-effort: a registration failure never blocks delegation.
_self_registered = False


def discovery_url() -> str | None:
    """The configured discovery broker URL, or None when discovery is disabled."""
    url = (os.environ.get(_DISCOVERY_URL_ENV) or "").strip()
    return url or None


def advertised_capabilities() -> list[str]:
    """Capabilities this agent advertises to the broker (AGENT_CAPABILITIES env, CSV) PLUS
    every LOCAL tool capability (from local_server_configs, e.g. "tool.pii"/"tool.compliance").

    So a peer can discover us by a TOOL capability over the /a2a/tool channel without an
    operator having to hand-list each tool in AGENT_CAPABILITIES — the in-process tool
    registry is the source of truth for what tools we can serve. Order-stable + de-duplicated
    (env-declared first, then any local tool capability not already present)."""
    raw = (os.environ.get(_CAPABILITIES_ENV) or "").strip()
    caps = [c.strip() for c in raw.split(",") if c.strip()]
    try:
        from tools.local_tools import local_server_configs
        for cfg in local_server_configs():
            cap = cfg.get("capability")
            if cap and cap not in caps:
                caps.append(cap)
    except Exception as exc:  # noqa: BLE001 — advertising local tools must never block registration
        log.debug("tool_capability_advertise_skipped", error=str(exc))
    return caps


# Lightweight keyword → capability map for deriving a query's capability when the
# caller doesn't supply one. Deliberately small + transparent (no model call): the
# broker match is case-insensitive and a miss just means "any capable peer", so this
# only needs to be good enough to prefer the right partner in a multi-peer mesh.
_CAPABILITY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "technical_architecture": ("kubernetes", "k8s", "infrastructure", "deployment",
                               "architecture", "cluster", "service", "api", "database"),
    "finance": ("revenue", "finance", "financial", "budget", "cost", "earnings", "q1",
                "q2", "q3", "q4", "profit"),
    "hr": ("salary", "salaries", "compensation", "headcount", "hr", "employee", "payroll",
           "hiring", "benefits", "earn", "wage", "pay", "engineer"),
}


def capability_for_query(query: str) -> str | None:
    """Best-effort capability hint from the query text (None → match any peer)."""
    q = (query or "").lower()
    for cap, kws in _CAPABILITY_KEYWORDS.items():
        if any(kw in q for kw in kws):
            return cap
    return None


@dataclass
class DelegationTarget:
    """The resolved peer to delegate to + how it was chosen (for observability)."""
    agent_url: str
    agent_did: str
    division_id: str
    capability: str | None
    source: str                       # "discovered" | "configured-fallback"
    negotiated: bool = False
    candidates: list[dict] = field(default_factory=list)   # control-plane peer views seen

    def is_configured_peer(self) -> bool:
        """True when this target resolves to the legacy configured peer (PEER_AGENT_URL).

        Informational: the transport now routes to ANY trust-anchored discovered DID
        (``call_peer_agent(target_did=...)``), so this no longer gates delegation."""
        configured = str(settings.peer_agent_url or "").rstrip("/")
        return bool(configured) and self.agent_url.rstrip("/") == configured


def _configured_target(capability: str | None, candidates: list[dict] | None = None,
                       negotiated: bool = False) -> DelegationTarget:
    """The graceful-degradation fallback: the statically-configured peer."""
    div = ""
    peer_did = settings.peer_agent_did or ""
    entry = settings.peer_trust.get(peer_did) if peer_did else None
    if entry:
        div = str(entry.get("division_id") or "")
    return DelegationTarget(
        agent_url=str(settings.peer_agent_url or "").rstrip("/"),
        agent_did=peer_did,
        division_id=div,
        capability=capability,
        source="configured-fallback",
        negotiated=negotiated,
        candidates=candidates or [],
    )


async def _ensure_registered(url: str) -> None:
    """Register self with the broker once per process (best-effort, never raises)."""
    global _self_registered
    if _self_registered:
        return
    try:
        await _register_self(url, advertised_capabilities())
        _self_registered = True
        log.info("discovery_self_registered_lazy", url=url)
    except Exception as exc:  # noqa: BLE001 — registration must never block delegation
        log.warning("discovery_self_registration_failed", url=url, error=str(exc))


def _trusted(peer: dict) -> bool:
    """A discovered peer is delegable only if its DID is in our DATA-PATH trust anchor.

    The broker is an OPEN, self-asserted registry; trust comes from ``settings.peer_trust``
    (operator-curated peer DIDs + public JWKs), NOT from being listed in the broker. This
    is the control-plane/data-plane split: discovery says who CLAIMS a capability, the
    trust map says whom we'll actually talk to."""
    did = str(peer.get("agent_did") or "")
    return bool(did) and did in settings.peer_trust


async def _negotiate(peer: dict, capability: str | None) -> bool:
    """Lightweight "can you help with <capability>?" confirmation with a candidate.

    Negotiation here is a capability ASSERTION check against the peer's published
    control-plane view (it already advertised its capabilities to the broker, DID-signed),
    so we confirm the match without a second network hop the broker round-trip already
    settled. A no-capability query trivially negotiates (we're asking "anything?")."""
    if not capability:
        return True
    advertised = [str(c).lower() for c in (peer.get("capabilities") or [])]
    ok = capability.lower() in advertised
    log.debug("discovery_negotiation", peer_did=peer.get("agent_did"),
              capability=capability, accepted=ok)
    return ok


async def resolve_delegation_target(query: str, capability: str | None = None) -> DelegationTarget:
    """Discover → negotiate → resolve the peer to delegate *query* to.

    Returns a DelegationTarget. NEVER raises: any discovery failure degrades to the
    configured peer so existing single-peer federation keeps working unchanged.
    """
    cap = capability or capability_for_query(query)
    url = discovery_url()
    if not url:
        # Discovery disabled (no broker configured) — use the configured peer.
        log.debug("discovery_disabled_fallback_configured", capability=cap)
        return _configured_target(cap)

    await _ensure_registered(url)

    try:
        peers = await _discover_peers(url, capability=cap)
    except Exception as exc:  # noqa: BLE001 — broker down → graceful fallback
        log.warning("discovery_lookup_failed_fallback", url=url, error=str(exc))
        return _configured_target(cap)

    if not peers:
        log.info("discovery_no_capable_peer_fallback", capability=cap)
        return _configured_target(cap, candidates=[])

    # Prefer the first capable, TRUSTED peer that also negotiates the capability.
    for peer in peers:
        if not _trusted(peer):
            log.info("discovery_skip_untrusted_peer", peer_did=peer.get("agent_did"))
            continue
        if not await _negotiate(peer, cap):
            continue
        # Defence-in-depth (A1c/A4): the broker is an OPEN, self-asserted registry — its
        # copy of agent_url/division_id is attacker-influenceable even for a trusted DID
        # (a rogue can register the trusted DID string with its own URL/division). For the
        # resolved TARGET we take agent_url + division_id from the operator-curated
        # peer_trust anchor keyed on the (now trust-verified) DID, NOT from the broker
        # entry. So a rogue can't steer the target's metadata: the broker only says WHICH
        # trusted DID claims the capability; the data-path anchor says WHERE it lives and
        # WHAT division it is. (The transport independently re-resolves the URL from the
        # anchor, but this also stops the broker-supplied division reaching the FR-3.4 marker.)
        did = str(peer.get("agent_did") or "")
        anchor = settings.peer_trust.get(did) or {}
        anchor_url = str(anchor.get("agent_url") or "").rstrip("/")
        if not anchor_url:
            # Trusted DID but no data-path URL in OUR anchor → unroutable; never fall back
            # to the broker's advertised URL. Try the next candidate / configured peer.
            log.info("discovery_skip_peer_without_anchor_url", peer_did=did)
            continue
        target = DelegationTarget(
            agent_url=anchor_url,
            agent_did=did,
            division_id=str(anchor.get("division_id") or ""),
            capability=cap,
            source="discovered",
            negotiated=True,
            candidates=peers,
        )
        log.info("discovery_delegation_target_selected", peer_did=target.agent_did,
                 division=target.division_id, capability=cap, agt_audit=True)
        return target

    # Found peers but none trusted/negotiable → fall back to the configured peer.
    log.info("discovery_no_trusted_negotiable_peer_fallback", capability=cap, count=len(peers))
    return _configured_target(cap, candidates=peers)


@dataclass
class ToolPeer:
    """A discovered peer that advertises (and negotiated) a TOOL capability.

    Carries exactly what mesh.peer_client.call_peer_tool needs to delegate: the peer's
    DATA-PATH agent_url + DID (both from the operator-curated peer_trust anchor, NOT the
    open broker), plus the division for audit/observability."""
    agent_url: str
    agent_did: str
    division_id: str
    capability: str


def _tool_peer_from_anchor(did: str, capability: str) -> ToolPeer | None:
    """Build a ToolPeer for ``did`` from the operator-curated DATA-PATH trust anchor, or None
    if ``did`` is not a trusted peer / has no anchor URL.

    SECURITY (single source of truth for WHERE we send): the peer's agent_url + division come
    ONLY from ``settings.peer_trust[did]`` — never from a broker entry or the peer_tool_map.
    A DID that is not in peer_trust resolves to None, so neither a rogue broker row nor a
    misconfigured peer_tool_map entry can ever fabricate a peer we'd talk to."""
    anchor = settings.peer_trust.get(did) or {}
    if not anchor:
        return None
    agent_url = str(anchor.get("agent_url") or "").rstrip("/")
    if not agent_url:
        return None
    return ToolPeer(
        agent_url=agent_url,
        agent_did=did,
        division_id=str(anchor.get("division_id") or ""),
        capability=capability,
    )


def _configured_tool_peer(capability: str) -> ToolPeer | None:
    """Broker-less CONFIGURED fallback: resolve ``capability`` via ``settings.peer_tool_map``
    (capability → peer_did) and the ``peer_trust`` anchor, so a template deployment can
    delegate tools with NO discovery-broker service.

    The map only names WHICH trusted peer serves the capability; _tool_peer_from_anchor takes
    the url/division from peer_trust (never fabricated). An unmapped capability, or a mapped
    DID that is NOT a trust anchor, yields None (graceful degradation — fail-closed)."""
    did = str(settings.peer_tool_map_dict.get(capability) or "").strip()
    if not did:
        return None
    peer = _tool_peer_from_anchor(did, capability)
    if peer is None:
        # The map points at a DID we don't trust (or that has no anchor URL) — refuse to
        # fabricate a peer. This is the security boundary: peer_tool_map can only SELECT
        # among already-trusted peers, it can never add one.
        log.info("tool_routing_configured_peer_not_trusted", peer_did=did, capability=capability)
        return None
    log.info("tool_routing_configured_peer_selected", peer_did=peer.agent_did,
             division=peer.division_id, capability=capability, agt_audit=True)
    return peer


async def find_peer_for_capability(capability: str) -> ToolPeer | None:
    """Discover a TRUSTED peer that advertises a given TOOL capability (e.g. "tool.pii").

    Two routing sources, broker FIRST (dynamic) then a static CONFIGURED fallback:

      1. DISCOVERY BROKER (primary, dynamic): ask the broker for peers advertising
         ``capability``, keep only those whose DID is in this division's DATA-PATH trust anchor
         (settings.peer_trust), confirm via the lightweight negotiate ("can you help with
         <capability>?"), and resolve the WINNER's agent_url + division from the trust anchor
         (never the broker — a rogue broker entry can't steer where we actually send).

      2. CONFIGURED peer_tool_map (fallback, static): when no broker is configured, the broker
         is unreachable, or it returns no trusted+negotiable peer, look the capability up in
         settings.peer_tool_map (capability → peer_did) and build the ToolPeer from the trust
         anchor for that DID. This lets a template Kubernetes deployment do cross-agent tool
         delegation with NO extra broker service. SECURITY: the map only says WHICH trusted
         peer serves the capability; the agent_url/DID/division ALWAYS come from peer_trust, so
         a peer_tool_map DID that is not a trust anchor resolves to None (never fabricated).
         This reuses the existing agent→agent NetworkPolicy (same trusted peer URL).

    GRACEFUL DEGRADATION: no broker AND no configured route, broker down with no configured
    route, broker returns nothing trusted and no configured route → None, so the caller
    (solve_with_tools) degrades cleanly ("no agent can serve capability X") instead of crashing.
    NEVER raises.
    """
    if not capability or not capability.strip():
        return None

    url = discovery_url()
    if not url:
        # No broker — try the broker-less CONFIGURED route before giving up.
        log.debug("tool_discovery_disabled_try_configured", capability=capability)
        return _configured_tool_peer(capability)

    await _ensure_registered(url)

    try:
        peers = await _discover_peers(url, capability=capability)
    except Exception as exc:  # noqa: BLE001 — broker down → fall back to the configured route
        log.warning("tool_discovery_lookup_failed", url=url, capability=capability, error=str(exc))
        return _configured_tool_peer(capability)

    for peer in peers or []:
        if not _trusted(peer):
            log.info("tool_discovery_skip_untrusted_peer", peer_did=peer.get("agent_did"))
            continue
        if not await _negotiate(peer, capability):
            continue
        # Take agent_url + division from the operator-curated trust anchor keyed on the
        # (now trust-verified) DID — the broker only says WHICH trusted DID claims the
        # capability, the anchor says WHERE it lives (defence-in-depth A1c/A4, as above).
        did = str(peer.get("agent_did") or "")
        target = _tool_peer_from_anchor(did, capability)
        if target is None:
            log.info("tool_discovery_peer_has_no_anchor_url", peer_did=did, capability=capability)
            continue
        log.info("tool_discovery_peer_selected", peer_did=did, division=target.division_id,
                 capability=capability, agt_audit=True)
        return target

    # Broker yielded no trusted+negotiable peer — try the broker-less CONFIGURED route.
    log.info("tool_discovery_no_capable_peer_try_configured", capability=capability)
    return _configured_tool_peer(capability)
