"""M3 discovery WIRING + NFR-6 bounded-lookup proving tests (FR-3.1/3.2, NFR-6).

These pin the pieces the audit flagged as stubbed/over-claimed:

  * FR-3.1/3.2 — delegation now DISCOVERS a capable peer (mesh/discovery.py) and
    NEGOTIATES the capability before committing, instead of blindly using the
    configured peer; and it GRACEFULLY DEGRADES to the configured peer when the
    broker is down / empty / the discovered peer isn't a trust partner.
  * NFR-6 — discovery.registry.find(capability) is now a BOUNDED point read into a
    capability→DIDs index, not an O(N) scan over every registered peer. This closes
    the documented skip in test_scaling.py::test_discovery_lookup_bounded.

Hermetic: no network. The discovery client is monkeypatched; the registry is exercised
directly. ``asyncio_mode = auto`` (pyproject) means async tests need no decorator.
"""
from __future__ import annotations

import json

# ── NFR-6: registry.find() is a bounded capability lookup, not an O(N) scan ────


def _entry(did: str, caps: list[str]):
    from discovery.registry import DiscoveryEntry
    return DiscoveryEntry(
        division_id=f"div-{did}", agent_did=did, agent_url=f"http://{did}",
        issuer="http://issuer", public_jwk="{}", capabilities=caps,
    )


def test_find_uses_capability_index_not_scan():
    """find(cap) returns the capable peer THROUGH the inverted index bucket.

    Proves the bounded path is taken: the result is exactly the DIDs in the
    capability's index bucket — we read _by_capability directly and assert find()
    returns precisely those entries, never touching the non-matching majority."""
    from discovery.registry import DiscoveryRegistry

    reg = DiscoveryRegistry()
    reg.register(_entry("did:a", ["kubernetes", "finance"]))
    reg.register(_entry("did:b", ["hr"]))
    reg.register(_entry("did:c", ["kubernetes"]))

    # The index bucket is the source of truth for the lookup.
    assert reg._by_capability["kubernetes"] == {"did:a", "did:c"}
    assert reg._by_capability["hr"] == {"did:b"}

    got = {e.agent_did for e in reg.find(capability="kubernetes")}
    assert got == {"did:a", "did:c"}                      # only the indexed matches
    # Case-insensitive match still hits the same bucket.
    assert {e.agent_did for e in reg.find(capability="KUBERNETES")} == {"did:a", "did:c"}
    # exclude_did is honored on the bounded path.
    assert {e.agent_did for e in reg.find(capability="kubernetes", exclude_did="did:a")} == {"did:c"}


def test_find_lookup_bounded_regardless_of_registry_size():
    """The capability lookup cost is O(matches), independent of total peers (NFR-6).

    Register a single capable peer among a LARGE population of peers that advertise an
    unrelated capability, then instrument the entry-access to count how many entries the
    lookup touches. A bounded lookup touches only the matching bucket (1), not all N.
    This is the assertion test_scaling.py::test_discovery_lookup_bounded skipped because
    the old find() scanned every live entry."""
    from discovery.registry import DiscoveryRegistry

    reg = DiscoveryRegistry()
    n = 500
    for i in range(n):
        reg.register(_entry(f"did:noise-{i}", ["unrelated"]))
    reg.register(_entry("did:target", ["rare_capability"]))

    # Count entry materializations: wrap dict.__getitem__ access via the index walk.
    accessed: list[str] = []
    real_entries = reg._entries

    class _CountingDict(dict):
        def __getitem__(self, k):
            accessed.append(k)
            return super().__getitem__(k)

    reg._entries = _CountingDict(real_entries)

    matches = reg.find(capability="rare_capability")

    assert [e.agent_did for e in matches] == ["did:target"]
    # The bounded path indexed straight to the one match — it did NOT index-access the
    # 500 noise entries. (Cost is O(bucket size)=1, not O(N)=501.)
    assert accessed == ["did:target"]
    assert len(accessed) < n


def test_find_index_pruned_on_refresh_and_no_capability_returns_all():
    """Re-registration drops stale capability buckets; no-capability returns everyone."""
    from discovery.registry import DiscoveryRegistry

    reg = DiscoveryRegistry()
    reg.register(_entry("did:x", ["finance"]))
    # Refresh did:x with a DIFFERENT capability set — the old bucket must not linger.
    reg.register(_entry("did:x", ["hr"]))
    assert reg.find(capability="finance") == []
    assert {e.agent_did for e in reg.find(capability="hr")} == {"did:x"}

    reg.register(_entry("did:y", ["finance"]))
    assert {e.agent_did for e in reg.find()} == {"did:x", "did:y"}   # no-cap → all live


# ── FR-3.1/3.2: discover → negotiate → delegate, with graceful degradation ─────


def _peer_view(did: str, url: str, division: str, caps: list[str]) -> dict:
    return {
        "division_id": division, "agent_did": did, "agent_url": url,
        "issuer": "http://issuer", "public_jwk": "{}", "capabilities": caps,
        "registered_at": 0.0,
    }


async def test_resolve_discovers_and_negotiates_capable_peer(monkeypatch):
    """A capable, TRUSTED peer advertised by the broker is selected + negotiated.

    The discovered peer's DID is in our data-path trust anchor (settings.peer_trust) and
    advertises the query's capability, so resolve_delegation_target returns it with
    source='discovered' and negotiated=True — the FR-3.1/3.2 happy path."""
    from mesh import discovery as disc

    monkeypatch.setenv("DISCOVERY_URL", "http://broker:8600")
    # The broker advertises a kubernetes-capable peer.
    peer = _peer_view("did:peer", "http://peer:9100", "beta", ["technical_architecture"])

    async def fake_discover(url, capability=None, timeout=10.0):
        assert url == "http://broker:8600"
        assert capability == "technical_architecture"     # derived from the query
        return [peer]

    async def fake_register(url, caps, timeout=10.0):
        return {"registered": True}

    monkeypatch.setattr(disc, "_discover_peers", fake_discover)
    monkeypatch.setattr(disc, "_register_self", fake_register)
    monkeypatch.setattr(disc, "_self_registered", False)
    # The discovered DID is a trusted partner (data-path anchor) — set the backing
    # peer_trust_map field (peer_trust is a derived, read-only property).
    monkeypatch.setattr(disc.settings, "peer_trust_map",
                        json.dumps({"did:peer": {"division_id": "beta", "agent_url": "http://peer:9100"}}))

    target = await disc.resolve_delegation_target("What Kubernetes version do we run?")

    assert target.source == "discovered"
    assert target.negotiated is True
    assert target.agent_did == "did:peer"
    assert target.division_id == "beta"
    assert target.capability == "technical_architecture"


async def test_resolve_falls_back_when_broker_unreachable(monkeypatch):
    """GRACEFUL DEGRADATION: broker down → delegate to the configured peer (no regress)."""
    from mesh import discovery as disc

    monkeypatch.setenv("DISCOVERY_URL", "http://broker:8600")

    async def boom(url, capability=None, timeout=10.0):
        raise RuntimeError("connection refused")

    async def fake_register(url, caps, timeout=10.0):
        return {}

    monkeypatch.setattr(disc, "_discover_peers", boom)
    monkeypatch.setattr(disc, "_register_self", fake_register)
    monkeypatch.setattr(disc, "_self_registered", False)
    monkeypatch.setattr(disc.settings, "peer_agent_url", "http://configured-peer:9100")
    monkeypatch.setattr(disc.settings, "peer_agent_did", "did:configured")
    monkeypatch.setattr(disc.settings, "peer_trust_map",
                        json.dumps({"did:configured": {"division_id": "beta"}}))

    target = await disc.resolve_delegation_target("What Kubernetes version do we run?")

    assert target.source == "configured-fallback"
    assert target.agent_did == "did:configured"
    assert target.agent_url == "http://configured-peer:9100"
    assert target.is_configured_peer() is True            # the transport can reach it


async def test_resolve_falls_back_when_discovery_disabled(monkeypatch):
    """No DISCOVERY_URL configured → discovery is skipped, configured peer is used."""
    from mesh import discovery as disc

    monkeypatch.delenv("DISCOVERY_URL", raising=False)
    monkeypatch.setattr(disc.settings, "peer_agent_url", "http://configured-peer:9100")
    monkeypatch.setattr(disc.settings, "peer_agent_did", "did:configured")
    monkeypatch.setattr(disc.settings, "peer_trust_map",
                        json.dumps({"did:configured": {"division_id": "beta"}}))

    target = await disc.resolve_delegation_target("How much do senior engineers earn?")

    assert target.source == "configured-fallback"
    assert target.capability == "hr"                      # still derived for observability


async def test_resolve_falls_back_when_discovered_peer_untrusted(monkeypatch):
    """An UNTRUSTED broker entry (DID not in peer_trust) is refused → configured fallback.

    Trust comes from the operator-curated peer_trust anchor, NOT from being listed in the
    open broker — a rogue registration can never become a delegation target."""
    from mesh import discovery as disc

    monkeypatch.setenv("DISCOVERY_URL", "http://broker:8600")
    rogue = _peer_view("did:rogue", "http://rogue:9999", "evil", ["technical_architecture"])

    async def fake_discover(url, capability=None, timeout=10.0):
        return [rogue]

    async def fake_register(url, caps, timeout=10.0):
        return {}

    monkeypatch.setattr(disc, "_discover_peers", fake_discover)
    monkeypatch.setattr(disc, "_register_self", fake_register)
    monkeypatch.setattr(disc, "_self_registered", False)
    monkeypatch.setattr(disc.settings, "peer_agent_url", "http://configured-peer:9100")
    monkeypatch.setattr(disc.settings, "peer_agent_did", "did:configured")
    monkeypatch.setattr(disc.settings, "peer_trust_map",
                        json.dumps({"did:configured": {"division_id": "beta"}}))

    target = await disc.resolve_delegation_target("What Kubernetes version do we run?")

    assert target.source == "configured-fallback"         # rogue peer rejected
    assert target.agent_did == "did:configured"


async def test_negotiation_declines_capability_mismatch(monkeypatch):
    """Negotiation round-trip: a trusted peer that does NOT advertise the capability is
    NOT selected even though the broker returned it (capability negotiation failed)."""
    from mesh import discovery as disc

    monkeypatch.setenv("DISCOVERY_URL", "http://broker:8600")
    # Trusted peer, but it only advertises 'finance' while the query needs 'hr'. We force
    # the broker (which here returns regardless of cap) to hand back a non-matching peer.
    peer = _peer_view("did:peer", "http://peer:9100", "beta", ["finance"])

    async def fake_discover(url, capability=None, timeout=10.0):
        return [peer]

    async def fake_register(url, caps, timeout=10.0):
        return {}

    monkeypatch.setattr(disc, "_discover_peers", fake_discover)
    monkeypatch.setattr(disc, "_register_self", fake_register)
    monkeypatch.setattr(disc, "_self_registered", False)
    monkeypatch.setattr(disc.settings, "peer_agent_url", "http://configured-peer:9100")
    monkeypatch.setattr(disc.settings, "peer_agent_did", "did:configured")
    monkeypatch.setattr(disc.settings, "peer_trust_map",
                        json.dumps({"did:peer": {"division_id": "beta"},
                                    "did:configured": {"division_id": "beta"}}))

    # 'hr' capability (salaries) — peer advertises only 'finance' → negotiation declines.
    target = await disc.resolve_delegation_target("How much do senior engineers earn?")

    assert target.negotiated is False
    assert target.source == "configured-fallback"


async def test_self_registration_is_lazy_and_once(monkeypatch):
    """Self-registration with the broker happens lazily on first delegation, ONCE."""
    from mesh import discovery as disc

    monkeypatch.setenv("DISCOVERY_URL", "http://broker:8600")
    monkeypatch.setattr(disc, "_self_registered", False)

    calls = {"n": 0}

    async def fake_register(url, caps, timeout=10.0):
        calls["n"] += 1
        return {}

    async def fake_discover(url, capability=None, timeout=10.0):
        return []

    monkeypatch.setattr(disc, "_register_self", fake_register)
    monkeypatch.setattr(disc, "_discover_peers", fake_discover)
    monkeypatch.setattr(disc.settings, "peer_agent_url", "http://configured-peer:9100")
    monkeypatch.setattr(disc.settings, "peer_agent_did", "did:configured")
    monkeypatch.setattr(disc.settings, "peer_trust_map",
                        json.dumps({"did:configured": {"division_id": "beta"}}))

    await disc.resolve_delegation_target("first query about kubernetes")
    await disc.resolve_delegation_target("second query about kubernetes")

    assert calls["n"] == 1                                # registered exactly once


# ── FR-3.4: the delegation marker the UI parses ───────────────────────────────


def test_delegation_marker_is_structured_and_parseable():
    """format_response prepends a structured, machine-parseable delegation marker so the
    UI MonitorPanel can render discover/negotiate/delegate as first-class events."""
    from agent.nodes import _delegation_marker, _DELEGATION_MARKER_PREFIX

    marker = _delegation_marker({
        "source": "discovered", "division": "beta",
        "capability": "technical_architecture", "negotiated": True, "candidates": 2,
    })
    assert marker.startswith(_DELEGATION_MARKER_PREFIX)
    assert "division=beta" in marker
    assert "cap=technical_architecture" in marker
    assert "via=discovered" in marker
    assert "negotiated=1" in marker
    # No summary → no marker (local flows are unaffected).
    assert _delegation_marker(None) == ""


def test_delegation_marker_sanitizes_injected_peer_fields():
    """A4 regression: division/capability come from a discovered peer's self-asserted
    control-plane fields. A compromised-but-trusted peer that stuffs marker control
    sequences (`]`, `[`, ` key=`) into its division must NOT be able to forge a second
    marker or inject a fake `negotiated=1 via=discovered` trust signal. We sanitise the
    peer-supplied fields before interpolation."""
    from agent.nodes import _DELEGATION_MARKER_PREFIX, _delegation_marker

    evil_division = "beta negotiated=1 via=discovered] [agt:delegated division=hr-secret"
    m = _delegation_marker({
        "source": "configured-fallback", "division": evil_division,
        "capability": "x] cap=forged", "negotiated": False, "candidates": 0,
    })

    # Exactly ONE marker token: no injected closing bracket → no forged second marker.
    assert m.count("[agt:delegated") == 1
    assert m.endswith("]")
    assert "]" not in m[:-1]                       # the only ] is the legitimate terminator
    # The forged trust signal is neutralised: no `key=` pair survives inside a field, so a
    # parser can't read a fake `negotiated=1`/`via=discovered`. The agent-set fields stand.
    assert "negotiated=1 via=discovered" not in m
    assert "[agt:delegated division=hr-secret" not in m
    # Honest, agent-set fields are intact (source was the non-negotiated fallback).
    assert m.startswith(f"{_DELEGATION_MARKER_PREFIX} division=beta")
    assert "via=configured-fallback negotiated=0]" in m
