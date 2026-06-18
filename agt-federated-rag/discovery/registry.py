"""In-memory discovery registry + DID-signed registration verification (M3, FR-3.1/3.2).

Registration is SELF-ASSERTED but key-possession-proven: the registrant signs its entry
with its DID's Ed25519 key and embeds the matching public JWK; the registry verifies the
signature against that embedded JWK and that the JWK derives the claimed DID. This proves
the registrant controls the private key for the DID it publishes — without the registry
needing pre-shared trust. The DATA path independently re-verifies peer DIDs + re-authorizes,
so a rogue registration can never grant data access (D-4: control-plane only).
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from mesh.agent_identity import AgentIdentity, _canonical_bytes  # type: ignore[attr-defined]


@dataclass
class DiscoveryEntry:
    division_id: str
    agent_did: str
    agent_url: str
    issuer: str                       # the division's Keycloak issuer (for signer-bound identity)
    public_jwk: str                   # the agent's DID public JWK (JSON string)
    capabilities: list[str] = field(default_factory=list)
    registered_at: float = field(default_factory=time.time)

    def public_view(self) -> dict[str, Any]:
        """Control-plane metadata only — NEVER any division data."""
        return {
            "division_id": self.division_id,
            "agent_did": self.agent_did,
            "agent_url": self.agent_url,
            "issuer": self.issuer,
            "public_jwk": self.public_jwk,
            "capabilities": list(self.capabilities),
            "registered_at": self.registered_at,
        }


class RegistrationError(Exception):
    """Raised when a registration fails verification (caller maps to HTTP 400/401)."""


def verify_registration(payload: dict[str, Any]) -> str:
    """Verify a DID-signed registration. Returns the verified signer DID, or raises.

    Checks: (1) an _agentmesh envelope + embedded public_jwk are present; (2) the JWK
    derives the DID claimed as the signer; (3) the Ed25519 signature verifies over the
    canonical bytes (so the body — incl. agent_url/capabilities/issuer — is authentic).
    """
    block = payload.get("_agentmesh")
    if not isinstance(block, dict):
        raise RegistrationError("missing _agentmesh signature envelope")
    sender_did = block.get("sender_did")
    signature = block.get("signature")
    pub_jwk = payload.get("public_jwk")
    if not (sender_did and signature and pub_jwk):
        raise RegistrationError("registration missing sender_did / signature / public_jwk")
    try:
        identity = AgentIdentity.from_jwk(json.loads(pub_jwk) if isinstance(pub_jwk, str) else pub_jwk)
    except Exception as exc:  # noqa: BLE001
        raise RegistrationError(f"invalid public_jwk: {exc}") from exc
    if str(identity.did) != sender_did:
        raise RegistrationError("public_jwk does not derive the claimed sender_did (key/DID mismatch)")
    try:
        ok = identity.verify_signature(_canonical_bytes(payload), signature)
    except Exception as exc:  # noqa: BLE001
        raise RegistrationError(f"signature verification error: {exc}") from exc
    if not ok:
        raise RegistrationError("registration signature invalid")
    return sender_did


class DiscoveryRegistry:
    """Thread-safe in-memory registry keyed by agent DID. Stale entries expire.

    NFR-6 (bounded lookup): a capability→DIDs inverted index (``_by_capability``)
    backs ``find(capability)`` so a capability lookup is a single dict point read +
    a walk over only the DIDs that advertise THAT capability — its cost is O(matches),
    independent of the total number of registered peers. The old implementation
    re-scanned every live entry (and re-lowercased every capability) on each find,
    which is the O(N) behavior NFR-6 flags. The index is maintained on register
    (and on TTL expiry), and entry capabilities are normalized to lower-case at
    registration so the lookup needs no per-call lowercasing.
    """

    def __init__(self, ttl_seconds: float = 3600.0) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._entries: dict[str, DiscoveryEntry] = {}
        # Inverted index: lower-cased capability → set of agent DIDs advertising it.
        # The NFR-6 bounded-lookup structure — find(cap) reads exactly this one bucket.
        self._by_capability: dict[str, set[str]] = {}

    def _index_locked(self, entry: DiscoveryEntry) -> None:
        """Add an entry to the capability index. Caller holds the lock."""
        for cap in {c.lower() for c in entry.capabilities}:
            self._by_capability.setdefault(cap, set()).add(entry.agent_did)

    def _deindex_locked(self, entry: DiscoveryEntry) -> None:
        """Remove an entry's DID from every capability bucket. Caller holds the lock."""
        for cap in {c.lower() for c in entry.capabilities}:
            bucket = self._by_capability.get(cap)
            if bucket is not None:
                bucket.discard(entry.agent_did)
                if not bucket:
                    del self._by_capability[cap]

    def register(self, entry: DiscoveryEntry) -> None:
        with self._lock:
            # Re-registration (refresh) must not leave the DID double-indexed under
            # capabilities it no longer advertises — drop the old index first.
            prior = self._entries.get(entry.agent_did)
            if prior is not None:
                self._deindex_locked(prior)
            self._entries[entry.agent_did] = entry
            self._index_locked(entry)

    def _expire_locked(self) -> None:
        """Prune stale entries from BOTH the primary map and the capability index."""
        now = time.time()
        stale = [e for e in self._entries.values() if now - e.registered_at > self._ttl]
        for e in stale:
            self._deindex_locked(e)
            del self._entries[e.agent_did]

    def _live(self) -> list[DiscoveryEntry]:
        with self._lock:
            self._expire_locked()
            return list(self._entries.values())

    def all(self) -> list[DiscoveryEntry]:
        return self._live()

    def find(self, capability: str | None = None, exclude_did: str | None = None) -> list[DiscoveryEntry]:
        """Return live entries matching *capability* (case-insensitive), excluding the
        caller's own DID. No capability → all peers.

        NFR-6: a capability lookup walks ONLY the DIDs in that capability's index
        bucket (O(matches)), not every registered peer. The no-capability call is
        inherently "return everything" so it is O(live) by definition."""
        with self._lock:
            self._expire_locked()
            cap = (capability or "").strip().lower()
            if not cap:
                return [e for e in self._entries.values() if e.agent_did != exclude_did]
            # Bounded point read: only DIDs that advertise this capability.
            dids = self._by_capability.get(cap, set())
            return [
                self._entries[did]
                for did in dids
                if did != exclude_did and did in self._entries
            ]
