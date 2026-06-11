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
    """Thread-safe in-memory registry keyed by agent DID. Stale entries expire."""

    def __init__(self, ttl_seconds: float = 3600.0) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._entries: dict[str, DiscoveryEntry] = {}

    def register(self, entry: DiscoveryEntry) -> None:
        with self._lock:
            self._entries[entry.agent_did] = entry

    def _live(self) -> list[DiscoveryEntry]:
        now = time.time()
        with self._lock:
            fresh = [e for e in self._entries.values() if now - e.registered_at <= self._ttl]
            # opportunistic prune
            self._entries = {e.agent_did: e for e in fresh}
            return fresh

    def all(self) -> list[DiscoveryEntry]:
        return self._live()

    def find(self, capability: str | None = None, exclude_did: str | None = None) -> list[DiscoveryEntry]:
        """Return live entries matching *capability* (case-insensitive), excluding the
        caller's own DID. No capability → all peers."""
        cap = (capability or "").strip().lower()
        out = []
        for e in self._live():
            if exclude_did and e.agent_did == exclude_did:
                continue
            if cap and cap not in [c.lower() for c in e.capabilities]:
                continue
            out.append(e)
        return out
