"""Federation wiring (IMPLEMENTATION_PLAN.md M2/M3).

Onboarding (scripts/onboard_division.py) stands each division up in PHYSICAL isolation
— it deliberately knows nothing about its peers. This script performs the SEPARATE,
explicit step of federating already-onboarded divisions so they can call each other's
DID-signed ``/a2a/query`` with verifiable cross-division user identity.

For each division D (manifest under infra/divisions/*.yml that is onboarded):

  TRANSPORT — register D's ``trusted_peers``:
    * PEER_AGENT_URL / PEER_AGENT_DID / PEER_AGENT_PUBLIC_JWK are set to D's FIRST
      trusted peer (the agent config is single-outbound-peer today; multi-peer
      discovery is M3). The peer DID + public JWK come from the peer's generated
      did.json — this is the out-of-band trust the AgentMesh IdentityRegistry needs.
    * TRUSTED_ISSUERS is the union of ALL trusted peers' Keycloak issuers, so D
      accepts a verifiable user assertion minted by any of them (and re-authorizes it
      against D's OWN OpenFGA).

  CROSS-GRANTS — apply D's manifest ``cross_grants`` (FR-3.7): pre-authorize a named
    external user (by home division + email) on one of D's docs. The tuple is keyed by
    the SAME namespaced principal the agent derives at runtime
    (``<email>|<sha256(home-issuer)[:16]>`` — see auth.token_validator.principal), so a
    verifiable cross-division request from that user is answered immediately, no approval.

Idempotent: .env keys are upserted in place; OpenFGA writes are idempotent. After
running, restart the affected agents (scripts/clusters.ps1 restart <ids>) to load the
new peer config.

Usage:
    python scripts/federate_divisions.py                 # federate all onboarded divisions
    python scripts/federate_divisions.py --only alpha beta
    python scripts/federate_divisions.py --dry-run       # show the plan, write nothing
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.onboard_division import (  # noqa: E402
    REALM,
    Manifest,
    _seed_principal,
    derive_ports,
    load_manifest,
)

DIV_DIR = ROOT / "infra" / "divisions"
GEN_DIR = ROOT / "infra" / "generated"
AGENT_DIR = ROOT / "agt-federated-rag"


def log(msg: str) -> None:
    print(f"[federate] {msg}", flush=True)


class DivisionFacts:
    """Everything one division needs to know to federate with a peer."""

    def __init__(self, manifest: Manifest):
        self.m = manifest
        self.id = manifest.division_id
        self.ports = derive_ports(manifest.port_base)
        self.issuer = f"http://localhost:{self.ports['keycloak']}/realms/{REALM}"
        self.agent_url = f"http://localhost:{self.ports['agent']}"
        self.gen = GEN_DIR / self.id
        self.env_path = AGENT_DIR / f".env.{self.id}"

    @property
    def onboarded(self) -> bool:
        return self.env_path.exists() and (self.gen / "did.json").exists()

    def did_jwk(self) -> tuple[str, str]:
        d = json.loads((self.gen / "did.json").read_text())
        # PEER_AGENT_PUBLIC_JWK is a compact JSON string of the peer's public JWK.
        return str(d["did"]), json.dumps(d["jwk"], separators=(",", ":"))

    def store(self) -> tuple[str, str]:
        store_id = json.loads((self.gen / "state.json").read_text())["store_id"]
        token = json.loads((self.gen / "secrets.json").read_text())["openfga_api_token"]
        return store_id, token


def _upsert_env(env_path: Path, updates: dict[str, str], dry_run: bool) -> list[str]:
    """Replace existing KEY=… lines (or append) so federation is re-runnable. Returns
    the human-readable change list."""
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    remaining = dict(updates)
    changes: list[str] = []
    out: list[str] = []
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key and key in remaining:
            newval = remaining.pop(key)
            if line.strip() != f"{key}={newval}":
                changes.append(f"  ~ {key}")
            out.append(f"{key}={newval}")
        else:
            out.append(line)
    for key, val in remaining.items():
        changes.append(f"  + {key}")
        out.append(f"{key}={val}")
    if changes and not dry_run:
        env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return changes


async def _apply_cross_grants(facts: DivisionFacts, by_id: dict[str, DivisionFacts],
                              dry_run: bool) -> None:
    """Write this division's manifest cross_grants to its OWN OpenFGA, keyed by the
    namespaced principal of the external (home-division) user."""
    grants = facts.m.cross_grants
    if not grants:
        return
    import httpx

    store_id, token = facts.store()
    ofga = f"http://localhost:{facts.ports['openfga']}"
    qd = f"http://localhost:{facts.ports['qdrant']}"
    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient(timeout=30) as c:
        # chunk ids grouped by doc title from THIS division's Qdrant
        r = await c.post(f"{qd}/collections/knowledge_base/points/scroll",
                         json={"limit": 512, "with_payload": True, "with_vector": False})
        r.raise_for_status()
        by_title: dict[str, list[str]] = {}
        for pt in r.json()["result"]["points"]:
            pl = pt["payload"]
            title = pl.get("title") or (pl.get("metadata") or {}).get("title", "")
            cid = pl.get("chunk_id", "")
            if title and cid:
                by_title.setdefault(title, []).append(cid)

        for g in grants:
            email = str(g.get("user_email", "")).strip()
            home = str(g.get("home_division", "")).strip()
            relation = str(g.get("relation", "viewer")).strip()
            doc = str(g.get("doc", "")).strip()
            if not (email and home and doc):
                log(f"  SKIP malformed cross_grant {g!r}")
                continue
            if home not in by_id:
                log(f"  SKIP cross_grant: home division '{home}' not found/onboarded")
                continue
            home_issuer = by_id[home].issuer
            principal = _seed_principal(email, home_issuer)
            chunks = by_title.get(doc, [])
            if not chunks:
                log(f"  WARN cross_grant doc '{doc}' has no chunks in {facts.id}'s Qdrant")
            log(f"  grant {facts.id}: user:{principal} {relation} '{doc}' ({len(chunks)} chunks)")
            if dry_run:
                continue
            for cid in chunks:
                await c.post(f"{ofga}/stores/{store_id}/write",
                             json={"writes": {"tuple_keys": [
                                 {"user": f"user:{principal}", "relation": relation,
                                  "object": f"chunk:{cid}"}]}},
                             headers=headers)


def federate(only: list[str] | None, dry_run: bool) -> int:
    manifests = [load_manifest(p) for p in sorted(DIV_DIR.glob("*.yml"))]
    by_id = {m.division_id: DivisionFacts(m) for m in manifests}
    targets = [f for f in by_id.values()
               if (not only or f.id in only)]
    if not targets:
        log("no matching divisions")
        return 1

    rc = 0
    for f in targets:
        if not f.onboarded:
            log(f"{f.id}: NOT onboarded (run onboard_division.py infra/divisions/{f.id}.yml) -- skipped")
            rc = 1
            continue
        peers = [p for p in f.m.trusted_peers if p in by_id and by_id[p].onboarded]
        missing = [p for p in f.m.trusted_peers if p not in by_id or not by_id[p].onboarded]
        for mp in missing:
            log(f"{f.id}: trusted peer '{mp}' not onboarded -- not wired")
        log(f"=== {f.id} -> peers {peers or '(none)'} ===")
        if peers:
            primary = by_id[peers[0]]
            did, jwk = primary.did_jwk()
            updates = {
                "PEER_AGENT_URL": primary.agent_url,
                "PEER_AGENT_DID": did,
                "PEER_AGENT_PUBLIC_JWK": jwk,
                "TRUSTED_ISSUERS": ",".join(by_id[p].issuer for p in peers),
            }
            for ch in _upsert_env(f.env_path, updates, dry_run):
                log(ch)
            if len(peers) > 1:
                log(f"  NOTE outbound peer = '{peers[0]}' only (single-peer config; M3 = multi-peer)")
        # cross-grants land in THIS division's store
        asyncio.run(_apply_cross_grants(f, by_id, dry_run))

    log("DRY-RUN (nothing written)" if dry_run else
        "done -- restart affected agents: scripts/clusters.ps1 restart " + " ".join(t.id for t in targets))
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="Federate onboarded divisions (M2/M3).")
    ap.add_argument("--only", nargs="*", help="limit to these division ids")
    ap.add_argument("--dry-run", action="store_true", help="show the plan, write nothing")
    args = ap.parse_args()
    return federate(args.only, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
