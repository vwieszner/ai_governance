"""Issue the federation mTLS certs + CRL (Phase-1 item 7; revocation NFR-3).

Generates ONE shared federation CA + a per-division cert/key + the CA's CRL, written under
infra/generated/_certs/ (gitignored — they're key material). Each issued cert carries a
CRLDistributionPoints extension pointing at where the CRL is published, AND (when
TLS_OCSP_URL is set, default http://ocsp.federation.local) an Authority Information Access
(AIA) OCSP-responder URL so a relying party can do an online revocation check / OCSP stapling
once a responder is deployed (NFR-3 readiness — enforcement still needs the responder +
front-end stapling). Then point each division's agent env at them and set REQUIRE_MTLS=true:

    TLS_CA_FILE   = infra/generated/_certs/federation-ca.crt
    TLS_CERT_FILE = infra/generated/_certs/<division>.crt
    TLS_KEY_FILE  = infra/generated/_certs/<division>.key
    TLS_CRL_FILE  = infra/generated/_certs/federation-ca.crl   # revocation gate (NFR-3)
    REQUIRE_MTLS  = true

Each division cert's CN + SAN is its division_id (defence-in-depth cert identity on top
of the DID-signed application layer). Re-running rotates the whole set (a fresh CA).

To REVOKE a division (regenerate the CRL with the revoked cert serials), pass --revoke
followed by the serial numbers of the certs to revoke. The serving context reloads the CRL
on its next bind (mtime cache) and rejects the revoked client cert at the handshake.

OCSP (NFR-3): ``--ocsp-url URL`` bakes URL into each cert's AIA OCSP field (overrides
TLS_OCSP_URL; ``--ocsp-url ""`` omits the extension). To ENFORCE it inbound, set
TLS_OCSP_MODE=soft|hard on the serving agent (transport/ocsp.py); TLS_OCSP_RESPONDER_URL
optionally overrides the per-cert AIA URL.

Usage:
    .venv\\Scripts\\python.exe scripts/issue_division_certs.py alpha beta gamma
    .venv\\Scripts\\python.exe scripts/issue_division_certs.py --ocsp-url http://ocsp.fed:8080 alpha beta
    .venv\\Scripts\\python.exe scripts/issue_division_certs.py --revoke <serial> [<serial>...]
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agt-federated-rag"))

from transport.mtls import issue_federation_certs, regenerate_crl  # noqa: E402

CERT_DIR = ROOT / "infra" / "generated" / "_certs"


def _revoke(serials: list[str]) -> int:
    """Regenerate the existing CA's CRL, revoking the given cert serial numbers."""
    ca_crt = CERT_DIR / "federation-ca.crt"
    ca_key = CERT_DIR / "federation-ca.key"
    crl = CERT_DIR / "federation-ca.crl"
    if not (ca_crt.exists() and ca_key.exists()):
        print(f"[revoke] no CA at {CERT_DIR} — run issuance first.", file=sys.stderr)
        return 1
    revoked = [int(s) for s in serials]
    path = regenerate_crl(ca_crt, ca_key, crl, revoked)
    print(f"[revoke] regenerated CRL revoking {len(revoked)} serial(s): {path}")
    print("[revoke] restart/rebind the serving agents to enforce (CRL reloads on next bind).")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--revoke":
        return _revoke(argv[1:])
    ocsp_url = None
    if argv and argv[0] == "--ocsp-url":
        if len(argv) < 2:
            print("--ocsp-url needs a URL (or \"\" to omit the AIA extension)", file=sys.stderr)
            return 2
        ocsp_url, argv = argv[1], argv[2:]
    divisions = argv or ["alpha", "beta", "gamma"]
    result = issue_federation_certs(CERT_DIR, divisions, ocsp_url=ocsp_url)
    print(f"[certs] federation CA:  {result['_ca']}")
    print(f"[certs] federation CRL: {result['_crl']}")
    for div in divisions:
        crt, key = result[div]
        print(f"[certs] {div}: {crt} / {key}")
    print("\nSet in each agt-federated-rag/.env.<division> (then restart the agents):")
    print(f"  TLS_CA_FILE={result['_ca']}")
    print("  TLS_CERT_FILE=<...>/<division>.crt")
    print("  TLS_KEY_FILE=<...>/<division>.key")
    print(f"  TLS_CRL_FILE={result['_crl']}")
    print("  REQUIRE_MTLS=true")
    print("  TLS_OCSP_MODE=soft|hard   # optional: query the AIA OCSP responder per peer cert")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
