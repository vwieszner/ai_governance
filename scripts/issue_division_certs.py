"""Issue the federation mTLS certs (Phase-1 item 7).

Generates ONE shared federation CA + a per-division cert/key, written under
infra/generated/_certs/ (gitignored — they're key material). Then point each division's
agent env at them and set REQUIRE_MTLS=true:

    TLS_CA_FILE   = infra/generated/_certs/federation-ca.crt
    TLS_CERT_FILE = infra/generated/_certs/<division>.crt
    TLS_KEY_FILE  = infra/generated/_certs/<division>.key
    REQUIRE_MTLS  = true

Each division cert's CN + SAN is its division_id (defence-in-depth cert identity on top
of the DID-signed application layer). Re-running rotates the whole set (a fresh CA).

Usage:
    .venv\\Scripts\\python.exe scripts/issue_division_certs.py alpha beta gamma
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agt-federated-rag"))

from transport.mtls import issue_federation_certs  # noqa: E402


def main(argv: list[str]) -> int:
    divisions = argv or ["alpha", "beta", "gamma"]
    out = ROOT / "infra" / "generated" / "_certs"
    result = issue_federation_certs(out, divisions)
    print(f"[certs] federation CA: {result['_ca']}")
    for div in divisions:
        crt, key = result[div]
        print(f"[certs] {div}: {crt} / {key}")
    print("\nSet in each agt-federated-rag/.env.<division> (then restart the agents):")
    print(f"  TLS_CA_FILE={result['_ca']}")
    print("  TLS_CERT_FILE=<...>/<division>.crt")
    print("  TLS_KEY_FILE=<...>/<division>.key")
    print("  REQUIRE_MTLS=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
