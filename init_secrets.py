"""
Generate the gitignored root .env that docker-compose.yml and setup_agt.py read.

Run ONCE before `docker compose up -d`:
    python init_secrets.py

Creates ./.env with strong, randomly-generated credentials for the infra stack:
  - POSTGRES_USER / POSTGRES_PASSWORD   (OpenFGA's datastore)
  - KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD
  - OPENFGA_API_TOKEN                    (preshared key the backends must send)
  - APPROVAL_HMAC_SECRET_A / _B          (sign approval deep-links)
  - AGENT_CLIENT_SECRET_A / _B           (Keycloak confidential-client secrets)

It does NOT overwrite an existing .env (so credentials are stable across restarts).
NVIDIA_API_KEY is NOT generated — it must already be in your environment or in .env;
this script copies it in from the environment if present.

Security: .env is gitignored. No secret is ever written to tracked source.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

ENV_PATH = Path(__file__).parent / ".env"


def main() -> None:
    if ENV_PATH.exists():
        print(f".env already exists at {ENV_PATH} — leaving it untouched.")
        print("Delete it and re-run to rotate all credentials (then recreate the stack).")
        return

    nvidia = os.environ.get("NVIDIA_API_KEY", "")
    lines = [
        "# Auto-generated infra credentials — gitignored, never commit.",
        "# Regenerate by deleting this file and running: python init_secrets.py",
        "",
        "# Postgres (OpenFGA datastore)",
        "POSTGRES_USER=openfga",
        f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}",
        "",
        "# Keycloak admin",
        "KEYCLOAK_ADMIN=admin",
        f"KEYCLOAK_ADMIN_PASSWORD={secrets.token_urlsafe(24)}",
        "",
        "# OpenFGA preshared key — backends must send this as a Bearer token",
        f"OPENFGA_API_TOKEN={secrets.token_urlsafe(32)}",
        "",
        "# Approval deep-link HMAC signing keys (per cluster)",
        f"APPROVAL_HMAC_SECRET_A={secrets.token_hex(32)}",
        f"APPROVAL_HMAC_SECRET_B={secrets.token_hex(32)}",
        "",
        "# Keycloak confidential-client secrets (per cluster)",
        f"AGENT_CLIENT_SECRET_A={secrets.token_urlsafe(24)}",
        f"AGENT_CLIENT_SECRET_B={secrets.token_urlsafe(24)}",
        "",
        "# LLM key — sourced from your environment at generation time.",
        f"NVIDIA_API_KEY={nvidia}",
        "",
    ]
    ENV_PATH.write_text("\n".join(lines), encoding="utf-8")
    try:
        os.chmod(ENV_PATH, 0o600)  # owner-only (effective on POSIX)
    except OSError:
        pass

    print(f"Wrote {ENV_PATH} with freshly generated credentials.")
    if not nvidia:
        print("WARNING: NVIDIA_API_KEY was not in your environment — set it in .env "
              "before running setup_agt.py (LLM calls will fail without it).")


if __name__ == "__main__":
    main()
