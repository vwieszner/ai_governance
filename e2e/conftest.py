"""Shared fixtures + the live-stack skip-guard for the ≥3-division end-to-end suite.

The whole suite is gated TWICE, both of which must be true for any SC step to run:

  1. ``RUN_E2E=1`` in the environment — opt-in, so the hermetic unit suite never
     spends minutes probing docker stacks that aren't there.
  2. A genuine reachability probe of each required division's stack — exactly like
     tests/test_isolation.py, so the suite SKIPS cleanly (never fails) when the
     stacks aren't up, and RUNS + ASSERTS when they are.

A division's endpoints derive from its manifest ``port_base`` via the SAME helper
the onboarding/federation IaC uses (scripts.onboard_division.derive_ports). We read
the per-division generated artifacts (``infra/generated/<id>/{div-<id>.env,
secrets.json,did.json}``) the onboarder wrote — we do NOT invent new stacks.

Loopback is addressed as 127.0.0.1 (not "localhost"): the stacks bind 127.0.0.1:<port>
and on Windows "localhost" resolves to ::1 first, where WSL2 mirrored networking can
squat the IPv6 loopback and shadow the real service (same rationale as test_isolation).
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

# Repo root on sys.path so we can import the onboarding/federation IaC (single source
# of truth for ports + generated-artifact locations) — never re-deriving it here.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.onboard_division import (  # noqa: E402
    GENERATED_DIR,
    REALM,
    derive_ports,
    load_manifest,
)

# The ≥3 divisions the e2e exercises (alpha=A, beta=B, gamma=C). They are onboarded
# from infra/divisions/{alpha,beta,gamma}.yml and federated via federate_divisions.py.
E2E_DIVISIONS = ("alpha", "beta", "gamma")
DISCOVERY_URL = os.environ.get("E2E_DISCOVERY_URL", "http://127.0.0.1:8600")

# A short network timeout everywhere — these are loopback calls; a hang means "down".
HTTP_TIMEOUT = 5.0


def _loopback(port: int) -> str:
    return f"http://127.0.0.1:{port}"


@dataclass(frozen=True)
class Division:
    """Everything a test needs to talk to one live division — derived from its
    manifest + the artifacts the onboarder wrote. Addresses are loopback-pinned."""

    division_id: str
    ports: dict[str, int]
    secrets: dict[str, str]
    did: str

    @property
    def agent_url(self) -> str:
        return _loopback(self.ports["agent"])

    @property
    def openfga_url(self) -> str:
        return _loopback(self.ports["openfga"])

    @property
    def keycloak_url(self) -> str:
        return _loopback(self.ports["keycloak"])

    @property
    def issuer(self) -> str:
        return f"{self.keycloak_url}/realms/{REALM}"

    @property
    def openfga_token(self) -> str:
        return self.secrets["openfga_api_token"]

    @property
    def seed_password(self) -> str:
        # The per-division random seed-user (alice/bob) password the onboarder persisted.
        return self.secrets["seed_user_password"]


def _load_division(division_id: str) -> Division | None:
    """Build a Division from its onboarded artifacts, or None if it was never onboarded
    (so the caller can skip rather than crash on a missing file)."""
    manifest_path = ROOT / "infra" / "divisions" / f"{division_id}.yml"
    gen = GENERATED_DIR / division_id
    secrets_path = gen / "secrets.json"
    did_path = gen / "did.json"
    if not (manifest_path.exists() and secrets_path.exists() and did_path.exists()):
        return None
    manifest = load_manifest(manifest_path)
    secrets = json.loads(secrets_path.read_text(encoding="utf-8"))
    did = json.loads(did_path.read_text(encoding="utf-8")).get("did", "")
    return Division(
        division_id=division_id,
        ports=derive_ports(manifest.port_base),
        secrets=secrets,
        did=did,
    )


def _agent_reachable(div: Division) -> bool:
    """True only if this is genuinely THIS division's agent (its /health reports the
    matching cluster/division id), so an unrelated squatter on the port is treated as
    'not running' and the suite skips rather than asserting against the wrong service."""
    try:
        r = httpx.get(f"{div.agent_url}/health", timeout=HTTP_TIMEOUT)
    except Exception:
        return False
    if r.status_code != 200:
        return False
    body = r.json()
    return body.get("status") == "ok" and body.get("cluster") == div.division_id


def _openfga_reachable(div: Division) -> bool:
    try:
        r = httpx.get(f"{div.openfga_url}/healthz", timeout=HTTP_TIMEOUT)
        return r.status_code == 200 and r.json().get("status") == "SERVING"
    except Exception:
        return False


def _discovery_reachable() -> bool:
    try:
        r = httpx.get(f"{DISCOVERY_URL}/health", timeout=HTTP_TIMEOUT)
        return r.status_code == 200 and r.json().get("service") == "discovery"
    except Exception:
        return False


def mint_user_token(div: Division, username: str) -> str:
    """Mint a real division-scoped access token for a seeded user (alice/bob) via the
    rag-ui public client's direct-access (password) grant against THIS division's
    Keycloak realm. The token carries the division's agent client_id in `aud` (the
    onboarder's audience mapper), so the division's agent accepts it and a peer
    division would reject it (FR-2.1/2.4)."""
    r = httpx.post(
        f"{div.keycloak_url}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "rag-ui",
            "username": username,
            "password": div.seed_password,
        },
        timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()
    return str(r.json()["access_token"])


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def divisions() -> dict[str, Division]:
    """The three onboarded divisions, gated on RUN_E2E + a real reachability probe.

    Skips the WHOLE suite (clean reason, never a failure) when the opt-in flag is off
    or any required division stack is not up — the established test_isolation pattern,
    lifted to the federation level."""
    if os.environ.get("RUN_E2E") != "1":
        pytest.skip("e2e federation suite is opt-in — set RUN_E2E=1 (and bring up 3 divisions)")
    loaded: dict[str, Division] = {}
    for div_id in E2E_DIVISIONS:
        div = _load_division(div_id)
        if div is None:
            pytest.skip(
                f"division '{div_id}' not onboarded — run "
                f"scripts/onboard_division.py infra/divisions/{div_id}.yml"
            )
        if not (_agent_reachable(div) and _openfga_reachable(div)):
            pytest.skip(f"division '{div_id}' stack not reachable (agent/openfga down)")
        loaded[div_id] = div
    return loaded


@pytest.fixture(scope="session")
def discovery_up() -> str:
    """The discovery service URL, skipping if it isn't reachable. Separated from
    `divisions` so a division-only SC step doesn't depend on the broker being up
    (graceful degradation — FR-3.1 discovery is a control-plane convenience)."""
    if os.environ.get("RUN_E2E") != "1":
        pytest.skip("e2e federation suite is opt-in — set RUN_E2E=1")
    if not _discovery_reachable():
        pytest.skip(f"discovery service not reachable at {DISCOVERY_URL}")
    return DISCOVERY_URL
