"""M0 physical-isolation proof (IMPLEMENTATION_PLAN.md M0, D-3 / NFR-2).

The discriminating test: a division's agent — configured with its OWN OpenFGA
store/server/credential — CANNOT read another division's store. This is what makes
tenancy real rather than a division_id label on shared infra.

Requires two onboarded division OpenFGA stacks (alpha :8101, beta :8201), brought
up from infra/division-stack.template.yml via scripts/onboard_division.py. Skips
cleanly if they aren't running (so the unit suite stays infra-free).
"""
from __future__ import annotations

import httpx
import pytest

from scripts.onboard_division import AUTH_MODEL, DIVISIONS_DIR, GENERATED_DIR, onboard


def _read_env_file(path) -> dict[str, str]:
    return {k.strip(): v.strip() for k, _, v in
            (ln.partition("=") for ln in path.read_text(encoding="utf-8").splitlines() if "=" in ln)}


def test_division_config_isolation_invariant():
    """Hermetic (no live stacks, runs by default): each division renders a DISTINCT
    endpoint + credential set — own OpenFGA port+token, Keycloak port, Postgres &
    KC-admin passwords. This is the config-level physical-isolation invariant that
    backs test_division_cannot_read_peer_store (which needs live stacks). Together
    they prove NFR-2 both statically (here) and at runtime (there)."""
    cfg = {}
    for div in ("alpha", "beta"):
        onboard(DIVISIONS_DIR / f"{div}.yml", dry_run=True)   # renders only; no docker/network
        cfg[div] = _read_env_file(GENERATED_DIR / div / f"div-{div}.env")
    a, b = cfg["alpha"], cfg["beta"]
    for key in ("DIV_OPENFGA_PORT", "DIV_KEYCLOAK_PORT", "DIV_TEMPORAL_PORT",
                "OPENFGA_API_TOKEN", "POSTGRES_PASSWORD", "KEYCLOAK_ADMIN_PASSWORD"):
        assert a[key] != b[key], f"divisions share {key} -> not isolated"

_TUPLE = {"user": "user:alice", "relation": "viewer", "object": "chunk:secret-A"}


def _div_openfga(div: str) -> tuple[str, str]:
    env_path = GENERATED_DIR / div / f"div-{div}.env"
    if not env_path.exists():
        pytest.skip(f"division '{div}' not onboarded (run scripts/onboard_division.py {div})")
    env = {k.strip(): v.strip() for k, _, v in
           (ln.partition("=") for ln in env_path.read_text(encoding="utf-8").splitlines() if "=" in ln)}
    return f"http://localhost:{env['DIV_OPENFGA_PORT']}", env["OPENFGA_API_TOKEN"]


def _reachable(url: str) -> bool:
    try:
        return httpx.get(f"{url}/healthz", timeout=3).status_code < 500
    except Exception:
        return False


def test_division_cannot_read_peer_store():
    a_url, a_tok = _div_openfga("alpha")
    b_url, b_tok = _div_openfga("beta")
    if not (_reachable(a_url) and _reachable(b_url)):
        pytest.skip("alpha/beta OpenFGA stacks not running")

    ah = {"Authorization": f"Bearer {a_tok}"}
    bh = {"Authorization": f"Bearer {b_tok}"}

    # Division ALPHA: create its own store + model, grant alice viewer on a secret.
    sid_a = httpx.post(f"{a_url}/stores", json={"name": "div-alpha"}, headers=ah).json()["id"]
    httpx.post(f"{a_url}/stores/{sid_a}/authorization-models", json=AUTH_MODEL, headers=ah).raise_for_status()
    httpx.post(f"{a_url}/stores/{sid_a}/write",
               json={"writes": {"tuple_keys": [_TUPLE]}}, headers=ah).raise_for_status()

    # Sanity: alpha CAN read its own grant.
    own = httpx.post(f"{a_url}/stores/{sid_a}/check", json={"tuple_key": _TUPLE}, headers=ah)
    assert own.json().get("allowed") is True, "alpha must be able to read its own store"

    # ISOLATION 1 (store): alpha's store does not exist on beta's server — beta
    # cannot read it, by any means (no 200+allowed leak).
    cross = httpx.post(f"{b_url}/stores/{sid_a}/check", json={"tuple_key": _TUPLE}, headers=bh)
    assert not (cross.status_code == 200 and cross.json().get("allowed")), \
        "beta must NOT be able to read alpha's store/tuple"

    # ISOLATION 2 (credential): alpha's preshared key is rejected by beta's server,
    # and vice-versa — each division authenticates only to its own OpenFGA (NFR-2:
    # no shared credential whose leak crosses a division boundary).
    assert httpx.get(f"{b_url}/stores", headers=ah).status_code in (401, 403), \
        "alpha's OpenFGA token must be rejected by beta's server"
    assert httpx.get(f"{a_url}/stores", headers=bh).status_code in (401, 403), \
        "beta's OpenFGA token must be rejected by alpha's server"

    # And the two servers are genuinely distinct endpoints.
    assert a_url != b_url
