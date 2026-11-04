"""Pytest bootstrap for the AGT Federated-RAG test suite.

Lives at the package root so the backend's top-level modules (`config`, `mesh`,
`auth`, ...) are importable from tests the same way the app imports them. Also
provides a hermetic `Settings` factory so config/tenancy tests don't depend on a
real `.env` or live infra.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make `from config import ...` (and mesh/auth/etc.) resolve when pytest collects.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
# Also expose the repo root so tests can import `scripts.onboard_division`
# (the M0 division generator lives at repo-root/scripts/, outside this package).
_REPO_ROOT = _ROOT.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


# Minimal set of REQUIRED settings so Settings() constructs without a .env.
_REQUIRED = dict(
    openai_api_key="test-openai-key",
    openfga_store_id="test-store",
    openfga_model_id="test-model",
    neo4j_password="test-neo4j",
    agent_client_id="test-agent",
    agent_client_secret="test-agent-secret",
    agent_sponsor_email="sponsor@example.com",
    approval_hmac_secret="0" * 64,
)

# config.py constructs a module-level `settings = Settings()` on import, which needs
# the REQUIRED fields. Locally a (gitignored) .env supplies them; in CI / a fresh
# checkout there is NO .env, so `import config` (during collection) would raise.
# When no env file is present, seed the REQUIRED values into the environment so the
# suite is hermetic. `setdefault` + the file-absence guard keep a real .env run
# (local/dev) byte-for-byte unchanged — these fallbacks apply ONLY when no env file
# exists (the CI case). Must run at conftest import, before any test imports config.
_ENV_FILE = _ROOT / os.environ.get("RAG_ENV_FILE", ".env")
if not _ENV_FILE.exists():
    for _field, _val in _REQUIRED.items():
        os.environ.setdefault(_field.upper(), _val)


@pytest.fixture(autouse=True)
def _reset_mosaic_release_ledger(monkeypatch):
    """The mosaic guard's per-user release ledger is process-global; isolate every test.

    Production default is the shared Redis ledger; the hermetic suite has no Redis, so tests
    use the in-process one (tests that exercise the Redis ledger construct it explicitly)."""
    import config

    monkeypatch.setattr(config.settings, "mosaic_ledger_backend", "memory")
    mod = sys.modules.get("agent.context_guard")
    if mod is not None:
        mod.LEDGER.clear()
    yield
    mod = sys.modules.get("agent.context_guard")
    if mod is not None:
        mod.LEDGER.clear()


@pytest.fixture
def make_settings():
    """Return a factory that builds a hermetic Settings (no env file, no infra).

    Usage: ``s = make_settings(cluster_id="division-x", division_id="alpha")``.
    """
    from config import Settings

    def _make(**overrides):
        # _env_file=None disables .env loading so the test is deterministic.
        return Settings(_env_file=None, **{**_REQUIRED, **overrides})

    return _make
