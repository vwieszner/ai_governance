"""Pluggable secrets-backend tests (Phase-1 item 14).

Pins: literals pass through untouched (default env-file deployment is unaffected), a
`vault:path#field` ref resolves via the backend, an unresolvable ref fails LOUD (never
silently becomes ''), and the Vault adapter parses KV v2.
"""
from __future__ import annotations

import json

import pytest

from secrets_backend import (
    EnvFileBackend,
    VaultBackend,
    is_ref,
    resolve_secret,
    resolve_mapping,
)


def test_literal_passthrough():
    assert not is_ref("nvapi-abc")
    assert resolve_secret("nvapi-abc") == "nvapi-abc"
    # mapping no-op when nothing is a ref (the default deployment)
    assert resolve_mapping({"a": "1", "b": "plain"}) == {"a": "1", "b": "plain"}


def test_envfile_backend_resolves_ref(monkeypatch):
    monkeypatch.setenv("SECRET_DATA_AGT_ALPHA__OPENFGA_API_TOKEN", "tok-123")
    be = EnvFileBackend()
    assert resolve_secret("vault:secret/data/agt/alpha#openfga_api_token", be) == "tok-123"


def test_ref_missing_field_raises():
    with pytest.raises(ValueError):
        resolve_secret("vault:secret/data/agt/alpha", EnvFileBackend())  # no #field


def test_unresolvable_ref_fails_loud():
    with pytest.raises(ValueError):
        resolve_secret("vault:secret/data/none#missing", EnvFileBackend())


def test_vault_backend_parses_kv_v2():
    class _Resp:
        def __init__(self, b): self._b = b
        def read(self): return self._b

    captured = {}
    def opener(req):
        captured["url"] = req.full_url
        captured["token"] = req.headers.get("X-vault-token")
        return _Resp(json.dumps({"data": {"data": {"openfga_api_token": "vault-secret"}}}).encode())

    be = VaultBackend(addr="https://vault.corp", token="t", opener=opener)
    assert be.get("secret/data/agt/alpha", "openfga_api_token") == "vault-secret"
    assert captured["url"] == "https://vault.corp/v1/secret/data/agt/alpha"
    assert captured["token"] == "t"


def test_resolve_mapping_mixes_literals_and_refs(monkeypatch):
    monkeypatch.setenv("SECRET_DATA__K", "resolved")
    out = resolve_mapping(
        {"plain": "x", "ref": "vault:secret/data#k"},
        backend=EnvFileBackend(),
    )
    assert out == {"plain": "x", "ref": "resolved"}
