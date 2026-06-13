"""Pluggable secrets backend (Phase-1 item 14).

By default secrets come from the environment / .env (the current behaviour — zero change).
A deployment that mandates a vault sets ``SECRETS_BACKEND=vault`` and references secrets
indirectly: any setting whose VALUE is a ``vault:<path>#<field>`` reference is resolved at
startup against the configured backend. This keeps the high-value secrets (LLM key, OpenFGA
token, DB/HMAC secrets) out of env files entirely when a vault is in use, behind ONE
interface, with the env-file path as the always-available fallback.

Reference syntax:  vault:secret/data/agt/alpha#openfga_api_token
Anything not starting with a known backend prefix is returned verbatim (a literal secret).
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Protocol


class SecretsBackend(Protocol):
    def get(self, path: str, field: str) -> str | None: ...


class EnvFileBackend:
    """Resolve ``vault:`` refs from the environment as ``<PATH>__<FIELD>`` (upper-cased,
    non-alnum -> _). Lets the abstraction be exercised end-to-end with no real vault — the
    same indirection, backed by env. Also the safe fallback."""
    def get(self, path: str, field: str) -> str | None:
        key = (path + "__" + field).upper()
        key = "".join(c if c.isalnum() else "_" for c in key)
        return os.environ.get(key)


class VaultBackend:
    """HashiCorp Vault KV v2 over HTTP. Reads VAULT_ADDR + VAULT_TOKEN from the env.
    Best-effort + transport-injectable for tests (``opener``)."""
    def __init__(self, addr: str | None = None, token: str | None = None, opener=None) -> None:
        self.addr = (addr or os.environ.get("VAULT_ADDR", "")).rstrip("/")
        self.token = token or os.environ.get("VAULT_TOKEN", "")
        self._opener = opener or (lambda req: urllib.request.urlopen(req, timeout=10))

    def get(self, path: str, field: str) -> str | None:
        if not self.addr:
            return None
        url = f"{self.addr}/v1/{path}"
        req = urllib.request.Request(url, headers={"X-Vault-Token": self.token})
        try:
            raw = self._opener(req).read()
        except Exception:
            return None
        doc = json.loads(raw)
        # KV v2 nests under data.data; tolerate KV v1 (data) too.
        data = (doc.get("data") or {}).get("data") or doc.get("data") or {}
        val = data.get(field)
        return str(val) if val is not None else None


def get_backend(kind: str | None = None, **kw) -> SecretsBackend:
    kind = (kind or os.environ.get("SECRETS_BACKEND", "file")).lower()
    if kind == "vault":
        return VaultBackend(**kw)
    return EnvFileBackend()


_PREFIX = "vault:"


def is_ref(value: str) -> bool:
    return isinstance(value, str) and value.startswith(_PREFIX)


def resolve_secret(value: str, backend: SecretsBackend | None = None) -> str:
    """Resolve a single value: a ``vault:path#field`` ref via the backend, else verbatim.
    Raises if a ref cannot be resolved (fail loud — a missing secret must not become '')."""
    if not is_ref(value):
        return value
    spec = value[len(_PREFIX):]
    path, _, field = spec.partition("#")
    if not field:
        raise ValueError(f"secret ref missing '#field': {value!r}")
    be = backend or get_backend()
    got = be.get(path, field)
    if got is None:
        raise ValueError(f"secret ref could not be resolved: {value!r}")
    return got


def resolve_mapping(values: dict, backend: SecretsBackend | None = None) -> dict:
    """Return a copy of *values* with every ``vault:`` ref resolved. No-op when none are
    refs (the default env-file deployment), so it is free to call unconditionally."""
    be = backend or get_backend()
    return {k: (resolve_secret(v, be) if is_ref(v) else v) for k, v in values.items()}
