"""BFF session-layer tests (production browser auth).

Pins the security-load-bearing pieces without a live IdP: server-side PKCE, the cookie ->
token resolution, CSRF enforcement on state-changing methods, silent server-side refresh,
and that NO token is ever returned to the browser (/bff/session exposes identity only).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time

import pytest

from api import bff


class _FakeRedis:
    def __init__(self): self.kv = {}
    async def setex(self, k, ttl, v): self.kv[k] = v
    async def get(self, k): return self.kv.get(k)
    async def delete(self, k): self.kv.pop(k, None)


def _patch_redis(monkeypatch):
    fake = _FakeRedis()
    async def r(): return fake
    monkeypatch.setattr(bff, "_redis", r)
    return fake


def test_pkce_pair_challenge_is_s256_of_verifier():
    v, c = bff._pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")
    assert c == expected
    assert bff._pkce_pair()[0] != v          # fresh each call


def test_cookie_value_parsing():
    assert bff._cookie_value("a=1; __Host-agtsession=xyz; b=2", "__Host-agtsession") == "xyz"
    assert bff._cookie_value("", "x") == ""


def test_session_store_roundtrip(monkeypatch):
    _patch_redis(monkeypatch)
    asyncio.run(bff._save_session("sid1", {"access": "AT", "csrf": "C"}))
    assert asyncio.run(bff._load_session("sid1"))["access"] == "AT"
    asyncio.run(bff._delete_session("sid1"))
    assert asyncio.run(bff._load_session("sid1")) is None


def test_session_endpoint_returns_identity_not_token(monkeypatch):
    _patch_redis(monkeypatch)
    asyncio.run(bff._save_session("sid2", {"access": "SECRET-TOKEN", "refresh": "R",
                                           "user": "alice@x", "groups": ["finance"], "csrf": "C"}))

    class _Req:
        cookies = {bff.settings.bff_cookie_name: "sid2"}
    body = json.loads(bytes(asyncio.run(bff.bff_session(_Req())).body).decode())
    assert body == {"authenticated": True, "user": "alice@x", "groups": ["finance"], "csrf_token": "C"}
    assert "SECRET-TOKEN" not in json.dumps(body)        # token NEVER leaves the server
    assert "refresh" not in body


def test_refresh_skips_when_not_expiring(monkeypatch):
    _patch_redis(monkeypatch)
    sess = {"access": "AT", "refresh": "R", "expiry": time.time() + 600}
    out = asyncio.run(bff._refresh_if_needed("sid", sess))
    assert out["access"] == "AT"             # untouched


def test_refresh_mints_new_token_when_near_expiry(monkeypatch):
    fake = _patch_redis(monkeypatch)

    class _Resp:
        def raise_for_status(self): pass
        def json(self): return {"access_token": "NEW", "refresh_token": "R2", "expires_in": 300}

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return _Resp()

    monkeypatch.setattr(bff.httpx, "AsyncClient", _Client)
    sess = {"access": "OLD", "refresh": "R", "expiry": time.time() - 1}
    out = asyncio.run(bff._refresh_if_needed("sid", sess))
    assert out["access"] == "NEW" and out["refresh"] == "R2"


# ── CSRF middleware ───────────────────────────────────────────────────────────

def _run_mw(scope, monkeypatch, session=None):
    """Drive BFFSessionMiddleware once; return (status, injected_auth_header_or_None)."""
    _patch_redis(monkeypatch)
    if session is not None:
        asyncio.run(bff._save_session("sidM", session))
    captured = {"status": None, "downstream_scope": None}

    async def app(scope, receive, send):
        captured["downstream_scope"] = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = bff.BFFSessionMiddleware(app)

    async def receive(): return {"type": "http.request"}
    async def send(msg):
        if msg["type"] == "http.response.start":
            captured["status"] = msg["status"]

    asyncio.run(mw(scope, receive, send))
    auth = None
    if captured["downstream_scope"]:
        for k, v in captured["downstream_scope"]["headers"]:
            if k == b"authorization":
                auth = v.decode()
    return captured["status"], auth


def _scope(method, headers):
    return {"type": "http", "method": method, "path": "/query",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()]}


def test_mw_injects_bearer_from_cookie_on_get(monkeypatch):
    cookie = f"{bff.settings.bff_cookie_name}=sidM"
    status, auth = _run_mw(_scope("GET", {"cookie": cookie}), monkeypatch,
                           session={"access": "AT", "csrf": "C", "expiry": time.time() + 600})
    assert status == 200
    assert auth == "Bearer AT"               # cookie resolved -> Authorization injected


def test_mw_blocks_post_without_csrf(monkeypatch):
    cookie = f"{bff.settings.bff_cookie_name}=sidM"
    status, _ = _run_mw(_scope("POST", {"cookie": cookie}), monkeypatch,
                        session={"access": "AT", "csrf": "C", "expiry": time.time() + 600})
    assert status == 403                     # state-changing call needs the CSRF header


def test_mw_allows_post_with_matching_csrf(monkeypatch):
    cookie = f"{bff.settings.bff_cookie_name}=sidM"
    status, auth = _run_mw(_scope("POST", {"cookie": cookie, "x-csrf-token": "C"}), monkeypatch,
                           session={"access": "AT", "csrf": "C", "expiry": time.time() + 600})
    assert status == 200 and auth == "Bearer AT"


def test_mw_passes_through_existing_bearer(monkeypatch):
    # An API/peer client with its own bearer is untouched (no cookie logic).
    status, auth = _run_mw(_scope("POST", {"authorization": "Bearer CLIENT"}), monkeypatch)
    assert status == 200 and auth == "Bearer CLIENT"
