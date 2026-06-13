"""Backend-For-Frontend (BFF) session layer — production browser auth.

The browser NEVER holds an access or refresh token. Instead:
  - GET  /bff/login    -> server-side PKCE; redirect the browser to the IdP.
  - GET  /bff/callback -> exchange code+verifier for tokens SERVER-SIDE; store them in Redis
                          under an opaque session id; set an HttpOnly+Secure+SameSite cookie.
  - GET  /bff/session  -> {authenticated, user, groups, csrf_token}  (NO token returned).
  - POST /bff/logout   -> delete the session + clear the cookie.

`BFFSessionMiddleware` then resolves the session cookie on every request: it injects
`Authorization: Bearer <access>` (looked up + silently refreshed server-side) so the existing
JWT-validating endpoints work unchanged, and enforces a CSRF double-submit token on
state-changing methods. A request that already carries an Authorization header (peer calls,
API clients) is passed through untouched.

This is the IETF "OAuth 2.0 for Browser-Based Apps" BFF pattern: refresh tokens never leave
the server, and an XSS in the SPA cannot read the HttpOnly cookie. One session per browser.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.parse
from typing import Any

import httpx
import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from config import settings

log = structlog.get_logger(__name__)

router = APIRouter()

_redis_client: Any = None


async def _redis() -> Any:
    global _redis_client
    if _redis_client is None:
        import redis.asyncio as aioredis
        _redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


def _skey(sid: str) -> str:
    return f"bff:session:{settings.division_id}:{sid}"


def _pkce_key(state: str) -> str:
    return f"bff:pkce:{settings.division_id}:{state}"


# ── OIDC endpoints (derived from the issuer) ───────────────────────────────────

def _authorize_url() -> str:
    return str(settings.oidc_issuer).rstrip("/") + "/protocol/openid-connect/auth"


def _token_url() -> str:
    return str(settings.oidc_issuer).rstrip("/") + "/protocol/openid-connect/token"


def _redirect_uri() -> str:
    # Must match a redirect URI registered on the rag-ui client (onboarding registers the
    # SPA origin). The BFF is reached same-origin via the UI proxy / edge.
    return settings.bff_public_base_url.rstrip("/") + "/bff/callback"


# ── PKCE ────────────────────────────────────────────────────────────────────────

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


# ── Session store ────────────────────────────────────────────────────────────────

async def _save_session(sid: str, data: dict) -> None:
    r = await _redis()
    await r.setex(_skey(sid), settings.bff_session_ttl_seconds, json.dumps(data))


async def _load_session(sid: str) -> dict | None:
    r = await _redis()
    raw = await r.get(_skey(sid))
    return json.loads(raw) if raw else None


async def _delete_session(sid: str) -> None:
    r = await _redis()
    await r.delete(_skey(sid))


async def _refresh_if_needed(sid: str, sess: dict) -> dict:
    """Silently refresh the access token server-side when it's near expiry. The refresh
    token never leaves the server. On refresh failure the session is left as-is (the next
    protected call will 401 and the SPA restarts login)."""
    if sess.get("expiry", 0) - time.time() > 30:
        return sess
    refresh = sess.get("refresh")
    if not refresh:
        return sess
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(_token_url(), data={
                "grant_type": "refresh_token",
                "client_id": settings.bff_client_id,
                "refresh_token": refresh,
            })
        resp.raise_for_status()
        tok = resp.json()
    except Exception as exc:  # noqa: BLE001
        log.warning("bff_refresh_failed", error=str(exc))
        return sess
    sess["access"] = tok["access_token"]
    sess["refresh"] = tok.get("refresh_token", refresh)
    sess["expiry"] = time.time() + int(tok.get("expires_in", 300))
    await _save_session(sid, sess)
    return sess


# ── Cookie helpers ───────────────────────────────────────────────────────────────

def _set_session_cookie(resp, sid: str) -> None:
    resp.set_cookie(
        key=settings.bff_cookie_name, value=sid,
        max_age=settings.bff_session_ttl_seconds,
        httponly=True, secure=settings.bff_cookie_secure, samesite="strict", path="/",
    )


def _clear_session_cookie(resp) -> None:
    resp.delete_cookie(key=settings.bff_cookie_name, path="/")


# ── Routes ───────────────────────────────────────────────────────────────────────

# Browser-bound login state: a cookie set at /bff/login and required to match the `state`
# at /bff/callback. Without this, the callback only checks that *some* state exists in Redis
# — vulnerable to login CSRF / session fixation (an attacker plants their own code in a
# victim's session). SameSite=Lax (NOT Strict) so it survives the top-level IdP redirect back.
_STATE_COOKIE = "__Host-bff_state"


@router.get("/bff/login")
async def bff_login() -> RedirectResponse:
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    r = await _redis()
    await r.setex(_pkce_key(state), 600, verifier)     # 10-min one-time verifier, server-side
    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": settings.bff_client_id,
        "redirect_uri": _redirect_uri(),
        "scope": "openid email profile",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    out = RedirectResponse(f"{_authorize_url()}?{params}", status_code=302)
    out.set_cookie(_STATE_COOKIE, state, max_age=600, httponly=True,
                   secure=settings.bff_cookie_secure, samesite="lax", path="/")
    return out


@router.get("/bff/callback")
async def bff_callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
    if not code or not state:
        raise HTTPException(status_code=400, detail="missing code/state")
    # Bind the callback to the browser that started login (login-CSRF / fixation guard).
    cookie_state = request.cookies.get(_STATE_COOKIE, "")
    if not cookie_state or not hmac.compare_digest(cookie_state, state):
        log.warning("bff_state_mismatch", agt_audit=True)
        raise HTTPException(status_code=400, detail="login state mismatch")
    r = await _redis()
    verifier = await r.get(_pkce_key(state))
    if not verifier:
        raise HTTPException(status_code=400, detail="invalid or expired login state")
    await r.delete(_pkce_key(state))
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(_token_url(), data={
                "grant_type": "authorization_code",
                "client_id": settings.bff_client_id,
                "code": code,
                "redirect_uri": _redirect_uri(),
                "code_verifier": verifier,
            })
        resp.raise_for_status()
        tok = resp.json()
    except Exception as exc:  # noqa: BLE001
        log.warning("bff_code_exchange_failed", error=str(exc), agt_audit=True)
        raise HTTPException(status_code=401, detail="login failed")

    # Validate the access token + derive identity (re-uses the agent's validator).
    from auth.token_validator import validate_token, principal, extract_groups
    try:
        claims = await validate_token(tok["access_token"])
        princ = principal(claims)
    except Exception as exc:  # noqa: BLE001
        log.warning("bff_token_invalid", error=str(exc), agt_audit=True)
        raise HTTPException(status_code=401, detail="login failed")

    sid = secrets.token_urlsafe(32)             # fresh id => no session fixation
    sess = {
        "access": tok["access_token"],
        "refresh": tok.get("refresh_token", ""),
        "expiry": time.time() + int(tok.get("expires_in", 300)),
        "principal": princ,
        "user": claims.get("email") or claims.get("preferred_username") or claims.get("sub"),
        "groups": extract_groups(claims),
        "csrf": secrets.token_urlsafe(24),
    }
    await _save_session(sid, sess)
    log.info("bff_login_ok", user=sess["user"], agt_audit=True)
    out = RedirectResponse(settings.bff_post_login_redirect, status_code=302)
    _set_session_cookie(out, sid)
    out.delete_cookie(_STATE_COOKIE, path="/")     # one-time login-state cookie consumed
    return out


@router.get("/bff/session")
async def bff_session(request: Request) -> JSONResponse:
    sid = request.cookies.get(settings.bff_cookie_name)
    sess = await _load_session(sid) if sid else None
    if not sess:
        return JSONResponse({"authenticated": False})
    # Expose identity + the CSRF token the SPA must echo on mutations — never the access token.
    return JSONResponse({
        "authenticated": True,
        "user": sess.get("user"),
        "groups": sess.get("groups", []),
        "csrf_token": sess.get("csrf", ""),
    })


@router.post("/bff/logout")
async def bff_logout(request: Request) -> JSONResponse:
    sid = request.cookies.get(settings.bff_cookie_name)
    if sid:
        await _delete_session(sid)
    out = JSONResponse({"ok": True})
    _clear_session_cookie(out)
    return out


# ── Middleware: cookie -> Authorization header + CSRF ──────────────────────────

_CSRF_SAFE = {"GET", "HEAD", "OPTIONS"}


class BFFSessionMiddleware:
    """ASGI middleware. If a request has NO Authorization header but a valid BFF session
    cookie, inject `Authorization: Bearer <access>` (resolved + silently refreshed
    server-side) so the existing endpoints authenticate normally. Enforces a CSRF
    double-submit token on state-changing methods for cookie-authenticated requests."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        # Don't touch requests that already carry a bearer token (peer/API clients) or the
        # BFF endpoints themselves.
        path = scope.get("path", "")
        if headers.get("authorization") or path.startswith("/bff/"):
            await self.app(scope, receive, send)
            return
        sid = _cookie_value(headers.get("cookie", ""), settings.bff_cookie_name)
        if sid:
            sess = await _load_session(sid)
            if sess:
                sess = await _refresh_if_needed(sid, sess)
                method = scope.get("method", "GET").upper()
                if method not in _CSRF_SAFE:
                    if headers.get("x-csrf-token", "") != sess.get("csrf", ""):
                        await _deny(send, 403, "CSRF token missing/invalid")
                        return
                # inject the bearer the endpoints expect
                new_headers = [(k, v) for k, v in scope["headers"]
                               if k.decode().lower() != "authorization"]
                new_headers.append((b"authorization", f"Bearer {sess['access']}".encode()))
                scope = dict(scope)
                scope["headers"] = new_headers
        await self.app(scope, receive, send)


def _cookie_value(cookie_header: str, name: str) -> str:
    for part in cookie_header.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return ""


async def _deny(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})
