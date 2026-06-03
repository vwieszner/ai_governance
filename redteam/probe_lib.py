"""
Red-team probe helpers — shared utilities for adversarial probing of both
federated-RAG solutions (A2A on :8000/:8002, AGT on :8010/:8012).

Run with the project venv python:
    D:\\work\\ai_governance\\ai_governance\\.venv\\Scripts\\python.exe

NOTE (rules of engagement): this script does NOT modify any backend source.
It only sends HTTP requests and reports observed responses. Where a probe needs
a secret that an external attacker would not possess (e.g. the approval HMAC
secret), the probe deliberately uses a WRONG/guessed value — demonstrating that
knowing the leaked secret lets you sign is the trust boundary working as
designed, not a vulnerability.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx

KEYCLOAK = "http://localhost:8087"
REALM = "rag"
TOKEN_URL = f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token"

A2A_A = "http://localhost:8000"
A2A_B = "http://localhost:8002"
AGT_A = "http://localhost:8010"
AGT_B = "http://localhost:8012"

# Short timeout so a degraded Temporal worker (known Windows signal bug) or a
# hung approval flow does not stall the probe run.
TIMEOUT = httpx.Timeout(15.0, connect=5.0)


def get_token(username: str = "alice", password: str = "demo",
              client_id: str = "rag-ui", client_secret: str | None = None,
              scope: str = "openid profile") -> str:
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
        "scope": scope,
    }
    if client_secret:
        data["client_secret"] = client_secret
    r = httpx.post(TOKEN_URL, data=data, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()["access_token"]


def client_credentials_token(client_id: str, client_secret: str,
                             scope: str = "openid") -> dict[str, Any]:
    """Try a client_credentials grant. Returns the full token response dict."""
    r = httpx.post(TOKEN_URL, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }, timeout=TIMEOUT)
    return {"status": r.status_code, "body": r.json() if r.headers.get(
        "content-type", "").startswith("application/json") else r.text}


def decode_claims(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def forge_alg_none(claims: dict[str, Any]) -> str:
    """Build an unsigned alg:none JWT with the given claims."""
    header = {"alg": "none", "typ": "JWT"}
    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(claims).encode())
    return f"{h}.{p}."


def tamper_signature(token: str) -> str:
    """Flip the last chars of a real token's signature to break it."""
    h, p, s = token.split(".")
    # mutate a few signature characters deterministically
    bad = list(s)
    for i in range(min(8, len(bad))):
        bad[i] = "A" if bad[i] != "A" else "B"
    return f"{h}.{p}.{''.join(bad)}"


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def a2a_send_body(text: str) -> dict[str, Any]:
    return {"message": {"role": "user", "parts": [{"type": "text", "text": text}]}}


def post_sse(url: str, headers: dict[str, str], body: dict[str, Any],
             max_seconds: float = 25.0) -> dict[str, Any]:
    """POST and collect an SSE stream (or a normal response). Returns
    {status, events:[...], raw:str(truncated)}."""
    events: list[str] = []
    raw_parts: list[str] = []
    start = time.time()
    try:
        with httpx.stream("POST", url, headers=headers, json=body,
                          timeout=httpx.Timeout(max_seconds, connect=5.0)) as r:
            status = r.status_code
            ct = r.headers.get("content-type", "")
            if "text/event-stream" in ct:
                for line in r.iter_lines():
                    raw_parts.append(line)
                    if line.startswith("data:"):
                        events.append(line[5:].strip())
                    if time.time() - start > max_seconds:
                        break
            else:
                raw_parts.append(r.read().decode("utf-8", "ignore"))
    except httpx.TimeoutException:
        return {"status": "TIMEOUT", "events": events,
                "raw": "\n".join(raw_parts)[:2000]}
    except Exception as e:  # noqa: BLE001
        return {"status": f"ERR:{type(e).__name__}", "events": events,
                "raw": f"{e}"[:500]}
    return {"status": status, "events": events,
            "raw": "\n".join(raw_parts)[:3000]}


def short(resp: httpx.Response, n: int = 400) -> str:
    return f"{resp.status_code} {resp.text[:n]!r}"
