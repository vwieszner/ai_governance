"""Keycloak Admin REST helpers — the ONE Keycloak admin client in this repo (FR-2.2).

Shared by:
  * scripts/onboard_division.py — provisioning a division's realm (seed users + RBAC
    realm roles), authenticated as the master ``admin-cli`` user;
  * api/main.py — the division-admin user-lifecycle API (provision / disable / assign
    roles), authenticated as THIS division's agent service account (client-credentials).

Every helper takes an ``httpx.AsyncClient``, the Keycloak base URL, the realm and the
bearer headers, so the caller owns transport + credentials (and tests can drive them with
an ``httpx.MockTransport``). Deliberately free of ``config`` imports: the onboarding script
imports this module without an agent ``.env``.

Role mapping uses the user's ``role-mappings/realm/available`` + ``role-mappings/realm``
views (not ``GET /roles/{name}``), so the agent service account only needs the
realm-management ``manage-users``/``view-users``/``query-users`` roles — no realm-wide
``view-realm``.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

# The division RBAC realm roles (FR-2.2 / FR-2.3): requester/member, data owner, admin.
DIVISION_ROLES: tuple[str, ...] = ("member", "data-owner", "division-admin")

# realm-management client roles the agent's service account needs to run the
# user-lifecycle API (and nothing broader — no manage-realm / manage-clients).
USER_ADMIN_CLIENT_ROLES: tuple[str, ...] = ("manage-users", "view-users", "query-users")


class KeycloakAdminError(RuntimeError):
    """A Keycloak admin call failed (non-2xx other than an expected idempotent 409)."""

    def __init__(self, op: str, status: int) -> None:
        super().__init__(f"keycloak admin '{op}' failed with HTTP {status}")
        self.op = op
        self.status = status


def _check(resp: Any, op: str, ok: tuple[int, ...] = (200, 201, 204)) -> Any:
    if resp.status_code not in ok:
        raise KeycloakAdminError(op, resp.status_code)
    return resp


def split_realm_url(url: str) -> tuple[str, str]:
    """``http://kc:8080/realms/rag/protocol/...`` -> (``http://kc:8080``, ``rag``).

    Accepts an issuer or any realm-scoped URL (e.g. the JWKS URI, which is reachable
    from the agent even where the browser-facing issuer host is not)."""
    base, sep, rest = url.partition("/realms/")
    realm = rest.split("/", 1)[0]
    if not sep or not realm:
        raise ValueError("URL is not a Keycloak realm URL (no /realms/<realm>)")
    return base.rstrip("/"), realm


def _u(kc: str, realm: str, path: str = "") -> str:
    return f"{kc}/admin/realms/{quote(realm, safe='')}{path}"


async def service_account_headers(c: Any, kc: str, realm: str, client_id: str,
                                  client_secret: str) -> dict[str, str]:
    """Client-credentials token for a realm client's service account -> bearer headers."""
    r = await c.post(f"{kc}/realms/{quote(realm, safe='')}/protocol/openid-connect/token",
                     data={"grant_type": "client_credentials", "client_id": client_id,
                           "client_secret": client_secret})
    _check(r, "service_account_token", ok=(200,))
    return {"Authorization": f"Bearer {r.json()['access_token']}",
            "Content-Type": "application/json"}


# ── users ──────────────────────────────────────────────────────────────────────

async def find_user(c: Any, kc: str, realm: str, h: dict, username: str) -> dict | None:
    """Exact-username lookup in THIS realm; None if absent."""
    r = await c.get(_u(kc, realm, "/users"),
                    params={"username": username, "exact": "true"}, headers=h)
    _check(r, "find_user", ok=(200,))
    for u in r.json() or []:
        if str(u.get("username", "")).lower() == username.lower():
            return u
    return None


async def create_user(c: Any, kc: str, realm: str, h: dict, *, username: str, email: str,
                      first_name: str = "", last_name: str = "", password: str | None = None,
                      temporary: bool = True) -> bool:
    """Create an enabled user with a verified email. Returns False if it already exists
    (409), True if created. With no ``password`` the user gets the UPDATE_PASSWORD required
    action (the admin issues credentials out-of-band, e.g. Keycloak's reset email).

    Names default to the onboarding convention (``<Username> User``): Keycloak's declarative
    user profile (KC 24+) requires firstName/lastName, and an empty one leaves a
    VERIFY_PROFILE action that refuses login ("Account is not fully set up")."""
    body: dict[str, Any] = {
        "username": username, "enabled": True, "email": email, "emailVerified": True,
        "firstName": first_name or username.capitalize(), "lastName": last_name or "User",
        "requiredActions": [] if password else ["UPDATE_PASSWORD"],
    }
    if password:
        body["credentials"] = [{"type": "password", "value": password, "temporary": temporary}]
    r = await c.post(_u(kc, realm, "/users"), json=body, headers=h)
    if r.status_code == 409:
        return False
    _check(r, "create_user", ok=(201,))
    return True


async def ensure_user(c: Any, kc: str, realm: str, h: dict, username: str, email: str,
                      password: str) -> None:
    """Idempotent seed-user provisioning (onboarding): create, then FORCE enabled +
    verified + no required actions + permanent password, so a direct-access-grant login
    works even on a re-run (a bare create can leave a required action that 400s it)."""
    await create_user(c, kc, realm, h, username=username, email=email,
                      first_name=username.capitalize(), last_name="User",
                      password=password, temporary=False)
    u = await find_user(c, kc, realm, h, username)
    if u:
        await c.put(_u(kc, realm, f"/users/{u['id']}"),
                    json={"enabled": True, "emailVerified": True, "requiredActions": []},
                    headers=h)
        await c.put(_u(kc, realm, f"/users/{u['id']}/reset-password"),
                    json={"type": "password", "value": password, "temporary": False},
                    headers=h)


async def set_enabled(c: Any, kc: str, realm: str, h: dict, uid: str, enabled: bool) -> None:
    r = await c.put(_u(kc, realm, f"/users/{uid}"), json={"enabled": enabled}, headers=h)
    _check(r, "set_enabled")


async def logout_user(c: Any, kc: str, realm: str, h: dict, uid: str) -> None:
    """Revoke ALL of the user's sessions (SSO + offline) — refresh tokens stop working."""
    r = await c.post(_u(kc, realm, f"/users/{uid}/logout"), headers=h)
    _check(r, "logout_user")


# ── realm roles ────────────────────────────────────────────────────────────────

async def ensure_realm_roles(c: Any, kc: str, realm: str, h: dict,
                             roles: tuple[str, ...] | list[str] = DIVISION_ROLES) -> None:
    """Create the realm roles (idempotent: 201 or 409)."""
    for role in sorted(roles):
        await c.post(_u(kc, realm, "/roles"), json={"name": role}, headers=h)


async def get_realm_roles(c: Any, kc: str, realm: str, h: dict, uid: str) -> list[str]:
    """The user's DIRECT realm-role names (composite/default roles not expanded)."""
    r = await c.get(_u(kc, realm, f"/users/{uid}/role-mappings/realm"), headers=h)
    _check(r, "get_realm_roles", ok=(200,))
    return sorted(str(x.get("name")) for x in (r.json() or []) if x.get("name"))


async def add_realm_roles(c: Any, kc: str, realm: str, h: dict, uid: str,
                          names: list[str] | tuple[str, ...]) -> list[str]:
    """Map realm roles onto the user. Returns the names actually added. Raises if a
    requested role does not exist / is not assignable (never a silent partial grant)."""
    want = set(names)
    if not want:
        return []
    r = await c.get(_u(kc, realm, f"/users/{uid}/role-mappings/realm/available"), headers=h)
    _check(r, "available_realm_roles", ok=(200,))
    reps = [x for x in (r.json() or []) if x.get("name") in want]
    have = set(await get_realm_roles(c, kc, realm, h, uid))
    missing = want - {x["name"] for x in reps} - have
    if missing:
        raise KeycloakAdminError(f"add_realm_roles:unknown:{','.join(sorted(missing))}", 404)
    if reps:
        rr = await c.post(_u(kc, realm, f"/users/{uid}/role-mappings/realm"), json=reps, headers=h)
        _check(rr, "add_realm_roles")
    return sorted(x["name"] for x in reps)


async def remove_realm_roles(c: Any, kc: str, realm: str, h: dict, uid: str,
                             names: list[str] | tuple[str, ...]) -> list[str]:
    """Unmap realm roles from the user. Returns the names actually removed."""
    want = set(names)
    if not want:
        return []
    r = await c.get(_u(kc, realm, f"/users/{uid}/role-mappings/realm"), headers=h)
    _check(r, "get_realm_roles", ok=(200,))
    reps = [x for x in (r.json() or []) if x.get("name") in want]
    if reps:
        # DELETE with a JSON body (httpx.delete() takes no body — use request()).
        rr = await c.request("DELETE", _u(kc, realm, f"/users/{uid}/role-mappings/realm"),
                             json=reps, headers=h)
        _check(rr, "remove_realm_roles")
    return sorted(x["name"] for x in reps)


async def assign_realm_roles_by_username(c: Any, kc: str, realm: str, h: dict,
                                         assignments: dict[str, list[str]]) -> None:
    """Onboarding: additively assign realm roles to (seeded) users by username."""
    for username, want in assignments.items():
        u = await find_user(c, kc, realm, h, username)
        if u:
            await add_realm_roles(c, kc, realm, h, u["id"], want)


# ── service account wiring (onboarding) ─────────────────────────────────────────

async def grant_user_admin_to_service_account(c: Any, kc: str, realm: str, h: dict,
                                              client_id: str) -> None:
    """Give ``client_id``'s service account the realm-management user-admin roles
    (``USER_ADMIN_CLIENT_ROLES``) so the division agent can run the FR-2.2 lifecycle API
    against ITS OWN realm. Scoped to this realm only — a division's agent can never manage
    another division's users (each division has its own Keycloak/realm)."""
    q = await c.get(_u(kc, realm, "/clients"), params={"clientId": client_id}, headers=h)
    _check(q, "find_client", ok=(200,))
    cl = q.json()
    if not cl:
        raise KeycloakAdminError(f"find_client:{client_id}", 404)
    sa = await c.get(_u(kc, realm, f"/clients/{cl[0]['id']}/service-account-user"), headers=h)
    _check(sa, "service_account_user", ok=(200,))
    sa_uid = sa.json()["id"]
    rm = await c.get(_u(kc, realm, "/clients"), params={"clientId": "realm-management"}, headers=h)
    _check(rm, "find_realm_management", ok=(200,))
    rm_id = rm.json()[0]["id"]
    reps = []
    for name in USER_ADMIN_CLIENT_ROLES:
        rr = await c.get(_u(kc, realm, f"/clients/{rm_id}/roles/{name}"), headers=h)
        _check(rr, f"realm_management_role:{name}", ok=(200,))
        reps.append(rr.json())
    m = await c.post(_u(kc, realm, f"/users/{sa_uid}/role-mappings/clients/{rm_id}"),
                     json=reps, headers=h)
    _check(m, "grant_user_admin")
