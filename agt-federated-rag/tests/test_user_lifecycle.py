"""FR-2.2 — division-admin user lifecycle API (provision / disable / assign roles).

Pins:
  * admin happy paths: provision (Keycloak user + realm roles + OpenFGA role mirror) and
    role assignment (Keycloak mappings and the OpenFGA mirror converge together);
  * a non-admin is refused (403) and a FOREIGN division's admin token is refused (401) —
    with ZERO Keycloak calls made in either case;
  * the disable cascade: denylist (a still-valid token is refused on the next request),
    Keycloak disabled + sessions revoked, OpenFGA access tuples deleted (owner retained),
    requests the user made auto-denied in Temporal + withdrawn from approvers' inboxes,
    requests awaiting the user left pending, outcome inbox purged;
  * every action lands in the tamper-evident audit chain (verified);
  * fail-closed edges: denylist store down → 503; partial cascade → 502 + step report;
  * re-enable: Keycloak enabled, denylist cleared (a NEW token works), OpenFGA role mirror
    rebuilt from the CURRENT Keycloak roles while the viewer/editor/pending grants the
    disable deleted stay gone; idempotent; partial → 502; same admin gate + audit.

Hermetic: Keycloak is an in-memory fake behind an ``httpx.MockTransport`` (so the real
auth.keycloak_admin HTTP calls run); OpenFGA is the REAL ``OpenFGAAuth`` over a fake SDK
client (tuple set); Redis is an in-memory fake shared by main/approval_index/outcome_store;
tokens for the identity tests are real RS256 JWTs validated by the real validate_token.
"""
from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace

import httpx
import pytest
import structlog
from jose import jwt

from api import main

ISS_A = "http://kc.alpha:8080/realms/rag"
ISS_B = "http://kc.beta:8080/realms/rag"
AUD_A = "agent-alpha"
AUD_B = "agent-beta"


# ── fakes ──────────────────────────────────────────────────────────────────────

class FakeKeycloak:
    """Just enough of the Keycloak admin REST API for auth.keycloak_admin."""

    def __init__(self, realm: str = "rag", client_id: str = AUD_A, secret: str = "test-agent-secret"):
        self.realm, self.client_id, self.secret = realm, client_id, secret
        self.token = "kc-admin-token"
        self.roles = {"member": "r-member", "data-owner": "r-owner",
                      "division-admin": "r-admin", "default-roles-rag": "r-default"}
        self.users: dict[str, dict] = {}         # id -> user
        self.mappings: dict[str, set[str]] = {}  # id -> realm role names
        self.logouts: list[str] = []
        self.calls: list[str] = []
        self.client_role_grants: dict[str, list[str]] = {}
        self.clients = {"agent-alpha": "c-agent", "realm-management": "c-rm"}

    def add_user(self, username, email, roles=(), enabled=True):
        uid = f"kc-{username}"
        self.users[uid] = {"id": uid, "username": username, "email": email, "enabled": enabled}
        self.mappings[uid] = set(roles) | {"default-roles-rag"}
        return uid

    def _rep(self, name):
        return {"id": self.roles[name], "name": name}

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(f"{req.method} {req.url.path}")
        p = req.url.path
        if p == f"/realms/{self.realm}/protocol/openid-connect/token":
            form = dict(x.split("=", 1) for x in req.content.decode().split("&"))
            if form.get("client_id") == self.client_id and form.get("client_secret") == self.secret:
                return httpx.Response(200, json={"access_token": self.token})
            return httpx.Response(401, json={"error": "unauthorized_client"})
        if req.headers.get("authorization") != f"Bearer {self.token}":
            return httpx.Response(401)
        base = f"/admin/realms/{self.realm}"
        assert p.startswith(base), p
        rest = p[len(base):]
        parts = rest.strip("/").split("/")
        body = json.loads(req.content) if req.content else None
        if parts == ["users"] and req.method == "GET":
            un = req.url.params.get("username", "").lower()
            return httpx.Response(200, json=[u for u in self.users.values() if u["username"] == un])
        if parts == ["users"] and req.method == "POST":
            if any(u["username"] == body["username"].lower() for u in self.users.values()):
                return httpx.Response(409)
            uid = self.add_user(body["username"].lower(), body["email"], enabled=body["enabled"])
            self.users[uid]["requiredActions"] = body.get("requiredActions", [])
            return httpx.Response(201)
        if parts == ["roles"] and req.method == "POST":
            if body["name"] in self.roles:
                return httpx.Response(409)
            self.roles[body["name"]] = f"r-{body['name']}"
            return httpx.Response(201)
        if parts[0] == "users" and len(parts) >= 2:
            uid = parts[1]
            if uid not in self.users:
                return httpx.Response(404)
            sub = parts[2:]
            if sub == [] and req.method == "PUT":
                self.users[uid].update(body)
                return httpx.Response(204)
            if sub == ["reset-password"]:
                return httpx.Response(204)
            if sub == ["logout"]:
                self.logouts.append(uid)
                return httpx.Response(204)
            if sub == ["role-mappings", "realm"]:
                if req.method == "GET":
                    return httpx.Response(200, json=[self._rep(n) for n in sorted(self.mappings[uid])])
                names = {x["name"] for x in body}
                if req.method == "POST":
                    self.mappings[uid] |= names
                else:
                    self.mappings[uid] -= names
                return httpx.Response(204)
            if sub == ["role-mappings", "realm", "available"]:
                return httpx.Response(200, json=[self._rep(n) for n in sorted(self.roles)
                                                 if n not in self.mappings[uid]])
            if sub[:2] == ["role-mappings", "clients"]:
                self.client_role_grants[uid] = [x["name"] for x in body]
                return httpx.Response(204)
        if parts == ["clients"]:
            cid = req.url.params.get("clientId")
            return httpx.Response(200, json=[{"id": self.clients[cid]}] if cid in self.clients else [])
        if parts[0] == "clients" and parts[2:] == ["service-account-user"]:
            if "sa-user" not in self.users:
                self.users["sa-user"] = {"id": "sa-user", "username": "service-account-agent"}
                self.mappings["sa-user"] = set()
            return httpx.Response(200, json={"id": "sa-user"})
        if parts[0] == "clients" and parts[2] == "roles":
            return httpx.Response(200, json={"id": f"rm-{parts[3]}", "name": parts[3]})
        return httpx.Response(404)


class FakeFGAClient:
    """openfga_sdk client stand-in: a tuple set behind write()/read() (real OpenFGAAuth runs)."""

    def __init__(self):
        self.tuples: set[tuple[str, str, str]] = set()   # (user, relation, object)
        self.fail = False

    async def write(self, req):
        if self.fail:
            raise RuntimeError("openfga down")
        for t in (req.writes or []):
            self.tuples.add((t.user, t.relation, t.object))
        for t in (req.deletes or []):
            self.tuples.discard((t.user, t.relation, t.object))

    async def read(self, key, opts=None):
        if self.fail:
            raise RuntimeError("openfga down")
        otype = key.object.rstrip(":")
        hits = sorted(t for t in self.tuples
                      if t[0] == key.user and t[2].split(":", 1)[0] == otype)
        # paginate in pages of 2 to exercise the continuation loop
        start = int((opts or {}).get("continuation_token") or 0)
        page = hits[start:start + 2]
        nxt = str(start + 2) if start + 2 < len(hits) else ""
        return SimpleNamespace(
            tuples=[SimpleNamespace(key=SimpleNamespace(user=u, relation=r, object=o))
                    for u, r, o in page],
            continuation_token=nxt)


class FakeRedis:
    def __init__(self):
        self.kv: dict = {}
        self.h: dict[str, dict] = {}
        self.down = False

    def _chk(self):
        if self.down:
            raise ConnectionError("redis down")

    async def get(self, k):
        self._chk()
        return self.kv.get(k)

    async def set(self, k, v):
        self._chk()
        self.kv[k] = v

    async def mget(self, *ks):
        self._chk()
        return [self.kv.get(k) for k in ks]

    async def incr(self, k):
        self.kv[k] = int(self.kv.get(k, 0)) + 1
        return self.kv[k]

    async def expire(self, k, ttl):
        return True

    async def hset(self, k, f, v):
        self.h.setdefault(k, {})[f] = v

    async def hgetall(self, k):
        return dict(self.h.get(k, {}))

    async def hdel(self, k, f):
        self.h.get(k, {}).pop(f, None)

    async def hlen(self, k):
        return len(self.h.get(k, {}))

    async def delete(self, *ks):
        for k in ks:
            self.h.pop(k, None)
            self.kv.pop(k, None)

    async def scan_iter(self, match):
        prefix = match.rstrip("*")
        for k in list(self.h):
            if k.startswith(prefix):
                yield k


class FakeTemporal:
    def __init__(self):
        self.signals: list[tuple[str, str, object]] = []

    def get_workflow_handle(self, wid):
        outer = self

        class _H:
            async def signal(self, name, arg):
                outer.signals.append((wid, name, arg))
        return _H()


def _req(body=None, temporal=None):
    class _R:
        app = SimpleNamespace(state=SimpleNamespace(temporal_client=temporal))

        async def json(self):
            return body
    return _R()


def _ns(iss=ISS_A):
    from auth.token_validator import issuer_namespace
    return issuer_namespace(iss)


def _p(email, iss=ISS_A):
    return f"{email}|{_ns(iss)}"


# ── fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def env(monkeypatch, tmp_path):
    """Division ALPHA agent wired to fake Keycloak/OpenFGA/Redis + a real audit chain."""
    import approval_index
    import audit_log
    import outcome_store
    from auth.openfga import OpenFGAAuth

    s = main.settings
    monkeypatch.setattr(s, "division_id", "alpha")
    monkeypatch.setattr(s, "oidc_issuer", ISS_A)
    monkeypatch.setattr(s, "oidc_jwks_uri", f"{ISS_A}/protocol/openid-connect/certs")
    monkeypatch.setattr(s, "agent_client_id", AUD_A)
    monkeypatch.setattr(s, "agent_client_secret", "test-agent-secret")
    monkeypatch.setattr(s, "principal_claim", "email")
    monkeypatch.setattr(s, "require_verified_principal", True)
    monkeypatch.setattr(s, "allowed_jwt_algorithms", "RS256")

    kc = FakeKeycloak()
    kc.add_user("bob", "bob@example.com", roles=("data-owner", "division-admin"))
    monkeypatch.setattr(main, "_kc_http_client",
                        lambda: httpx.AsyncClient(transport=httpx.MockTransport(kc.handler)))

    fga = OpenFGAAuth()
    fga._client = FakeFGAClient()

    async def get_fga():
        return fga
    monkeypatch.setattr(main.agent_nodes, "_get_openfga", get_fga)

    r = FakeRedis()

    async def get_redis():
        return r
    for mod in (main, approval_index, outcome_store):
        monkeypatch.setattr(mod, "_get_redis", get_redis)

    async def no_rl(subject, **kw):
        return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rl)

    # Real tamper-evident chain, hooked into structlog the way the app does at startup.
    chain = audit_log.AuditChain(tmp_path / "alpha_agent.jsonl")
    monkeypatch.setattr(audit_log, "_chain", chain)
    old = list(structlog.get_config()["processors"])
    procs = list(old)
    if audit_log._audit_processor not in procs:
        procs.insert(max(0, len(procs) - 1), audit_log._audit_processor)
    structlog.configure(processors=procs)
    yield SimpleNamespace(kc=kc, fga=fga, redis=r, chain=chain, tmp=tmp_path)
    structlog.configure(processors=old)


def _as(monkeypatch, claims):
    async def fake_bearer(auth):
        return ("tok", claims)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)


ADMIN = {"sub": "kc-bob", "email": "bob@example.com", "email_verified": True, "iss": ISS_A,
         "realm_access": {"roles": ["data-owner", "division-admin"]}}
MEMBER = {"sub": "kc-alice", "email": "alice@example.com", "email_verified": True, "iss": ISS_A,
          "realm_access": {"roles": ["member"]}}


def _audit(env, event):
    from audit_log import verify_chain
    ok, detail = verify_chain(env.chain.path)
    assert ok, detail
    return [e for e in (json.loads(x) for x in env.chain.path.read_text().splitlines() if x.strip())
            if e["event"] == event]


def _status(exc_info):
    return exc_info.value.status_code


# ── provision ──────────────────────────────────────────────────────────────────

def test_admin_provisions_user_with_roles_and_openfga_mirror(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    resp = asyncio.run(main.admin_provision_user(
        _req({"username": "carol", "email": "Carol@Example.com",
              "roles": ["member", "data-owner"], "password": "s3cret-pass"}),
        authorization="Bearer tok"))
    assert resp.status_code == 201
    body = json.loads(resp.body)
    carol = _p("carol@example.com")
    assert body["principal"] == carol and body["roles"] == ["data-owner", "member"]
    uid = body["keycloak_id"]
    assert env.kc.users[uid]["enabled"] is True
    assert env.kc.mappings[uid] >= {"member", "data-owner"}
    assert "division-admin" not in env.kc.mappings[uid]
    # OpenFGA mirror == Keycloak roles
    assert env.fga._client.tuples == {
        (f"user:{carol}", "member", "group:role-member"),
        (f"user:{carol}", "member", "group:role-data-owner"),
    }
    [entry] = _audit(env, "admin_user_provisioned")
    assert entry["data"]["user_id"] == carol
    assert entry["data"]["subject"] == _p("bob@example.com")
    assert entry["data"]["roles"] == ["data-owner", "member"]
    assert "password" not in json.dumps(entry)            # credentials never audited


def test_provision_existing_user_conflicts_and_bad_role_rejected(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_provision_user(
            _req({"username": "bob", "email": "bob@example.com"}), authorization="Bearer tok"))
    assert _status(ei) == 409
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_provision_user(
            _req({"username": "dave", "email": "d@example.com", "roles": ["realm-admin"]}),
            authorization="Bearer tok"))
    assert _status(ei) == 400
    assert env.fga._client.tuples == set()


# ── refusals: non-admin, foreign division ──────────────────────────────────────

def test_non_admin_refused_without_touching_keycloak(env, monkeypatch):
    _as(monkeypatch, MEMBER)
    env.kc.add_user("carol", "carol@example.com", roles=("member",))
    for call in (
        lambda: main.admin_provision_user(_req({"username": "x", "email": "x@example.com"}),
                                          authorization="Bearer tok"),
        lambda: main.admin_set_user_roles("carol", _req({"roles": ["division-admin"]}),
                                          authorization="Bearer tok"),
        lambda: main.admin_disable_user("carol", _req(), authorization="Bearer tok"),
        lambda: main.admin_enable_user("carol", _req(), authorization="Bearer tok"),
    ):
        with pytest.raises(main.HTTPException) as ei:
            asyncio.run(call())
        assert _status(ei) == 403
    assert env.kc.calls == []                      # no IdP call was ever made
    assert env.kc.mappings["kc-carol"] == {"member", "default-roles-rag"}


def _keypair(kid):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jose import jwk
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    j = jwk.construct(pub, "RS256").to_dict()
    j.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return priv, j


def _mint(priv, kid, iss, aud, sub, email, roles, iat_offset=0):
    now = int(time.time())
    return jwt.encode({"sub": sub, "iss": iss, "aud": aud, "iat": now + iat_offset,
                       "exp": now + 600,
                       "email": email, "email_verified": True,
                       "realm_access": {"roles": roles}},
                      priv, algorithm="RS256", headers={"kid": kid})


def _jwks(monkeypatch, *keys):
    from auth import token_validator as tv

    async def fake(force_refresh=False):
        return {"keys": list(keys)}
    monkeypatch.setattr(tv, "_get_jwks", fake)


def test_foreign_division_admin_token_refused(env, monkeypatch):
    """A BETA division-admin's real token is refused by ALPHA's lifecycle API (issuer +
    audience bound to alpha) — even with beta's key in alpha's JWKS — and no Keycloak call
    is made. Positive control: alpha's own admin token passes the same real validation."""
    priv_b, jwk_b = _keypair("beta-key")
    priv_a, jwk_a = _keypair("alpha-key")
    _jwks(monkeypatch, jwk_a, jwk_b)
    env.kc.add_user("carol", "carol@example.com", roles=("member",))
    beta_admin = _mint(priv_b, "beta-key", ISS_B, AUD_B, "kc-beta-admin",
                       "admin@beta.example.com", ["division-admin"])
    for call in (
        lambda: main.admin_provision_user(_req({"username": "x", "email": "x@example.com"}),
                                          authorization=f"Bearer {beta_admin}"),
        lambda: main.admin_set_user_roles("carol", _req({"roles": []}),
                                          authorization=f"Bearer {beta_admin}"),
        lambda: main.admin_disable_user("carol", _req(), authorization=f"Bearer {beta_admin}"),
        lambda: main.admin_enable_user("carol", _req(), authorization=f"Bearer {beta_admin}"),
    ):
        with pytest.raises(main.HTTPException) as ei:
            asyncio.run(call())
        assert _status(ei) == 401
    assert env.kc.calls == []

    # A beta token re-signed with ALPHA's key but still beta-issued is refused as well.
    forged = _mint(priv_a, "alpha-key", ISS_B, AUD_A, "kc-x", "admin@beta.example.com",
                   ["division-admin"])
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_disable_user("carol", _req(), authorization=f"Bearer {forged}"))
    assert _status(ei) == 401
    assert env.kc.calls == []

    alpha_admin = _mint(priv_a, "alpha-key", ISS_A, AUD_A, "kc-bob", "bob@example.com",
                        ["data-owner", "division-admin"])
    resp = asyncio.run(main.admin_set_user_roles("carol", _req({"roles": ["member"]}),
                                                 authorization=f"Bearer {alpha_admin}"))
    assert resp.status_code == 200
    assert env.kc.calls                                     # control reached the IdP


def test_keycloak_scope_is_this_divisions_realm_only(env):
    """The realm + credentials come from THIS division's config — there is no caller input
    that selects a realm. A service-account token request names alpha's own client."""
    from auth.keycloak_admin import split_realm_url
    assert split_realm_url(str(main.settings.oidc_jwks_uri)) == ("http://kc.alpha:8080", "rag")
    with pytest.raises(ValueError):
        split_realm_url("http://evil.example/other")


# ── roles ──────────────────────────────────────────────────────────────────────

def test_admin_sets_roles_keycloak_and_openfga_converge(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    uid = env.kc.add_user("carol", "carol@example.com", roles=("member",))
    carol = _p("carol@example.com")
    env.fga._client.tuples.add((f"user:{carol}", "member", "group:role-member"))
    resp = asyncio.run(main.admin_set_user_roles(
        "carol", _req({"roles": ["data-owner", "division-admin"]}), authorization="Bearer tok"))
    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["added"] == ["data-owner", "division-admin"] and body["removed"] == ["member"]
    assert env.kc.mappings[uid] == {"data-owner", "division-admin", "default-roles-rag"}
    assert env.fga._client.tuples == {
        (f"user:{carol}", "member", "group:role-data-owner"),
        (f"user:{carol}", "member", "group:role-division-admin"),
    }
    [entry] = _audit(env, "admin_user_roles_set")
    assert entry["data"]["roles"] == ["data-owner", "division-admin"]
    assert entry["data"]["cascade"] == {"added": ["data-owner", "division-admin"],
                                        "removed": ["member"]}


def test_admin_cannot_remove_own_admin_role_and_unknown_user_404(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_set_user_roles("bob", _req({"roles": ["member"]}),
                                              authorization="Bearer tok"))
    assert _status(ei) == 409
    assert "division-admin" in env.kc.mappings["kc-bob"]
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_set_user_roles("nobody", _req({"roles": ["member"]}),
                                              authorization="Bearer tok"))
    assert _status(ei) == 404


# ── disable cascade ────────────────────────────────────────────────────────────

def _seed_alice(env):
    import approval_index
    import outcome_store
    uid = env.kc.add_user("alice", "alice@example.com", roles=("member", "data-owner"))
    alice, bob, carol = _p("alice@example.com"), _p("bob@example.com"), _p("carol@example.com")
    t = env.fga._client.tuples
    t |= {
        (f"user:{alice}", "viewer", "chunk:c1"),
        (f"user:{alice}", "viewer", "chunk:c2"),               # e.g. a time-bound grant
        (f"user:{alice}", "pending_approval", "chunk:c3"),
        (f"user:{alice}", "editor", "chunk:c4"),
        (f"user:{alice}", "owner", "chunk:c9"),
        (f"user:{alice}", "member", "group:role-member"),
        (f"user:{alice}", "member", "group:role-data-owner"),
        (f"user:{bob}", "viewer", "chunk:c1"),                  # someone else — untouched
    }
    asyncio.run(approval_index.record(bob, "req-alice-1", alice, "q4 numbers?"))
    asyncio.run(approval_index.record(bob, "req-dave-1", _p("dave@example.com"), "other"))
    asyncio.run(approval_index.record(alice, "req-carol-1", carol, "alice's doc?"))
    asyncio.run(outcome_store.put(alice, "task-1", "q?", "denied", "no"))
    asyncio.run(outcome_store.bump_badge(alice))
    return uid, alice, bob, carol


def test_disable_cascades_everywhere_and_is_audited(env, monkeypatch):
    import approval_index
    import outcome_store
    _as(monkeypatch, ADMIN)
    uid, alice, bob, carol = _seed_alice(env)
    temporal = FakeTemporal()

    resp = asyncio.run(main.admin_disable_user("alice", _req(temporal=temporal),
                                               authorization="Bearer tok"))
    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["complete"] is True and body["enabled"] is False
    c = body["cascade"]
    # 1+2: denylist + Keycloak disabled + sessions revoked
    assert c["denylist"] == "ok" and c["keycloak"] == "ok"
    assert env.kc.users[uid]["enabled"] is False and env.kc.logouts == [uid]
    assert env.redis.kv.get(f"agt:disabled:alpha:{uid}")
    # 3: OpenFGA — access tuples gone, owner retained, others untouched
    assert c["openfga"] == {"viewer": 2, "editor": 1, "pending_approval": 1,
                            "group_member": 2, "owner_retained": 1}
    assert {x for x in env.fga._client.tuples if x[0] == f"user:{alice}"} == {
        (f"user:{alice}", "owner", "chunk:c9")}
    assert (f"user:{bob}", "viewer", "chunk:c1") in env.fga._client.tuples
    # 4: her own request is denied in Temporal (attributed to the admin) + withdrawn;
    #    the request awaiting HER decision stays pending; dave's request untouched.
    assert c["approvals"] == {"requested_withdrawn": 1, "denied_in_workflow": 1,
                              "pending_as_approver": 1}
    [(wid, name, sig)] = temporal.signals
    assert wid == "approval-req-alice-1" and name == "approval_decision"
    assert sig.decision == "denied" and sig.approver_id == bob
    bob_inbox = {x["request_id"] for x in asyncio.run(approval_index.list_for(bob))}
    assert bob_inbox == {"req-dave-1"}
    assert [x["request_id"] for x in asyncio.run(approval_index.list_for(alice))] == ["req-carol-1"]
    # 5: inbox purged
    assert c["inbox"] == {"purged": 1}
    assert asyncio.run(outcome_store.list_outcomes(alice, include_acknowledged=True)) == []

    [entry] = _audit(env, "admin_user_disabled")
    assert entry["data"]["user_id"] == alice and entry["data"]["subject"] == bob
    assert entry["data"]["cascade"]["openfga"]["owner_retained"] == 1


def test_disabled_users_still_valid_token_refused_next_request(env, monkeypatch):
    """Data access stops IMMEDIATELY: alice's already-issued (unexpired, correctly signed)
    token is refused by the real token path right after the disable — not at expiry."""
    priv, j = _keypair("alpha-key")
    _jwks(monkeypatch, j)
    uid = env.kc.add_user("alice", "alice@example.com", roles=("member",))
    alice_tok = _mint(priv, "alpha-key", ISS_A, AUD_A, uid, "alice@example.com", ["member"])
    admin_tok = _mint(priv, "alpha-key", ISS_A, AUD_A, "kc-bob", "bob@example.com",
                      ["data-owner", "division-admin"])
    # before: accepted
    _, claims = asyncio.run(main._get_bearer_token(f"Bearer {alice_tok}"))
    assert claims["sub"] == uid
    resp = asyncio.run(main.admin_disable_user("alice", _req(), authorization=f"Bearer {admin_tok}"))
    assert resp.status_code == 200
    # after: the same token is refused
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main._get_bearer_token(f"Bearer {alice_tok}"))
    assert _status(ei) == 401 and ei.value.detail == "Account disabled"
    assert _audit(env, "disabled_account_refused")
    # and an unrelated user still works
    _, claims = asyncio.run(main._get_bearer_token(f"Bearer {admin_tok}"))
    assert claims["sub"] == "kc-bob"


def test_denylist_store_down_fails_closed(env, monkeypatch):
    priv, j = _keypair("alpha-key")
    _jwks(monkeypatch, j)
    tok = _mint(priv, "alpha-key", ISS_A, AUD_A, "kc-bob", "bob@example.com", ["member"])
    env.redis.down = True
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main._get_bearer_token(f"Bearer {tok}"))
    assert _status(ei) == 503


def test_disable_self_conflict_and_unknown_404(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_disable_user("bob", _req(), authorization="Bearer tok"))
    assert _status(ei) == 409
    assert env.kc.users["kc-bob"]["enabled"] is True
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_disable_user("ghost", _req(), authorization="Bearer tok"))
    assert _status(ei) == 404


def test_partial_cascade_reports_502_and_rerun_completes(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    uid, alice, _, _ = _seed_alice(env)
    env.fga._client.fail = True
    resp = asyncio.run(main.admin_disable_user("alice", _req(), authorization="Bearer tok"))
    assert resp.status_code == 502
    body = json.loads(resp.body)
    assert body["complete"] is False and body["cascade"]["openfga"].startswith("failed")
    assert body["cascade"]["denylist"] == "ok" and env.kc.users[uid]["enabled"] is False
    assert _audit(env, "admin_user_disable_incomplete")
    # idempotent re-run finishes the job
    env.fga._client.fail = False
    resp = asyncio.run(main.admin_disable_user("alice", _req(), authorization="Bearer tok"))
    assert resp.status_code == 200
    assert {x for x in env.fga._client.tuples if x[0] == f"user:{alice}"} == {
        (f"user:{alice}", "owner", "chunk:c9")}


def test_roles_refused_for_disabled_user(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    env.kc.add_user("erin", "erin@example.com", roles=("member",), enabled=False)
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_set_user_roles("erin", _req({"roles": ["division-admin"]}),
                                              authorization="Bearer tok"))
    assert _status(ei) == 409
    assert env.fga._client.tuples == set()


# ── re-enable ──────────────────────────────────────────────────────────────────

def _alice_tuples(env, alice):
    return {x for x in env.fga._client.tuples if x[0] == f"user:{alice}"}


def test_enable_restores_roles_from_keycloak_not_old_grants(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    uid, alice, bob, _ = _seed_alice(env)
    assert asyncio.run(main.admin_disable_user("alice", _req(temporal=FakeTemporal()),
                                               authorization="Bearer tok")).status_code == 200
    # While disabled, an admin drops data-owner in Keycloak: the CURRENT roles win on enable.
    env.kc.mappings[uid].discard("data-owner")

    resp = asyncio.run(main.admin_enable_user("alice", _req(), authorization="Bearer tok"))
    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["complete"] is True and body["enabled"] is True and body["was_enabled"] is False
    assert body["roles"] == ["member"]
    assert body["cascade"] == {"keycloak": "ok", "openfga": {"roles_restored": ["member"]},
                               "denylist": "ok"}
    assert env.kc.users[uid]["enabled"] is True
    assert f"agt:disabled:alpha:{uid}" not in env.redis.kv
    # role mirror == current Keycloak roles; viewer/editor/pending grants NOT resurrected;
    # owner tuple (retained by the disable) still there.
    assert _alice_tuples(env, alice) == {
        (f"user:{alice}", "member", "group:role-member"),
        (f"user:{alice}", "owner", "chunk:c9"),
    }
    [entry] = _audit(env, "admin_user_enabled")
    assert entry["data"]["user_id"] == alice and entry["data"]["subject"] == bob
    assert entry["data"]["action"] == "enable" and entry["data"]["roles"] == ["member"]
    assert entry["data"]["cascade"]["denylist"] == "ok"


def test_enable_is_idempotent(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    uid, alice, _, _ = _seed_alice(env)
    asyncio.run(main.admin_disable_user("alice", _req(), authorization="Bearer tok"))
    first = asyncio.run(main.admin_enable_user("alice", _req(), authorization="Bearer tok"))
    tuples_after_first = _alice_tuples(env, alice)
    again = asyncio.run(main.admin_enable_user("alice", _req(), authorization="Bearer tok"))
    assert first.status_code == again.status_code == 200
    b = json.loads(again.body)
    assert b["complete"] is True and b["was_enabled"] is True
    assert b["roles"] == ["data-owner", "member"]
    assert _alice_tuples(env, alice) == tuples_after_first == {
        (f"user:{alice}", "member", "group:role-member"),
        (f"user:{alice}", "member", "group:role-data-owner"),
        (f"user:{alice}", "owner", "chunk:c9"),
    }
    assert env.kc.users[uid]["enabled"] is True
    assert len(_audit(env, "admin_user_enabled")) == 2


def test_enable_partial_failure_502_and_rerun_completes(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    uid, alice, _, _ = _seed_alice(env)
    asyncio.run(main.admin_disable_user("alice", _req(), authorization="Bearer tok"))
    env.fga._client.fail = True
    resp = asyncio.run(main.admin_enable_user("alice", _req(), authorization="Bearer tok"))
    assert resp.status_code == 502
    b = json.loads(resp.body)
    assert b["complete"] is False and b["cascade"]["openfga"].startswith("failed")
    assert b["cascade"]["keycloak"] == "ok" and b["cascade"]["denylist"] == "ok"
    assert _audit(env, "admin_user_enable_incomplete")
    env.fga._client.fail = False
    resp = asyncio.run(main.admin_enable_user("alice", _req(), authorization="Bearer tok"))
    assert resp.status_code == 200
    assert (f"user:{alice}", "member", "group:role-data-owner") in env.fga._client.tuples


def test_enable_keycloak_failure_keeps_denylist(env, monkeypatch):
    """If the IdP step fails, the denylist is NOT cleared (no re-admit of old tokens for an
    account Keycloak still holds disabled) and the role mirror is not touched → 502."""
    _as(monkeypatch, ADMIN)
    uid, alice, _, _ = _seed_alice(env)
    asyncio.run(main.admin_disable_user("alice", _req(), authorization="Bearer tok"))
    real = env.kc.handler

    def flaky(req):
        if req.method == "PUT" and req.url.path.endswith(f"/users/{uid}"):
            return httpx.Response(500)
        return real(req)
    monkeypatch.setattr(main, "_kc_http_client",
                        lambda: httpx.AsyncClient(transport=httpx.MockTransport(flaky)))
    resp = asyncio.run(main.admin_enable_user("alice", _req(), authorization="Bearer tok"))
    assert resp.status_code == 502
    c = json.loads(resp.body)["cascade"]
    assert c["keycloak"].startswith("failed")
    assert c["openfga"] == c["denylist"] == "skipped:keycloak_failed"
    assert env.redis.kv.get(f"agt:disabled:alpha:{uid}")
    assert env.kc.users[uid]["enabled"] is False
    assert _alice_tuples(env, alice) == {(f"user:{alice}", "owner", "chunk:c9")}


def test_enabled_users_new_token_accepted_after_reenable(env, monkeypatch):
    """End-to-end through the real token path: refused while disabled, a NEW token minted
    after the re-enable is accepted on the next request."""
    priv, j = _keypair("alpha-key")
    _jwks(monkeypatch, j)
    uid = env.kc.add_user("alice", "alice@example.com", roles=("member",))
    admin_tok = _mint(priv, "alpha-key", ISS_A, AUD_A, "kc-bob", "bob@example.com",
                      ["data-owner", "division-admin"])
    old_tok = _mint(priv, "alpha-key", ISS_A, AUD_A, uid, "alice@example.com", ["member"])
    asyncio.run(main.admin_disable_user("alice", _req(), authorization=f"Bearer {admin_tok}"))
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main._get_bearer_token(f"Bearer {old_tok}"))
    assert _status(ei) == 401 and ei.value.detail == "Account disabled"

    resp = asyncio.run(main.admin_enable_user("alice", _req(), authorization=f"Bearer {admin_tok}"))
    assert resp.status_code == 200
    new_tok = _mint(priv, "alpha-key", ISS_A, AUD_A, uid, "alice@example.com", ["member"])
    _, claims = asyncio.run(main._get_bearer_token(f"Bearer {new_tok}"))
    assert claims["sub"] == uid


def test_enable_self_conflict_and_unknown_404(env, monkeypatch):
    _as(monkeypatch, ADMIN)
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_enable_user("bob", _req(), authorization="Bearer tok"))
    assert _status(ei) == 409
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.admin_enable_user("ghost", _req(), authorization="Bearer tok"))
    assert _status(ei) == 404
    assert env.fga._client.tuples == set()


# ── onboarding reuses the same Keycloak client ─────────────────────────────────

def test_onboarding_uses_shared_keycloak_helpers():
    from scripts import onboard_division as od
    kc = FakeKeycloak()
    kc.roles = {"default-roles-rag": "r-default"}

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(kc.handler)) as c:
            h = {"Authorization": f"Bearer {kc.token}"}
            await od._kc_ensure_user(c, "http://kc", h, "alice", "alice@example.com", "pw-123456")
            await od._kc_setup_roles(c, "http://kc", h, {"alice": ["member"]})
            from auth import keycloak_admin as ka
            await ka.grant_user_admin_to_service_account(c, "http://kc", "rag", h, "agent-alpha")
    asyncio.run(go())
    assert set(kc.roles) >= {"member", "data-owner", "division-admin"}
    assert kc.mappings["kc-alice"] >= {"member"}
    assert kc.client_role_grants["sa-user"] == ["manage-users", "view-users", "query-users"]


def test_pre_disable_token_stays_dead_after_reenable(env, monkeypatch):
    """Re-enable must NOT resurrect a token minted before it (e.g. the stolen token that
    prompted the disable): enable writes a not-before marker; older tokens -> 401."""
    priv, j = _keypair("alpha-key")
    _jwks(monkeypatch, j)
    uid = env.kc.add_user("alice", "alice@example.com", roles=("member",))
    admin_tok = _mint(priv, "alpha-key", ISS_A, AUD_A, "kc-bob", "bob@example.com",
                      ["data-owner", "division-admin"])
    stolen = _mint(priv, "alpha-key", ISS_A, AUD_A, uid, "alice@example.com", ["member"],
                   iat_offset=-120)   # minted well before the disable/enable
    asyncio.run(main.admin_disable_user("alice", _req(), authorization=f"Bearer {admin_tok}"))
    resp = asyncio.run(main.admin_enable_user("alice", _req(), authorization=f"Bearer {admin_tok}"))
    assert resp.status_code == 200

    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main._get_bearer_token(f"Bearer {stolen}"))
    assert _status(ei) == 401 and ei.value.detail == "Token predates account re-enable"

    fresh = _mint(priv, "alpha-key", ISS_A, AUD_A, uid, "alice@example.com", ["member"])
    _, claims = asyncio.run(main._get_bearer_token(f"Bearer {fresh}"))
    assert claims["sub"] == uid


def test_not_before_marker_semantics():
    """Unit-level: no iat on a re-enabled account fails closed; never-disabled users are
    unaffected; the store being down still fails closed (503)."""
    r = FakeRedis()

    async def _get_redis():
        return r

    orig = main._get_redis
    main._get_redis = _get_redis
    try:
        assert asyncio.run(main._account_refusal("u1", 1000)) is None          # never disabled
        r.kv[main._not_before_key("u1")] = "2000"
        assert asyncio.run(main._account_refusal("u1", 1999)) == "stale_token"
        assert asyncio.run(main._account_refusal("u1", 2000)) is None
        assert asyncio.run(main._account_refusal("u1", None)) == "stale_token"  # no iat
        r.kv[main._disabled_key("u1")] = "3000"
        assert asyncio.run(main._account_refusal("u1", 9999)) == "disabled"
        r.down = True
        with pytest.raises(main.HTTPException) as ei:
            asyncio.run(main._account_refusal("u1", 9999))
        assert _status(ei) == 503
    finally:
        main._get_redis = orig
