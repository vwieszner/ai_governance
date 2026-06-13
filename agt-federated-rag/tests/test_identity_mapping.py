"""Phase-1 identity adapter tests: configurable claim mapping + group grants.

Proves the template works against any OIDC IdP (not just Keycloak's email/email_verified)
and that IdP group memberships flow into OpenFGA as LIVE contextual `group#member` tuples
(so a doc granted to a user's group is allowed, and leaving the group revokes on the next
token — no persisted membership).
"""
from __future__ import annotations

import pytest

from auth import token_validator as tv
from auth.token_validator import extract_groups, principal


# ── Configurable principal claim (any-IdP support) ─────────────────────────────

def test_default_principal_is_email_verified():
    # Default config = Keycloak hardened posture: email + email_verified required.
    p = principal({"iss": "http://idp/realms/rag", "email": "Alice@Example.com",
                   "email_verified": True, "sub": "x"})
    assert p.startswith("alice@example.com|")
    with pytest.raises(ValueError):
        principal({"iss": "http://idp/realms/rag", "email": "a@b.com", "email_verified": False})


def test_principal_claim_configurable_for_entra_style_token(monkeypatch):
    # Entra-style: subject is `preferred_username`, no email_verified emitted.
    monkeypatch.setattr(tv.settings, "principal_claim", "preferred_username")
    monkeypatch.setattr(tv.settings, "require_verified_principal", False)
    claims = {"iss": "https://login.microsoftonline.com/t/v2.0",
              "preferred_username": "Bob@corp.com", "oid": "guid-123"}
    p = principal(claims)
    assert p.startswith("bob@corp.com|")
    # still namespaced by issuer (16-hex)
    assert len(p.split("|")[1]) == 16


def test_principal_missing_configured_claim_raises(monkeypatch):
    monkeypatch.setattr(tv.settings, "principal_claim", "upn")
    monkeypatch.setattr(tv.settings, "require_verified_principal", False)
    with pytest.raises(ValueError):
        principal({"iss": "http://idp", "email": "a@b.com"})  # no 'upn' claim


# ── Group claim extraction ─────────────────────────────────────────────────────

def test_extract_groups_list_and_keycloak_paths():
    # Keycloak emits group PATHS like "/finance"; the leading slash is stripped.
    assert extract_groups({"groups": ["/finance", "engineering", "  /hr/leads  "]}) == [
        "finance", "engineering", "hr/leads",
    ]


def test_extract_groups_accepts_single_string_and_handles_missing():
    assert extract_groups({"groups": "admins"}) == ["admins"]
    assert extract_groups({}) == []                       # no claim -> opt-in, no groups
    assert extract_groups({"groups": []}) == []
    assert extract_groups({"groups": 123}) == []          # malformed -> [], never raises


def test_groups_claim_name_configurable(monkeypatch):
    monkeypatch.setattr(tv.settings, "groups_claim", "roles")
    assert extract_groups({"roles": ["finance"], "groups": ["ignored"]}) == ["finance"]


# ── Group membership becomes a contextual tuple (not persisted) ────────────────

def test_group_contextual_tuples_built_from_user_groups():
    from auth.openfga import OpenFGAAuth
    auth = OpenFGAAuth()                       # no _init: pure helper, no client needed
    tuples = auth._group_contextual_tuples("alice@example.com|ns", ["finance", "hr"])
    assert len(tuples) == 2
    users = {t.user for t in tuples}
    objs = {t.object for t in tuples}
    rels = {t.relation for t in tuples}
    assert users == {"user:alice@example.com|ns"}        # prefixed once
    assert objs == {"group:finance", "group:hr"}
    assert rels == {"member"}


def test_no_groups_means_no_contextual_tuples():
    from auth.openfga import OpenFGAAuth
    auth = OpenFGAAuth()
    assert auth._group_contextual_tuples("u", []) == []
    assert auth._group_contextual_tuples("u", None) == []


def test_check_passes_contextual_tuples_when_groups_present():
    # Prove check() actually attaches the group membership to the OpenFGA request,
    # so a group#member grant can resolve. Mock the SDK client.
    import asyncio
    from auth.openfga import OpenFGAAuth, Relation

    captured = {}

    class _Resp:
        allowed = True

    class _FakeClient:
        async def check(self, body):
            captured["body"] = body
            return _Resp()

    auth = OpenFGAAuth()
    auth._client = _FakeClient()
    ok = asyncio.run(auth.check("alice|ns", "chunk1", Relation.VIEWER, groups=["finance"]))
    assert ok is True
    body = captured["body"]
    assert body.contextual_tuples is not None
    assert any(t.object == "group:finance" and t.relation == "member"
               for t in body.contextual_tuples)


def test_check_without_groups_sends_no_contextual_tuples():
    import asyncio
    from auth.openfga import OpenFGAAuth, Relation

    captured = {}

    class _Resp:
        allowed = False

    class _FakeClient:
        async def check(self, body):
            captured["body"] = body
            return _Resp()

    auth = OpenFGAAuth()
    auth._client = _FakeClient()
    asyncio.run(auth.check("alice|ns", "chunk1", Relation.VIEWER))
    assert captured["body"].contextual_tuples is None
