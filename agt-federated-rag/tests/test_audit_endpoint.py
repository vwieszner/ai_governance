"""GET /audit — admin-queryable, division-scoped tamper-evident export (FR-8.1 / NFR-9).

Pins the three contracts the endpoint must hold:
  * a division admin gets the division's chain entries + a chain-verification status;
  * a non-admin (valid token, no division-admin role) is refused with 403;
  * the export is division-SCOPED — it reads only settings.division_id's own chains,
    never a peer division's <other>_*.jsonl trail (NFR-2 isolation).

Hermetic: the route handler is called directly with _get_bearer_token / _check_rate_limit
stubbed (the conftest Settings factory is unused here — we drive the handler, not the app).
The audit chains are real files written by audit_log.AuditChain, so verify_chain runs for real.
"""
from __future__ import annotations

import asyncio

import pytest

from api import main

# A division admin and a plain member, distinguished only by the realm role they carry.
_ADMIN_CLAIMS = {
    "sub": "kc-admin", "email": "bob@example.com", "email_verified": True,
    "iss": "http://localhost:9002/realms/rag",
    "realm_access": {"roles": ["data-owner", "division-admin"]},
}
_MEMBER_CLAIMS = {
    "sub": "kc-member", "email": "alice@example.com", "email_verified": True,
    "iss": "http://localhost:9002/realms/rag",
    "realm_access": {"roles": ["member"]},
}


def _patch_bearer(monkeypatch, claims):
    async def fake_bearer(auth):
        return ("tok", claims)
    monkeypatch.setattr(main, "_get_bearer_token", fake_bearer)

    async def no_rate_limit(subject):
        return None
    monkeypatch.setattr(main, "_check_rate_limit", no_rate_limit)


def _call_audit(event=None, limit=500):
    # Direct handler call: Query() defaults are sentinels, so pass the real values
    # explicitly (the same convention test_metrics uses for Header()).
    return asyncio.run(main.get_audit(authorization="Bearer tok", event=event, limit=limit))


def _seed_chain(base, division, role, events):
    """Write a real hash-chained audit file <division>_<role>.jsonl under base."""
    import audit_log
    chain = audit_log.AuditChain(base / f"{division}_{role}.jsonl")
    for ev, data in events:
        chain.append(ev, data)


def test_admin_gets_chain_and_verify_status(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    monkeypatch.setattr(main.settings, "audit_log_dir", str(tmp_path))
    _seed_chain(tmp_path, "alpha", "agent",
                [("auth_decision", {"allowed": True, "user_id": "alice|ns"}),
                 ("access_revoked", {"chunk_id": "c-1", "decision": "revoked"})])
    _patch_bearer(monkeypatch, _ADMIN_CLAIMS)

    resp = _call_audit()
    assert resp.status_code == 200
    import json
    body = json.loads(bytes(resp.body).decode())
    assert body["division"] == "alpha"
    assert body["verified"] is True                      # untampered chain verifies
    assert body["count"] == 2
    events = [e["event"] for e in body["entries"]]
    assert "auth_decision" in events and "access_revoked" in events
    # the verification status is surfaced per-chain too
    assert body["chains"] and all(c["ok"] for c in body["chains"])


def test_non_admin_forbidden_403(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    monkeypatch.setattr(main.settings, "audit_log_dir", str(tmp_path))
    _seed_chain(tmp_path, "alpha", "agent", [("auth_decision", {"allowed": True})])
    _patch_bearer(monkeypatch, _MEMBER_CLAIMS)            # valid token, NOT an admin

    with pytest.raises(main.HTTPException) as ei:
        _call_audit()
    assert ei.value.status_code == 403


def test_export_is_division_scoped(monkeypatch, tmp_path):
    # alpha admin must see ONLY alpha's chains, never beta's (NFR-2 isolation).
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    monkeypatch.setattr(main.settings, "audit_log_dir", str(tmp_path))
    _seed_chain(tmp_path, "alpha", "agent", [("auth_decision", {"allowed": True})])
    _seed_chain(tmp_path, "beta", "agent",
                [("peer_secret", {"user_id": "carol|other"}),
                 ("peer_secret2", {"user_id": "dave|other"})])
    _patch_bearer(monkeypatch, _ADMIN_CLAIMS)

    import json
    body = json.loads(bytes(_call_audit().body).decode())
    assert body["count"] == 1                             # only alpha's single entry
    assert all("peer_secret" not in e["event"] for e in body["entries"])
    assert all(c["file"].startswith("alpha_") for c in body["chains"])


def test_admin_via_groups_claim_also_accepted(monkeypatch, tmp_path):
    # The role can arrive through the configured groups/roles claim instead of realm_access.
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    monkeypatch.setattr(main.settings, "audit_log_dir", str(tmp_path))
    monkeypatch.setattr(main.settings, "recognized_groups", "")   # accept any group
    _seed_chain(tmp_path, "alpha", "agent", [("auth_decision", {"allowed": True})])
    claims = {"sub": "kc-x", "email": "bob@example.com", "email_verified": True,
              "iss": "http://localhost:9002/realms/rag", "groups": ["division-admin"]}
    _patch_bearer(monkeypatch, claims)

    resp = _call_audit()
    assert resp.status_code == 200


def test_event_filter(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    monkeypatch.setattr(main.settings, "audit_log_dir", str(tmp_path))
    _seed_chain(tmp_path, "alpha", "agent",
                [("auth_decision", {"allowed": True}),
                 ("access_revoked", {"chunk_id": "c-1"}),
                 ("auth_decision", {"allowed": False})])
    _patch_bearer(monkeypatch, _ADMIN_CLAIMS)

    import json
    body = json.loads(bytes(_call_audit(event="auth_decision").body).decode())
    assert body["count"] == 2
    assert {e["event"] for e in body["entries"]} == {"auth_decision"}


def test_tampered_chain_reported_not_500(monkeypatch, tmp_path):
    # A tampered trail must still EXPORT (so the admin sees the break) with verified=False.
    monkeypatch.setattr(main.settings, "division_id", "alpha")
    monkeypatch.setattr(main.settings, "audit_log_dir", str(tmp_path))
    _seed_chain(tmp_path, "alpha", "agent",
                [("auth_decision", {"user_id": "alice|ns"}), ("access_revoked", {"chunk_id": "c-1"})])
    # Corrupt the first line's data field (without touching its stored hash) so the
    # recomputed hash no longer matches — verify_chain must flag it.
    f = tmp_path / "alpha_agent.jsonl"
    lines = f.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("alice|ns", "mallory|ns")
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _patch_bearer(monkeypatch, _ADMIN_CLAIMS)

    import json
    body = json.loads(bytes(_call_audit().body).decode())
    assert body["verified"] is False                     # tamper detected, still returned 200
