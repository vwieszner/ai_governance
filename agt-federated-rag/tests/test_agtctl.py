"""agtctl CLI helper tests (Phase-1 item 12).

Pins the security-load-bearing pure helpers: the principal must be byte-identical to the
runtime/seed principal (or grants miss), and subject refs must form correct OpenFGA
user/group strings. (Live grant/revoke/list/status hit infra and are exercised manually.)
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("agtctl", _ROOT / "scripts" / "agtctl.py")
agtctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agtctl)

ISS = "http://localhost:9002/realms/rag"


def test_principal_matches_runtime_token_validator():
    import sys
    sys.path.insert(0, str(_ROOT / "agt-federated-rag"))
    from auth.token_validator import principal as rt_principal
    # agtctl.principal(email, issuer) must equal token_validator.principal(claims)
    assert agtctl.principal("Alice@Example.com", ISS) == rt_principal(
        {"email": "alice@example.com", "email_verified": True, "iss": ISS})


def test_subject_ref_user_and_group():
    assert agtctl.subject_ref("user", "alice@example.com", ISS) == f"user:{agtctl.principal('alice@example.com', ISS)}"
    assert agtctl.subject_ref("group", "finance", None) == "group:finance#member"
    assert agtctl.subject_ref("group", "group:hr#member", None) == "group:hr#member"


def test_user_subject_requires_issuer():
    with pytest.raises(ValueError):
        agtctl.subject_ref("user", "alice@example.com", None)


def test_cli_parses_grant_and_defaults_home(monkeypatch):
    # `grant --user` with no --home defaults home to --division (single-division grant).
    captured = {}
    def fake_grant(args):
        captured["division"] = args.division
        captured["home"] = args.home
        captured["user"] = args.user
        return 0
    monkeypatch.setattr(agtctl, "cmd_grant", fake_grant)
    # rebuild parser so it binds the patched func
    rc = agtctl.main(["grant", "--division", "beta", "--user", "alice@example.com", "--doc", "q4"])
    assert rc == 0
    assert captured["home"] == "beta"        # defaulted
