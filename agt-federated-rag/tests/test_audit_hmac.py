"""HMAC-keyed audit chain tests (THREAT_MODEL §4.1: tamper-EVIDENT → tamper-PROOF).

The keyless chain (test_audit.py) is only tamper-EVIDENT: a host-compromise attacker who owns
the file can recompute a forged chain (and the sidecar anchor) because nothing in the link is
secret. When an HMAC key — resolved from the secrets backend (``AUDIT_HMAC_KEY``, e.g. a
``vault:`` ref) — is configured, the link is keyed, so a forged keyless chain (even one
re-rooted at genesis and recomputed end-to-end, the red-team's attack) FAILS verification
without the key.

These pin: (1) a keyed chain verifies with the right key; (2) it FAILS with a wrong key and
with no/keyless verification; (3) the forged-but-genesis-rooted keyless chain is rejected when
keyed; (4) BACKWARD-COMPAT — with no key configured the behaviour is byte-for-byte the keyless
chain. Hermetic (tmp files + monkeypatched env only).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

KEY = b"super-secret-audit-signing-key"
WRONG = b"not-the-key"


def test_keyed_chain_verifies_with_right_key(tmp_path: Path):
    from audit_log import AuditChain, verify_chain
    c = AuditChain(tmp_path / "alpha_agent.jsonl", hmac_key=KEY)
    c.append("auth_decision", {"flow": "local_allowed", "user_id": "alice|ns"})
    c.append("openfga.write_tuple", {"relation": "viewer", "chunk_id": "abc"})
    ok, detail = verify_chain(c.path, key=KEY)
    assert ok, detail
    assert "2 entries" in detail


def test_keyed_chain_fails_with_wrong_key(tmp_path: Path):
    from audit_log import AuditChain, verify_chain
    c = AuditChain(tmp_path / "alpha_agent.jsonl", hmac_key=KEY)
    c.append("evt", {"count": 0})
    c.append("evt", {"count": 1})
    ok, detail = verify_chain(c.path, key=WRONG)
    assert not ok and "hash mismatch" in detail


def test_keyed_chain_fails_when_verified_keyless(tmp_path: Path):
    # A keyed chain verified WITHOUT the key (keyless) must fail — the HMAC hashes are not the
    # plain SHA256 a keyless verifier recomputes. (key=None forces keyless verification.)
    from audit_log import AuditChain, verify_chain
    c = AuditChain(tmp_path / "alpha_agent.jsonl", hmac_key=KEY)
    c.append("evt", {"count": 0})
    ok, detail = verify_chain(c.path, key=None)
    assert not ok and "hash mismatch" in detail


def _forge_keyless_chain(path: Path, events: list[tuple[str, dict]]) -> None:
    """Write a fully-valid KEYLESS (SHA256) chain rooted at genesis — exactly what a host-
    compromise attacker produces when they rewrite the audit file from scratch."""
    import time
    GENESIS = "0" * 64
    prev = GENESIS
    lines = []
    for seq, (event, data) in enumerate(events):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        norm = json.loads(json.dumps(data, default=str))
        canonical = json.dumps(norm, sort_keys=True, separators=(",", ":"), default=str)
        msg = f"{seq}|{ts}|{event}|{canonical}|{prev}".encode("utf-8")
        h = hashlib.sha256(msg).hexdigest()          # KEYLESS — the attacker has no key
        rec = {"seq": seq, "ts": ts, "event": event, "data": norm, "prev_hash": prev, "hash": h}
        lines.append(json.dumps(rec))
        prev = h
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_forged_genesis_rooted_keyless_chain_rejected_when_keyed(tmp_path: Path):
    # THE red-team attack: the attacker deletes the real trail and writes a clean, internally
    # consistent KEYLESS chain from genesis (so every keyless check — seq, prev_hash, hash —
    # passes). With a key, verify_chain recomputes HMACs that don't match the attacker's
    # SHA256 hashes → rejected. Without the key it would (and does, keyless) wrongly pass.
    from audit_log import verify_chain
    p = tmp_path / "alpha_agent.jsonl"
    _forge_keyless_chain(p, [("auth_decision", {"allowed": True}),
                             ("auth_decision", {"allowed": True})])
    ok_keyless, _ = verify_chain(p, key=None)        # the attack succeeds against a keyless verifier
    assert ok_keyless                                # (demonstrates WHY a key is needed)
    ok_keyed, detail = verify_chain(p, key=KEY)      # but fails the moment a key is required
    assert not ok_keyed and "hash mismatch" in detail


def test_no_key_is_byte_for_byte_keyless(tmp_path: Path):
    # BACKWARD-COMPAT: a chain built with NO key is identical to the legacy keyless chain and
    # verifies keyless. Pin the exact genesis hash so a future change to the keyless preimage
    # (which would silently invalidate every existing on-disk chain) is caught.
    from audit_log import AuditChain, verify_chain
    c = AuditChain(tmp_path / "beta_agent.jsonl")    # no hmac_key
    rec = c.append("evt", {"count": 0})
    GENESIS = "0" * 64
    canonical = json.dumps({"count": 0}, sort_keys=True, separators=(",", ":"))
    msg = f"0|{rec['ts']}|evt|{canonical}|{GENESIS}".encode("utf-8")
    assert rec["hash"] == hashlib.sha256(msg).hexdigest()
    ok, _ = verify_chain(c.path)                     # default resolution, no env key → keyless
    assert ok


def test_env_ref_resolves_key_via_backend(tmp_path: Path, monkeypatch):
    # The default (no explicit key) resolution path: AUDIT_HMAC_KEY is read from the env, and a
    # vault: ref is resolved through the secrets backend (EnvFileBackend exercises the same
    # indirection with no real vault). Both AuditChain.append and verify_chain pick it up.
    from audit_log import AuditChain, verify_chain
    # Backend resolves vault:secret/agt#audit_hmac -> SECRET_AGT__AUDIT_HMAC env var.
    monkeypatch.setenv("AUDIT_HMAC_KEY", "vault:secret/agt#audit_hmac")
    monkeypatch.setenv("SECRET_AGT__AUDIT_HMAC", "key-from-backend")
    c = AuditChain(tmp_path / "alpha_agent.jsonl")   # resolves the env ref in __init__
    c.append("evt", {"count": 0})
    ok, _ = verify_chain(c.path)                      # default resolution finds the same key
    assert ok
    # The same chain fails once the configured key is removed (keyed verifier, no key now).
    monkeypatch.delenv("AUDIT_HMAC_KEY")
    ok2, _ = verify_chain(c.path)                      # now resolves to keyless → mismatch
    assert not ok2


def test_unresolvable_ref_fails_loud(tmp_path: Path, monkeypatch):
    # A configured-but-unresolvable key ref must RAISE (fail loud), not silently fall back to
    # keyless — that would be a security downgrade.
    from audit_log import resolve_audit_hmac_key
    monkeypatch.setenv("AUDIT_HMAC_KEY", "vault:secret/agt#missing")
    # no SECRET_AGT__MISSING env → EnvFileBackend.get returns None → resolve_secret raises
    with pytest.raises(ValueError):
        resolve_audit_hmac_key()


def test_keyed_chain_still_detects_inplace_tamper(tmp_path: Path):
    # Sanity: keying doesn't lose the existing tamper-evidence — an in-place field edit is still
    # caught (here the attacker has the file but NOT the key).
    from audit_log import AuditChain, verify_chain
    p = tmp_path / "alpha_agent.jsonl"
    c = AuditChain(p, hmac_key=KEY)
    c.append("auth_decision", {"allowed": False})
    lines = p.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["data"]["allowed"] = True
    lines[0] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    ok, detail = verify_chain(p, key=KEY)
    assert not ok and "hash mismatch" in detail
