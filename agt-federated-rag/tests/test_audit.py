"""Tamper-evident audit-chain tests (IMPLEMENTATION_PLAN.md M8).

Pins the security property: any modification, deletion, reorder, or truncation of a
past audit entry is DETECTED by verify_chain. Also pins cross-restart continuation and
the structlog-processor capture of agt_audit=True events. Hermetic (tmp files only).
"""
from __future__ import annotations

import json
from pathlib import Path


def test_append_and_verify_ok(tmp_path: Path):
    from audit_log import AuditChain, verify_chain
    c = AuditChain(tmp_path / "beta_agent.jsonl")
    c.append("auth_decision", {"flow": "local_allowed", "user_id": "alice@x|ns"})
    c.append("openfga.write_tuple", {"relation": "viewer", "chunk_id": "abc"})
    c.append("approval_workflow_approved", {"request_id": "r1"})
    ok, detail = verify_chain(c.path)
    assert ok, detail
    assert "3 entries" in detail


def test_detects_tampered_field(tmp_path: Path):
    from audit_log import AuditChain, verify_chain
    p = tmp_path / "beta_agent.jsonl"
    c = AuditChain(p)
    c.append("auth_decision", {"flow": "local_denied", "allowed": 0})
    c.append("auth_decision", {"flow": "local_allowed", "allowed": 1})
    # Tamper: flip a denied decision to allowed in the stored data (hash won't match).
    lines = p.read_text().splitlines()
    rec = json.loads(lines[0]); rec["data"]["allowed"] = 1
    lines[0] = json.dumps(rec); p.write_text("\n".join(lines) + "\n")
    ok, detail = verify_chain(p)
    assert not ok and "hash mismatch" in detail


def test_detects_deletion(tmp_path: Path):
    from audit_log import AuditChain, verify_chain
    p = tmp_path / "beta_agent.jsonl"
    c = AuditChain(p)
    for i in range(3):
        c.append("evt", {"i": i})
    lines = p.read_text().splitlines()
    del lines[1]                              # delete the middle entry
    p.write_text("\n".join(lines) + "\n")
    ok, detail = verify_chain(p)
    assert not ok                             # seq gap + prev_hash mismatch


def test_detects_reorder(tmp_path: Path):
    from audit_log import AuditChain, verify_chain
    p = tmp_path / "beta_agent.jsonl"
    c = AuditChain(p)
    for i in range(3):
        c.append("evt", {"i": i})
    lines = p.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]   # swap order
    p.write_text("\n".join(lines) + "\n")
    ok, _ = verify_chain(p)
    assert not ok


def test_chain_continues_across_reopen(tmp_path: Path):
    # A restart re-opens the same file; the chain must continue (not reset to genesis).
    from audit_log import AuditChain, verify_chain
    p = tmp_path / "beta_worker.jsonl"
    AuditChain(p).append("evt", {"i": 0})
    c2 = AuditChain(p)                         # simulate process restart
    rec = c2.append("evt", {"i": 1})
    assert rec["seq"] == 1                     # continued, not restarted at 0
    ok, detail = verify_chain(p)
    assert ok, detail


def test_processor_records_only_agt_audit(tmp_path: Path, monkeypatch):
    import audit_log
    from audit_log import AuditChain, verify_chain
    chain = AuditChain(tmp_path / "beta_agent.jsonl")
    monkeypatch.setattr(audit_log, "_chain", chain)
    # agt_audit event -> recorded; ordinary log -> ignored.
    out = audit_log._audit_processor(None, "info",
                                     {"event": "openfga.check", "agt_audit": True, "allowed": True})
    assert out["event"] == "openfga.check"            # processor returns event_dict unchanged
    audit_log._audit_processor(None, "info", {"event": "debug_noise", "x": 1})
    entries = [json.loads(l) for l in chain.path.read_text().splitlines() if l.strip()]
    assert len(entries) == 1 and entries[0]["event"] == "openfga.check"
    assert "agt_audit" not in entries[0]["data"]      # control field stripped
    ok, _ = verify_chain(chain.path)
    assert ok


# ── #9: external anchoring (truncation/deletion) + field allowlist ─────────────

def test_anchor_detects_tail_truncation(tmp_path: Path):
    from audit_log import AuditChain, verify_chain
    c = AuditChain(tmp_path / "alpha_agent.jsonl")
    for i in range(4):
        c.append("evt", {"count": i})
    ok, _ = verify_chain(c.path)
    assert ok
    # Drop the last 2 lines (the classic attack a pure local chain can't catch).
    lines = c.path.read_text().splitlines()
    c.path.write_text("\n".join(lines[:-2]) + "\n")
    ok, detail = verify_chain(c.path)         # anchor still records seq 3
    assert not ok and "truncation" in detail.lower()


def test_anchor_detects_whole_file_deletion(tmp_path: Path):
    from audit_log import AuditChain, verify_chain
    c = AuditChain(tmp_path / "alpha_agent.jsonl")
    c.append("evt", {"count": 0})
    c.path.unlink()                           # attacker deletes the whole chain
    ok, detail = verify_chain(c.path)         # but the anchor sidecar remains
    assert not ok and "deletion" in detail.lower()


def test_clean_chain_with_anchor_verifies_ok(tmp_path: Path):
    from audit_log import AuditChain, verify_chain
    c = AuditChain(tmp_path / "alpha_agent.jsonl")
    c.append("evt", {"count": 0})
    c.append("evt", {"count": 1})
    ok, detail = verify_chain(c.path)
    assert ok and "anchor" in detail.lower()  # cross-checked against the anchor head


def test_processor_allowlist_drops_unexpected_fields(tmp_path: Path, monkeypatch):
    import audit_log
    from audit_log import AuditChain
    chain = AuditChain(tmp_path / "gamma_agent.jsonl")
    monkeypatch.setattr(audit_log, "_chain", chain)
    # A future .bind() leaks a token + answer onto an agt_audit event — must NOT persist.
    audit_log._audit_processor(None, "info", {
        "event": "auth_decision", "agt_audit": True,
        "user_id": "alice@x|ns", "allowed": True,          # allowlisted -> kept
        "access_token": "SECRET", "answer": "leak me",      # not allowlisted -> dropped
    })
    rec = [json.loads(l) for l in chain.path.read_text().splitlines() if l.strip()][0]
    assert rec["data"]["user_id"] == "alice@x|ns"
    assert "access_token" not in rec["data"] and "answer" not in rec["data"]
    assert rec["data"]["count_dropped"] == 2               # how many, never what
