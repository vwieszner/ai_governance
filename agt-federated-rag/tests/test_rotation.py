"""Scheduled key-rotation tests (Phase-1 item 8).

Pin the rotation LOGIC (perform_rotation + rotate_approval_hmac) without the Temporal
sandbox: DID rotation is delegated, HMAC rotation rolls the secret with a prior-value
overlap, and one failing leg never aborts the other (best-effort).
"""
from __future__ import annotations

import asyncio
import json


def test_rotate_approval_hmac_rolls_with_overlap(tmp_path):
    from workflow.rotation import rotate_approval_hmac

    sp = tmp_path / "secrets.json"
    sp.write_text(json.dumps({"approval_hmac_secret": "OLD", "seed_user_password": "x"}))

    assert rotate_approval_hmac(str(sp)) is True
    data = json.loads(sp.read_text())
    assert data["approval_hmac_secret_prev"] == "OLD"          # prior kept for grace window
    assert data["approval_hmac_secret"] != "OLD"               # rolled
    assert len(data["approval_hmac_secret"]) == 64             # 32-byte hex
    assert data["seed_user_password"] == "x"                   # other fields preserved


def test_rotate_approval_hmac_missing_file_is_safe(tmp_path):
    from workflow.rotation import rotate_approval_hmac
    assert rotate_approval_hmac(str(tmp_path / "nope.json")) is False


def test_perform_rotation_does_both_and_is_best_effort(tmp_path, monkeypatch):
    from workflow import rotation

    called = {"did": False}

    async def fake_rotate_creds():
        called["did"] = True

    monkeypatch.setattr("mesh.agent_identity.rotate_credentials", fake_rotate_creds)
    sp = tmp_path / "secrets.json"
    sp.write_text(json.dumps({"approval_hmac_secret": "OLD"}))

    summary = asyncio.run(rotation.perform_rotation(str(sp)))
    assert summary == {"did": True, "hmac": True}
    assert called["did"]


def test_perform_rotation_did_failure_does_not_block_hmac(tmp_path, monkeypatch):
    from workflow import rotation

    async def boom():
        raise RuntimeError("registry down")

    monkeypatch.setattr("mesh.agent_identity.rotate_credentials", boom)
    sp = tmp_path / "secrets.json"
    sp.write_text(json.dumps({"approval_hmac_secret": "OLD"}))

    summary = asyncio.run(rotation.perform_rotation(str(sp)))
    assert summary["did"] is False        # DID leg failed, logged not raised
    assert summary["hmac"] is True        # HMAC leg still ran


def test_worker_imports_rotation_symbols():
    # The worker registers the rotation workflow + activity — guard the wiring so a
    # rename can't silently drop scheduled rotation.
    from workflow import worker
    assert worker.KeyRotationWorkflow is not None
    assert worker.rotate_keys_activity is not None
