"""Artifact store — local backend round-trip, per-division isolation, key safety."""
from __future__ import annotations

import pytest

import artifact_store as A
from config import settings


@pytest.fixture
def local_store(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "artifact_backend", "local")
    monkeypatch.setattr(settings, "artifact_local_dir", str(tmp_path))
    monkeypatch.setattr(settings, "division_id", "alpha")
    A._backend = None          # reset the singleton so it picks up the tmp dir
    yield
    A._backend = None          # don't leak the tmp-dir backend into other test files


@pytest.mark.asyncio
async def test_put_get_list_delete(local_store):
    ref = await A.put_artifact("reports/q3.txt", b"hello world", content_type="text/plain")
    assert ref.size == 11
    assert ref.key == "alpha/reports/q3.txt"
    assert ref.division == "alpha"
    assert ref.sha256 == __import__("hashlib").sha256(b"hello world").hexdigest()

    assert await A.get_artifact("reports/q3.txt") == b"hello world"
    assert await A.artifact_exists("reports/q3.txt") is True
    assert "reports/q3.txt" in await A.list_artifacts()
    assert "reports/q3.txt" in await A.list_artifacts(prefix="reports/")

    await A.delete_artifact("reports/q3.txt")
    assert await A.artifact_exists("reports/q3.txt") is False


@pytest.mark.asyncio
async def test_per_division_isolation(local_store, monkeypatch):
    await A.put_artifact("secret.bin", b"alpha-only")
    # Switch to another division on the SAME backing dir — it must not see alpha's artifact.
    monkeypatch.setattr(settings, "division_id", "beta")
    assert await A.list_artifacts() == []
    assert await A.artifact_exists("secret.bin") is False


def test_rejects_path_traversal():
    for bad in ("../escape", "a/../../etc/passwd", "/abs/path", "x\x00y"):
        with pytest.raises(ValueError):
            A._validate_name(bad)
