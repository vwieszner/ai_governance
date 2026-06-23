"""Artifact store — LIVE S3 backend verification against a real object store (MinIO).

Skips automatically when MinIO isn't reachable on :9555 (so CI without it stays green), and runs
a real boto3 round-trip when it is — proving the s3 backend works end-to-end, not just mocked.
Bring MinIO up with:
    docker run -d --name agt-minio -p 9555:9000 \
      -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data
"""
from __future__ import annotations

import socket

import pytest

import artifact_store as A
from config import settings


def _minio_up(host: str = "127.0.0.1", port: int = 9555) -> bool:
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


pytestmark = pytest.mark.skipif(not _minio_up(), reason="MinIO not reachable on :9555")


@pytest.fixture
def s3(monkeypatch):
    import boto3

    monkeypatch.setattr(settings, "artifact_backend", "s3")
    monkeypatch.setattr(settings, "artifact_s3_endpoint", "http://localhost:9555")
    monkeypatch.setattr(settings, "artifact_s3_bucket", "agt-artifacts-test")
    monkeypatch.setattr(settings, "artifact_s3_access_key", "minioadmin")
    monkeypatch.setattr(settings, "artifact_s3_secret_key", "minioadmin")
    monkeypatch.setattr(settings, "division_id", "alpha")
    client = boto3.client("s3", endpoint_url="http://localhost:9555",
                          aws_access_key_id="minioadmin", aws_secret_access_key="minioadmin",
                          region_name="us-east-1")
    try:
        client.create_bucket(Bucket="agt-artifacts-test")
    except Exception:
        pass        # already exists
    A._backend = None
    yield
    A._backend = None


@pytest.mark.asyncio
async def test_s3_round_trip(s3):
    ref = await A.put_artifact("reports/q3.txt", b"hello s3 object store", content_type="text/plain")
    assert ref.backend == "s3"
    assert ref.key == "alpha/reports/q3.txt"
    assert ref.size == 21

    assert await A.get_artifact("reports/q3.txt") == b"hello s3 object store"
    assert await A.artifact_exists("reports/q3.txt") is True
    assert "reports/q3.txt" in await A.list_artifacts()

    await A.delete_artifact("reports/q3.txt")
    assert await A.artifact_exists("reports/q3.txt") is False


@pytest.mark.asyncio
async def test_s3_per_division_isolation(s3, monkeypatch):
    await A.put_artifact("secret.bin", b"alpha-only")
    monkeypatch.setattr(settings, "division_id", "beta")
    assert "secret.bin" not in await A.list_artifacts()       # beta can't see alpha's object
    monkeypatch.setattr(settings, "division_id", "alpha")
    await A.delete_artifact("secret.bin")
