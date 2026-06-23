"""S3 connector — LIVE against MinIO (read -> chunk, and through the generic ingest() engine).

Skips when MinIO isn't reachable on :9555. Proves the second connector works against a real
object store and flows through connectors.base.ingest() unchanged.
"""
from __future__ import annotations

import socket

import pytest

from connectors.base import AccessGrant, ingest
from connectors.registry import build_connector

_EP = "http://localhost:9555"
_BUCKET = "agt-connector-test"


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


def _conn(**extra):
    return build_connector("s3", bucket=_BUCKET, prefix="docs/", endpoint=_EP,
                           access_key="minioadmin", secret_key="minioadmin", **extra)


@pytest.fixture
def seeded_bucket():
    import boto3
    c = boto3.client("s3", endpoint_url=_EP, aws_access_key_id="minioadmin",
                     aws_secret_access_key="minioadmin", region_name="us-east-1")
    try:
        c.create_bucket(Bucket=_BUCKET)
    except Exception:
        pass
    objs = {
        "docs/policy.txt": b"Customer records are retained for seven years per policy.",
        "docs/readme.md": b"# Readme\nArchitecture overview and notes.",
        "docs/ignore.bin": b"\x00\x01 binary not text",   # must be skipped (not .txt/.md)
    }
    for k, v in objs.items():
        c.put_object(Bucket=_BUCKET, Key=k, Body=v)
    yield
    for k in objs:
        try:
            c.delete_object(Bucket=_BUCKET, Key=k)
        except Exception:
            pass


@pytest.mark.asyncio
async def test_reads_text_objects_and_skips_binary(seeded_bucket):
    chunks = [c async for c in _conn().chunks()]
    sources = {c.metadata["source"] for c in chunks}
    titles = {c.metadata["title"] for c in chunks}
    assert any(s.endswith("policy.txt") for s in sources)
    assert any(s.endswith("readme.md") for s in sources)
    assert all("ignore.bin" not in s for s in sources)     # non-text skipped
    assert {"policy", "readme"} <= titles
    assert all(len(c.chunk_id) == 16 for c in chunks)       # stable 16-hex ids


@pytest.mark.asyncio
async def test_chunk_ids_are_stable_across_runs(seeded_bucket):
    a = {c.chunk_id async for c in _conn().chunks()}
    b = {c.chunk_id async for c in _conn().chunks()}
    assert a == b and a            # deterministic + non-empty


@pytest.mark.asyncio
async def test_flows_through_ingest_engine(seeded_bucket):
    upserted: list = []
    granted: list = []

    class _FakeQdrant:
        async def upsert_chunks(self, payload):
            upserted.extend(payload)

    class _FakeFga:
        async def grant_viewer(self, subject, cid):
            granted.append((subject, cid))

    conn = _conn(grants=[AccessGrant(subject="alice@example.com", doc_title="policy",
                                     relation="viewer")])
    summary = await ingest(conn, _FakeQdrant(), _FakeFga())
    assert summary["chunks"] >= 2
    assert summary["grants"] >= 1
    assert any(subj == "alice@example.com" for subj, _ in granted)
    assert all("chunk_id" in p and "text" in p for p in upserted)
