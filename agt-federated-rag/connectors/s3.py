"""S3 connector — read documents from an S3-compatible object store (AWS S3 / MinIO).

The second reference Connector after folder.py, and the first against a real cloud source. It
lists ``.txt``/``.md`` objects under a bucket+prefix, chunks them (stable ids, so re-ingest
overwrites in place), and supplies ACL grants declaratively — same contract as FolderConnector,
so it flows through the generic connectors.base.ingest() engine unchanged (chunks -> Qdrant,
grants -> OpenFGA, per-chunk authorization preserved by construction).

boto3 is imported lazily (the optional ``s3`` extra), so this module only needs it when used.
"""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import PurePosixPath
from typing import AsyncIterator

from connectors.base import AccessGrant, DocumentChunk
from rag.ingest import split_text


def _chunk_id(source: str, i: int) -> str:
    """Stable id from (source, chunk index) — same scheme as the folder connector."""
    return hashlib.sha256(f"{source}:{i}".encode()).hexdigest()[:16]


class S3Connector:
    name = "s3"

    def __init__(self, bucket: str, prefix: str = "", *, endpoint: str | None = None,
                 access_key: str | None = None, secret_key: str | None = None,
                 region: str = "us-east-1", grants: list[AccessGrant] | None = None) -> None:
        import boto3  # lazy — optional s3 extra

        kw: dict = {"region_name": region}
        if endpoint:
            kw["endpoint_url"] = endpoint
        if access_key:
            kw["aws_access_key_id"] = access_key
            kw["aws_secret_access_key"] = secret_key
        self._client = boto3.client("s3", **kw)
        self.bucket = bucket
        self.prefix = prefix
        self._grants = grants or []

    def _list_keys(self) -> list[str]:
        paginator = self._client.get_paginator("list_objects_v2")
        keys: list[str] = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for o in page.get("Contents", []):
                if o["Key"].lower().endswith((".txt", ".md")):
                    keys.append(o["Key"])
        return sorted(keys)

    def _read(self, key: str) -> str:
        body = self._client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        return body.decode("utf-8", "replace")

    async def chunks(self) -> AsyncIterator[DocumentChunk]:
        keys = await asyncio.to_thread(self._list_keys)
        for key in keys:
            text = await asyncio.to_thread(self._read, key)
            source = f"s3://{self.bucket}/{key}"
            for i, ct in enumerate(split_text(text)):
                yield DocumentChunk(
                    chunk_id=_chunk_id(source, i),
                    text=ct,
                    metadata={"source": source, "chunk_index": i,
                              "title": PurePosixPath(key).stem},
                )

    async def grants(self) -> AsyncIterator[AccessGrant]:
        for g in self._grants:
            yield g
