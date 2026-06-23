"""Pluggable artifact (object/blob) storage for durable outputs.

The governed RAG/approval path persists *state* (Redis outcomes, the hash-chained audit log,
Qdrant vectors, OpenFGA tuples, Temporal), but there was no home for durable BLOBS — exported
audit/evidence packs, generated reports, user uploads. This module is that home.

Backends (``settings.artifact_backend``):
  - ``local`` (default): a directory on disk (``settings.artifact_local_dir``). Zero deps,
    good for dev / single-node.
  - ``s3``: any S3-compatible object store (AWS S3 or self-hosted MinIO) via boto3 (lazily
    imported, so boto3 is only needed when this backend is selected).

Per-division by construction: every key is prefixed with ``settings.division_id``, so a shared
bucket stays tenant-isolated the same way the per-division Redis/OpenFGA stores do — one division
can never address another's artifacts.

GOVERNANCE NOTE: this stores FINISHED, already-authorized outputs; it does not re-run per-chunk
authorization. Callers MUST authorize the content before storing it (e.g. an evidence pack is
generated from a division's own audit log by an admin-gated endpoint). The store is a durable
sink, not an access-control boundary.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import structlog

from config import settings

log = structlog.get_logger(__name__)

# Keys are operator/division-supplied; constrain them so a key can't escape the division prefix
# (path traversal on the local backend) or carry control chars into S3.
_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,250}$")


def _validate_name(name: str) -> str:
    if not _SAFE_KEY.match(name) or ".." in name:
        raise ValueError(f"invalid artifact name: {name!r}")
    return name


@dataclass(frozen=True)
class ArtifactRef:
    """A pointer to a stored artifact (returned by put / head)."""
    key: str            # division-namespaced storage key
    name: str           # caller-facing name (without the division prefix)
    backend: str
    size: int
    content_type: str
    sha256: str
    division: str


class _Backend:
    async def put(self, key: str, data: bytes, content_type: str, metadata: dict[str, str]) -> None: ...
    async def get(self, key: str) -> bytes: ...
    async def exists(self, key: str) -> bool: ...
    async def list(self, prefix: str) -> list[str]: ...
    async def delete(self, key: str) -> None: ...


class _LocalBackend(_Backend):
    """Filesystem backend. Each artifact is a file under ``<root>/<key>``; metadata + content
    type ride alongside in a sidecar ``<file>.meta.json`` so head()/content-type survive."""

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()

    def _path(self, key: str) -> Path:
        p = (self.root / key).resolve()
        # Defence in depth on top of _validate_name: never write outside the root.
        if not str(p).startswith(str(self.root)):
            raise ValueError("artifact key escapes the storage root")
        return p

    async def put(self, key: str, data: bytes, content_type: str, metadata: dict[str, str]) -> None:
        def _w() -> None:
            p = self._path(key)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            p.with_suffix(p.suffix + ".meta.json").write_text(
                json.dumps({"content_type": content_type, "metadata": metadata}), encoding="utf-8")
        await asyncio.to_thread(_w)

    async def get(self, key: str) -> bytes:
        return await asyncio.to_thread(lambda: self._path(key).read_bytes())

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(lambda: self._path(key).is_file())

    async def list(self, prefix: str) -> list[str]:
        def _l() -> list[str]:
            base = self.root
            if not base.is_dir():
                return []
            out = []
            for p in base.rglob("*"):
                if p.is_file() and not p.name.endswith(".meta.json"):
                    rel = str(p.relative_to(base)).replace("\\", "/")
                    if rel.startswith(prefix):
                        out.append(rel)
            return sorted(out)
        return await asyncio.to_thread(_l)

    async def delete(self, key: str) -> None:
        def _d() -> None:
            p = self._path(key)
            p.unlink(missing_ok=True)
            p.with_suffix(p.suffix + ".meta.json").unlink(missing_ok=True)
        await asyncio.to_thread(_d)


class _S3Backend(_Backend):
    """S3-compatible backend (AWS S3 / MinIO). boto3 is imported lazily so it's only a
    dependency when this backend is actually selected."""

    def __init__(self) -> None:
        import boto3  # lazy — only needed for the s3 backend

        kw: dict[str, Any] = {"region_name": settings.artifact_s3_region}
        if settings.artifact_s3_endpoint:
            kw["endpoint_url"] = settings.artifact_s3_endpoint   # MinIO / non-AWS
        if settings.artifact_s3_access_key:
            kw["aws_access_key_id"] = settings.artifact_s3_access_key
            kw["aws_secret_access_key"] = settings.artifact_s3_secret_key
        self._client = boto3.client("s3", **kw)
        self._bucket = settings.artifact_s3_bucket
        if not self._bucket:
            raise RuntimeError("artifact_backend=s3 requires ARTIFACT_S3_BUCKET")

    async def put(self, key: str, data: bytes, content_type: str, metadata: dict[str, str]) -> None:
        await asyncio.to_thread(
            lambda: self._client.put_object(Bucket=self._bucket, Key=key, Body=data,
                                            ContentType=content_type, Metadata=metadata))

    async def get(self, key: str) -> bytes:
        def _g() -> bytes:
            return self._client.get_object(Bucket=self._bucket, Key=key)["Body"].read()
        return await asyncio.to_thread(_g)

    async def exists(self, key: str) -> bool:
        def _h() -> bool:
            try:
                self._client.head_object(Bucket=self._bucket, Key=key)
                return True
            except Exception:
                return False
        return await asyncio.to_thread(_h)

    async def list(self, prefix: str) -> list[str]:
        def _l() -> list[str]:
            paginator = self._client.get_paginator("list_objects_v2")
            out: list[str] = []
            for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                out += [o["Key"] for o in page.get("Contents", [])]
            return out
        return await asyncio.to_thread(_l)

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(lambda: self._client.delete_object(Bucket=self._bucket, Key=key))


_backend: _Backend | None = None


def _get_backend() -> _Backend:
    global _backend
    if _backend is None:
        kind = settings.artifact_backend.lower()
        if kind == "s3":
            _backend = _S3Backend()
        elif kind == "local":
            _backend = _LocalBackend(settings.artifact_local_dir)
        else:
            raise RuntimeError(f"unknown artifact_backend: {settings.artifact_backend!r}")
        log.info("artifact_store_backend", backend=kind)
    return _backend


def _key(name: str) -> str:
    """Division-namespaced storage key for a caller-facing name."""
    return f"{settings.division_id}/{_validate_name(name)}"


async def put_artifact(name: str, data: bytes, *, content_type: str = "application/octet-stream",
                       metadata: dict[str, str] | None = None) -> ArtifactRef:
    """Store ``data`` under ``name`` (namespaced to this division). Returns an ArtifactRef."""
    key = _key(name)
    digest = hashlib.sha256(data).hexdigest()
    md = {**(metadata or {}), "sha256": digest, "division": settings.division_id}
    await _get_backend().put(key, data, content_type, md)
    ref = ArtifactRef(key=key, name=name, backend=settings.artifact_backend, size=len(data),
                      content_type=content_type, sha256=digest, division=settings.division_id)
    log.info("artifact_stored", key=key, size=len(data), content_type=content_type)
    return ref


async def get_artifact(name: str) -> bytes:
    return await _get_backend().get(_key(name))


async def artifact_exists(name: str) -> bool:
    return await _get_backend().exists(_key(name))


async def list_artifacts(prefix: str = "") -> list[str]:
    """List this division's artifact names (caller-facing, without the division prefix)."""
    full = await _get_backend().list(f"{settings.division_id}/{prefix}")
    pre = f"{settings.division_id}/"
    return [k[len(pre):] for k in full if k.startswith(pre)]


async def delete_artifact(name: str) -> None:
    await _get_backend().delete(_key(name))


def ref_to_dict(ref: ArtifactRef) -> dict[str, Any]:
    return asdict(ref)
