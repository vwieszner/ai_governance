"""Connector registry — build a Connector by kind, so ingestion sources are pluggable/config-driven.

    build_connector("folder", docs_dir="...", grants=[...])
    build_connector("s3", bucket="...", prefix="...", endpoint="...", grants=[...])

A new connector (Jira, SharePoint, Confluence, …) registers here and is then usable from the
generic connectors.base.ingest() engine with no caller changes — the contract (chunks()/grants())
is the only integration surface.
"""
from __future__ import annotations

from typing import Any

from connectors.base import Connector

KNOWN = ("folder", "s3")


def build_connector(kind: str, **kwargs: Any) -> Connector:
    k = (kind or "").lower()
    if k == "folder":
        from connectors.folder import FolderConnector
        return FolderConnector(**kwargs)
    if k == "s3":
        from connectors.s3 import S3Connector
        return S3Connector(**kwargs)
    raise ValueError(f"unknown connector kind: {kind!r} (known: {', '.join(KNOWN)})")
