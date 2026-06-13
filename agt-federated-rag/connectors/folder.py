"""Folder connector — the reference Connector implementation (Phase-1 item 10).

Ingests .txt/.md files from a directory (the bundled document source), reproducing the
behaviour of the legacy inline ingest but against the Connector contract. ACL grants are
supplied declaratively (matching the division manifest's seed_viewer / seed_approval /
group grants), so a deployment expresses "who sees what" as data, not code.

This is the template a real connector (Jira, SharePoint, …) follows: implement chunks()
to read the source and grants() to map the source's permissions to AccessGrant facts.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import AsyncIterator

from connectors.base import AccessGrant, DocumentChunk
from rag.ingest import split_text


def _chunk_id(source: str, i: int) -> str:
    """Stable id from (source, chunk index) — identical to the legacy ingest so re-ingest
    overwrites in place rather than duplicating."""
    return hashlib.sha256(f"{source}:{i}".encode()).hexdigest()[:16]


class FolderConnector:
    name = "folder"

    def __init__(self, docs_dir: str, grants: list[AccessGrant] | None = None) -> None:
        self.docs_dir = docs_dir
        self._grants = grants or []

    async def chunks(self) -> AsyncIterator[DocumentChunk]:
        files = sorted([*Path(self.docs_dir).rglob("*.txt"), *Path(self.docs_dir).rglob("*.md")])
        for f in files:
            text = f.read_text(encoding="utf-8", errors="replace")
            for i, ct in enumerate(split_text(text)):
                yield DocumentChunk(
                    chunk_id=_chunk_id(str(f), i),
                    text=ct,
                    metadata={"source": str(f), "chunk_index": i, "title": f.stem},
                )

    async def grants(self) -> AsyncIterator[AccessGrant]:
        for g in self._grants:
            yield g
