"""Connector SDK tests (Phase-1 item 10).

Pins the contract: the generic ingest engine upserts a connector's chunks to Qdrant and
writes its ACL grants to OpenFGA — including group-userset grants (ACL mirroring) and
doc-title fan-out. The FolderConnector reference impl is exercised against a temp dir.
"""
from __future__ import annotations

import asyncio


class _FakeQdrant:
    def __init__(self):
        self.upserted = []
    async def upsert_chunks(self, chunks):
        self.upserted.extend(chunks)


class _FakeOpenFGA:
    def __init__(self):
        self.user_viewer = []
        self.group_viewer = []
        self.pending = []
        self.owner = []
    async def grant_viewer(self, user_id, chunk_id):
        self.user_viewer.append((user_id, chunk_id))
    async def grant_group_viewer(self, group, chunk_id):
        self.group_viewer.append((group, chunk_id))
    async def set_pending_approval(self, user_id, chunk_id):
        self.pending.append((user_id, chunk_id))
    async def _write_tuple(self, user_id, chunk_id, relation):
        self.owner.append((user_id, chunk_id, relation.value))


def test_ingest_upserts_chunks_and_writes_all_grant_kinds():
    from connectors.base import AccessGrant, DocumentChunk, ingest

    class C:
        name = "fake"
        async def chunks(self):
            yield DocumentChunk("c1", "alpha text", {"title": "policy"})
            yield DocumentChunk("c2", "beta text", {"title": "q4"})
        async def grants(self):
            yield AccessGrant(subject="finance", subject_kind="group", doc_title="policy")
            yield AccessGrant(subject="alice@x|ns", relation="viewer", chunk_id="c2")
            yield AccessGrant(subject="alice@x|ns", relation="pending_approval", chunk_id="c2")
            yield AccessGrant(subject="bob@x|ns", relation="owner", chunk_id="c2")

    q, fga = _FakeQdrant(), _FakeOpenFGA()
    summary = asyncio.run(ingest(C(), q, fga))

    assert summary == {"chunks": 2, "grants": 4}
    assert {c["chunk_id"] for c in q.upserted} == {"c1", "c2"}
    assert fga.group_viewer == [("finance", "c1")]        # group grant via doc_title -> c1
    assert fga.user_viewer == [("alice@x|ns", "c2")]
    assert fga.pending == [("alice@x|ns", "c2")]
    assert fga.owner == [("bob@x|ns", "c2", "owner")]


def test_doc_title_grant_fans_out_to_all_its_chunks():
    from connectors.base import AccessGrant, DocumentChunk, ingest

    class C:
        name = "fake"
        async def chunks(self):
            yield DocumentChunk("a0", "t0", {"title": "handbook"})
            yield DocumentChunk("a1", "t1", {"title": "handbook"})
        async def grants(self):
            yield AccessGrant(subject="staff", subject_kind="group", doc_title="handbook")

    q, fga = _FakeQdrant(), _FakeOpenFGA()
    asyncio.run(ingest(C(), q, fga))
    assert sorted(fga.group_viewer) == [("staff", "a0"), ("staff", "a1")]


def test_folder_connector_reads_files_with_stable_ids(tmp_path):
    from connectors.folder import FolderConnector
    from connectors.base import AccessGrant, ingest

    (tmp_path / "retention.txt").write_text("the retention policy is seven years")
    (tmp_path / "notes.md").write_text("# notes\nsome content here")

    conn = FolderConnector(str(tmp_path), grants=[
        AccessGrant(subject="everyone", subject_kind="group", doc_title="retention"),
    ])
    q, fga = _FakeQdrant(), _FakeOpenFGA()
    summary = asyncio.run(ingest(conn, q, fga))

    assert summary["chunks"] >= 2
    titles = {c["metadata"]["title"] for c in q.upserted}
    assert {"retention", "notes"} <= titles
    # group grant resolved to the retention chunk(s)
    assert all(g[0] == "everyone" for g in fga.group_viewer)
    assert len(fga.group_viewer) >= 1
    # stable ids: a second run reproduces the same chunk_ids
    q2 = _FakeQdrant()
    asyncio.run(ingest(FolderConnector(str(tmp_path)), q2, _FakeOpenFGA()))
    assert {c["chunk_id"] for c in q.upserted} == {c["chunk_id"] for c in q2.upserted}
