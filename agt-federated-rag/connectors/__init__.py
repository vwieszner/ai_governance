"""Connector SDK (Phase-1 item 10).

A connector turns an external data source into (a) retrievable CHUNKS and (b) the ACL
GRANTS that mirror the source's permissions into OpenFGA — so per-deployment integrations
(Jira, SharePoint, file shares, …) are *contract work*, not core changes, and a connector
can never bypass authorization (emitting grants is part of the interface).

See base.py for the contract + the generic `ingest()` engine, and folder.py for the
reference implementation (the bundled .txt/.md folder source).
"""
from connectors.base import (
    AccessGrant,
    Connector,
    DocumentChunk,
    ingest,
)

__all__ = ["AccessGrant", "Connector", "DocumentChunk", "ingest"]
