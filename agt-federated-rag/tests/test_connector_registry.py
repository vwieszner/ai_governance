"""Connector registry — kind -> Connector (hermetic, no infra)."""
from __future__ import annotations

import pytest

from connectors.registry import build_connector


def test_folder_kind(tmp_path):
    conn = build_connector("folder", docs_dir=str(tmp_path))
    assert conn.name == "folder"


def test_unknown_kind_raises():
    with pytest.raises(ValueError):
        build_connector("does-not-exist")
