"""Reciprocal Rank Fusion (RRF) for combining Qdrant and GraphRAG results."""
from __future__ import annotations

from typing import Any


def rrf_fuse(
    *result_lists: list[dict[str, Any]],
    k: int = 60,
    final_limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Combine multiple ranked result lists using Reciprocal Rank Fusion.

    Args:
        *result_lists : One or more lists of result dicts, each containing
                        at least ``chunk_id`` and ``text``.
        k             : RRF constant (default 60, per the original paper).
        final_limit   : Maximum number of results to return.

    Returns:
        Fused and re-ranked list, highest score first.
    """
    scores: dict[str, float] = {}
    chunks: dict[str, dict[str, Any]] = {}

    for result_list in result_lists:
        for rank, item in enumerate(result_list, start=1):
            cid = item.get("chunk_id") or item.get("text", "")[:64]
            scores[cid] = scores.get(cid, 0.0) + 1.0 / (k + rank)
            if cid not in chunks:
                chunks[cid] = item

    fused = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:final_limit]

    return [
        {**chunks[cid], "rrf_score": score}
        for cid, score in fused
    ]


def deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate chunk_ids, keeping the first occurrence (highest score)."""
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        cid = item.get("chunk_id", "")
        if cid and cid in seen:
            continue
        seen.add(cid)
        out.append(item)
    return out
