"""
Reciprocal Rank Fusion (RRF) for combining Qdrant and GraphRAG results.

FIX M-1:  chunk_id key collision — when chunk_id is absent, the fallback key
          was text[:64], causing two different chunks with the same opening text
          to overwrite each other in the scores dict.
FIX C3-2: Python's built-in hash() uses a per-process random seed (PYTHONHASHSEED)
          — it is non-deterministic across processes and restarts, and can collide
          within a process for a large corpus. Replaced with SHA-256 (truncated to
          16 hex chars) which is both stable and collision-resistant.
"""
from __future__ import annotations

import hashlib
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
            # FIX M-1: use text hash as fallback, not a 64-char prefix, to
            # avoid collisions between chunks that share an opening sentence.
            chunk_id = item.get("chunk_id")
            if not chunk_id:
                # C3-2: SHA-256 (16 hex chars) — stable across processes, collision-resistant
                digest = hashlib.sha256(item.get("text", "").encode()).hexdigest()[:16]
                chunk_id = f"__hash_{digest}__"

            scores[chunk_id] = scores.get(chunk_id, 0.0) + 1.0 / (k + rank)
            if chunk_id not in chunks:
                chunks[chunk_id] = item

    fused = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:final_limit]

    return [
        {**chunks[cid], "rrf_score": score}
        for cid, score in fused
    ]

# PY-15: deduplicate() was dead code — rrf_fuse() already deduplicates by
# building a dict keyed on chunk_id, so this function was never called.
# Removed to avoid confusion about whether callers should call it.
