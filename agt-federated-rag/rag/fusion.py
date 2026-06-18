"""Reciprocal Rank Fusion (RRF) of Qdrant and Neo4j retrieval results.

Design decisions:
- RRF is the standard rank-fusion formula: score(d) = Σ 1/(k + rank(d))
  where k=60 is the standard smoothing constant (Cormack et al., 2009).
- Deduplication by chunk_id: if a chunk appears in both result lists, its RRF
  scores are summed (not averaged), giving a natural bonus to cross-retriever
  agreement.
- The merged result is sorted descending by fused score and truncated to
  final_limit before being returned.
- Pure function with no I/O — easy to unit-test.
"""
from __future__ import annotations


def rrf_fuse_many(
    result_lists: list[list[dict]],
    final_limit: int,
    k: int = 60,
) -> list[dict]:
    """Fuse N ranked result lists using Reciprocal Rank Fusion.

    Each list comes from one retriever — Qdrant, the Neo4j seam, or any number of
    external retrieval-as-a-service backends. Results are deduplicated by
    ``chunk_id``; a chunk several retrievers return has its RRF contributions
    SUMMED, giving a natural bonus to cross-retriever agreement. The merged list is
    sorted descending by fused score and truncated to ``final_limit``.

    The ``chunk_id`` is load-bearing: it both dedups here AND keys the OpenFGA
    per-chunk authorization decided downstream in ``check_auth`` — so every
    retriever, no matter how many are configured, MUST emit stable chunk_ids.

    Args:
        result_lists: One ordered list per retriever, each of dicts with keys
                      (chunk_id, text, metadata, score).
        final_limit:  Maximum number of results to return after fusion.
        k:            RRF smoothing constant (default 60, per the original paper).

    Returns:
        Merged list of dicts (chunk_id, text, metadata, rrf_score), sorted
        descending by rrf_score, truncated to final_limit.
    """
    # Map chunk_id → accumulated state for the fused result.
    fused: dict[str, dict] = {}

    def _add_ranked_list(results: list[dict]) -> None:
        for rank, item in enumerate(results, start=1):
            cid = item.get("chunk_id", "")
            if not cid:
                continue
            rrf_contribution = 1.0 / (k + rank)
            if cid in fused:
                fused[cid]["rrf_score"] += rrf_contribution
            else:
                fused[cid] = {
                    "chunk_id": cid,
                    "text": item.get("text", ""),
                    "metadata": item.get("metadata", {}),
                    "rrf_score": rrf_contribution,
                }

    for results in result_lists:
        _add_ranked_list(results)

    merged = sorted(fused.values(), key=lambda x: x["rrf_score"], reverse=True)
    return merged[:final_limit]


def rrf_fuse(
    qdrant_results: list[dict],
    graph_results: list[dict],
    final_limit: int,
    k: int = 60,
) -> list[dict]:
    """Two-list convenience wrapper over :func:`rrf_fuse_many` (back-compat)."""
    return rrf_fuse_many([qdrant_results, graph_results], final_limit, k)
