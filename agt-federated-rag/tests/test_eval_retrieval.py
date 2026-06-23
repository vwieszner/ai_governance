"""Retrieval-eval scoring core (recall@k, MRR, source extraction, harness wiring)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scenarios"))
import eval_retrieval as E  # noqa: E402


def test_recall_at_k():
    assert E.recall_at_k(["a", "b", "c"], "b", 3) == 1.0
    assert E.recall_at_k(["a", "b", "c"], "b", 1) == 0.0   # b is rank 2, not in top-1
    assert E.recall_at_k(["a", "b", "c"], "z", 3) == 0.0


def test_reciprocal_rank():
    assert E.reciprocal_rank(["a", "b", "c"], "a") == 1.0
    assert E.reciprocal_rank(["a", "b", "c"], "c") == pytest.approx(1 / 3)
    assert E.reciprocal_rank(["a"], "z") == 0.0


def test_summarize_aggregates():
    rows = [
        {"expected": "a", "retrieved": ["a", "x"]},   # r@1=1, r@3=1, rr=1
        {"expected": "b", "retrieved": ["x", "b"]},   # r@1=0, r@3=1, rr=0.5
    ]
    s = E.summarize(rows)
    assert s["n"] == 2
    assert s["recall@1"] == 0.5
    assert s["recall@3"] == 1.0
    assert s["mrr"] == pytest.approx((1 + 0.5) / 2)


def test_summarize_empty():
    assert E.summarize([])["n"] == 0


def test_sources_from_answer_dedups_and_drops_unknown():
    a = ("Retention is 7y [Source: data_retention_policy]. "
         "Vague [Source: unknown]. Again [Source: data_retention_policy].")
    assert E.sources_from_answer(a) == ["data_retention_policy"]


def test_run_live_with_injected_retrieve():
    res = E.run_live(lambda q: ["a", "b"], gold=[{"query": "q1", "expected": "a"},
                                                 {"query": "q2", "expected": "zzz"}])
    assert res["summary"]["recall@1"] == 0.5   # first hits @1, second misses
    assert len(res["detail"]) == 2
