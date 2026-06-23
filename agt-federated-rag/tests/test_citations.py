"""Deterministic citation / grounding gate (verify_citations)."""
from __future__ import annotations

from agent.nodes import verify_citations


def test_extracts_valid_citations():
    allowed = {"data_retention_policy", "q4_results"}
    answer = ("Retention is 7 years [Source: data_retention_policy]. "
              "Revenue rose [Source: q4_results].")
    cited, unverified = verify_citations(answer, allowed)
    assert cited == {"data_retention_policy", "q4_results"}
    assert unverified == set()


def test_flags_fabricated_citation():
    # The answer cites a source that is NOT in the authorized context → unverified.
    allowed = {"data_retention_policy"}
    answer = "Per [Source: data_retention_policy] and [Source: secret_salary_db] the answer is X."
    cited, unverified = verify_citations(answer, allowed)
    assert "secret_salary_db" in unverified
    assert "data_retention_policy" not in unverified


def test_unknown_source_is_not_flagged():
    # The default context label 'unknown' is never treated as a fabricated citation.
    _, unverified = verify_citations("see [Source: unknown]", set())
    assert unverified == set()


def test_no_citations_is_clean():
    cited, unverified = verify_citations("a plain ungrounded answer", {"x"})
    assert cited == set() and unverified == set()


def test_citation_match_is_whitespace_tolerant():
    cited, _ = verify_citations("a [Source:  data_retention_policy ] b", {"data_retention_policy"})
    assert cited == {"data_retention_policy"}
