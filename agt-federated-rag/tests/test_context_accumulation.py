"""Mosaic-effect (context-accumulation) guard — agent/context_guard.py + check_auth hook.

Per-chunk OpenFGA authz cannot see that an HR chunk and a Finance chunk, each individually
allowed, combine into an answer neither owner would release together. These tests pin the
guard built on the AGT Context Accumulation Governance primitives: single-source context
passes, a governed sensitive combination escalates (or denies), a sub-threshold mix passes,
a broken policy fails CLOSED, and the real check_auth node routes an escalation into the
EXISTING approval workflow via an OpenFGA clearance object.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agent import context_guard as cg

_DEFAULT_POLICY = (Path(__file__).resolve().parents[1]
                   / "agent" / "policies" / "aggregation" / "context-aggregation.yaml")

HR = {"chunk_id": "hr1", "text": "Senior engineer band: $180k-$220k.",
      "metadata": {"source": "tests/docs/cluster-a/hr_compensation_data.txt"}}
HR2 = {"chunk_id": "hr2", "text": "Staff band: $220k-$260k.",
       "metadata": {"source": "hr_compensation_data.txt"}}
FIN = {"chunk_id": "fin1", "text": "Q4 revenue was $4.2M; opex $3.1M.",
       "metadata": {"source": "C:\\docs\\cluster-b\\q4_financial_results.txt"}}
LEGAL = {"chunk_id": "leg1", "text": "Records are retained 7 years.",
         "metadata": {"source": "data_retention_policy.txt"}}
PLAIN = {"chunk_id": "ai1", "text": "Bias testing is quarterly.",
         "metadata": {"source": "bias_testing_requirements.txt"}}


def _cfg(**overrides):
    doc = yaml.safe_load(_DEFAULT_POLICY.read_text(encoding="utf-8"))
    doc.update(overrides)
    return cg.parse_config(doc)


# ── Unit: the shipped default policy ──────────────────────────────────────────

def test_default_policy_parses_and_labels_deterministically():
    cfg = cg.load_config(str(_DEFAULT_POLICY))
    assert cg.label_chunk(HR["metadata"], cfg) == (frozenset({"hr"}),
                                                   cg.DataClassification.CONFIDENTIAL)
    # Windows-style path: basename match still applies.
    assert cg.label_chunk(FIN["metadata"], cfg)[0] == frozenset({"financial"})
    # Unmatched source: default classification, no labels.
    assert cg.label_chunk(PLAIN["metadata"], cfg) == (frozenset(),
                                                      cg.DataClassification.INTERNAL)


def test_single_source_context_is_allowed():
    cfg = _cfg()
    d = cg.evaluate_chunks([HR, HR2], cfg, workflow_id="t1")
    assert d.outcome == cg.Outcome.ALLOW
    assert d.labels == frozenset({"hr"})
    assert d.sensitivity == cg.DataClassification.CONFIDENTIAL
    assert d.envelope_ref.envelope_id == "ctx-t1"


def test_hr_plus_finance_combination_escalates_with_clearance():
    d = cg.evaluate_chunks([HR, FIN, PLAIN], _cfg())
    assert d.outcome == cg.Outcome.ESCALATE
    assert d.rules_applied == ("hr-finance",)
    assert d.reason == "rule:hr-finance"
    # The AGT rule raises the AGGREGATE above either chunk's own classification.
    assert d.sensitivity == cg.DataClassification.RESTRICTED
    assert "no_external_export" in d.restrictions
    assert d.clearance_ids == ("mosaic-hr-finance",)
    assert d.contributing_chunk_ids == ("fin1", "hr1")      # PLAIN does not contribute


def test_rule_outcome_deny_is_honoured():
    doc = yaml.safe_load(_DEFAULT_POLICY.read_text(encoding="utf-8"))
    doc["rules"][0]["outcome"] = "deny"
    d = cg.evaluate_chunks([HR, FIN], cg.parse_config(doc))
    assert d.outcome == cg.Outcome.DENY
    assert d.clearance_ids == ()


def test_below_backstop_threshold_is_allowed():
    # Two distinct labels, no rule covering {hr, legal}, threshold 3 → allowed.
    d = cg.evaluate_chunks([HR, LEGAL, PLAIN], _cfg())
    assert d.outcome == cg.Outcome.ALLOW
    assert d.labels == frozenset({"hr", "legal"})


def test_uncovered_combination_at_backstop_threshold_escalates():
    # Drop the hr-finance rule so {hr, financial, legal} is governed by NO rule: the AGT
    # monotone backstop (>= 3 labels) escalates instead of passing silently.
    d = cg.evaluate_chunks([HR, FIN, LEGAL], _cfg(rules=[]))
    assert d.outcome == cg.Outcome.ESCALATE
    assert d.reason.startswith("backstop:3_labels")
    assert d.clearance_ids == (cg.backstop_clearance_id({"hr", "financial", "legal"}),)
    # Stable + order-independent clearance id.
    assert cg.backstop_clearance_id(["legal", "hr", "financial"]) == d.clearance_ids[0]


def test_explicit_chunk_metadata_labels_are_honoured():
    c = {"chunk_id": "x", "metadata": {"source": "notes.txt", "data_labels": ["financial"],
                                       "classification": "restricted"}}
    labels, cls = cg.label_chunk(c["metadata"], _cfg())
    assert labels == frozenset({"financial"}) and cls == cg.DataClassification.RESTRICTED
    assert cg.evaluate_chunks([HR, c], _cfg()).outcome == cg.Outcome.ESCALATE


# ── Fail closed on bad config ─────────────────────────────────────────────────

@pytest.mark.parametrize("mutate", [
    lambda d: d.update(version="2.0"),
    lambda d: d.update(surprise=True),                                   # unknown key
    lambda d: d["rules"][0].update(outcome="allow"),                     # bad outcome
    lambda d: d["rules"][0].update(all_labels=["hr"]),                   # not a combination
    lambda d: d["rules"][0].update(sets_sensitivity="ultra"),            # bad classification
    lambda d: d["rules"].append(dict(d["rules"][0])),                    # duplicate name
    lambda d: d["classifiers"][0].update(match={}),                      # empty match
    lambda d: d["backstop"].update(n_category_threshold=1),              # fires on 1 label
    lambda d: d.update(enabled="yes"),
])
def test_invalid_config_raises(mutate):
    doc = yaml.safe_load(_DEFAULT_POLICY.read_text(encoding="utf-8"))
    mutate(doc)
    with pytest.raises(cg.ContextAggregationConfigError):
        cg.parse_config(doc)


def test_config_errors_fail_closed_at_evaluate(tmp_path):
    bad = tmp_path / "broken.yaml"
    bad.write_text("version: '1.0'\nrules: [ {name: x, all_labels: [", encoding="utf-8")
    d = cg.evaluate([HR], str(bad))
    assert d.outcome == cg.Outcome.DENY and d.reason.startswith("config_error")
    missing = cg.evaluate([HR], str(tmp_path / "nope.yaml"))
    assert missing.outcome == cg.Outcome.DENY and missing.reason.startswith("config_error")
    # Explicitly disabled (empty path) is the only way to turn the guard off.
    assert cg.evaluate([HR, FIN], "").outcome == cg.Outcome.ALLOW


# ── Integration: through the REAL check_auth node ─────────────────────────────

class _Store:
    name = "qdrant"
    trusted = True

    def __init__(self, chunks):
        self._by_id = {c["chunk_id"]: c for c in chunks}

    async def fetch_by_chunk_ids(self, chunk_ids):
        return {cid: {"text": self._by_id[cid]["text"], "metadata": self._by_id[cid]["metadata"]}
                for cid in chunk_ids if cid in self._by_id}


class _Auth:
    """Every real chunk ALLOWED; clearance objects per ``cleared``; records calls."""

    def __init__(self, cleared=()):
        self.cleared = set(cleared)
        self.calls: list[list[str]] = []

    async def batch_decide(self, user_id, chunk_ids, groups=None):
        from auth.openfga import AuthzDecision
        self.calls.append(list(chunk_ids))
        return {cid: (AuthzDecision.DENIED if cid.startswith(cg.CLEARANCE_PREFIX)
                      and cid not in self.cleared else AuthzDecision.ALLOWED)
                for cid in chunk_ids}


def _wire(monkeypatch, chunks, auth):
    import agent.nodes as nodes

    async def fake_retrievers():
        return [_Store(chunks)]

    async def fake_openfga():
        return auth

    async def fake_enforce(action, context):
        return None

    monkeypatch.setattr(nodes, "_get_retrievers", fake_retrievers)
    monkeypatch.setattr(nodes, "_get_openfga", fake_openfga)
    monkeypatch.setattr(nodes, "_enforce", fake_enforce)
    return nodes


def _state(chunks):
    return {"query": "Compare senior pay with Q4 revenue", "user_id": "alice",
            "task_id": "task-1", "fused_chunks": [dict(c) for c in chunks], "user_groups": []}


async def test_check_auth_single_source_routes_to_generate(monkeypatch):
    from agent.graph import _route
    from agent.state import FlowDecision
    nodes = _wire(monkeypatch, [HR, HR2], _Auth())
    out = await nodes.check_auth(_state([HR, HR2]))
    assert out["flow"] == FlowDecision.LOCAL_ALLOWED
    assert out["pending_chunk_ids"] == []
    assert _route({**out}) == "generate_answer"


async def test_check_auth_combination_escalates_into_approval(monkeypatch):
    from agent.graph import _route
    from agent.state import FlowDecision
    auth = _Auth()
    nodes = _wire(monkeypatch, [HR, FIN], auth)
    out = await nodes.check_auth(_state([HR, FIN]))
    assert out["flow"] == FlowDecision.LOCAL_NEEDS_APPROVAL
    assert out["pending_chunk_ids"] == ["mosaic-hr-finance"]
    assert _route({**out}) == "start_approval"          # the EXISTING approval node
    assert ["mosaic-hr-finance"] in auth.calls          # clearance checked in OpenFGA
    # Per-chunk authz is not rewritten — each chunk is still individually allowed.
    assert sorted(out["allowed_chunk_ids"]) == ["fin1", "hr1"]


async def test_check_auth_combination_passes_once_cleared(monkeypatch):
    from agent.state import FlowDecision
    nodes = _wire(monkeypatch, [HR, FIN], _Auth(cleared={"mosaic-hr-finance"}))
    out = await nodes.check_auth(_state([HR, FIN]))
    assert out["flow"] == FlowDecision.LOCAL_ALLOWED
    assert out["pending_chunk_ids"] == []


async def test_check_auth_deny_rule_withholds_context(monkeypatch, tmp_path):
    from agent.state import FlowDecision
    from config import settings
    doc = yaml.safe_load(_DEFAULT_POLICY.read_text(encoding="utf-8"))
    doc["rules"][0]["outcome"] = "deny"
    p = tmp_path / "deny.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    monkeypatch.setattr(settings, "context_aggregation_policy", str(p))
    nodes = _wire(monkeypatch, [HR, FIN], _Auth())
    out = await nodes.check_auth(_state([HR, FIN]))
    assert out["flow"] == FlowDecision.LOCAL_DENIED
    assert out["allowed_chunk_ids"] == [] and out["fused_chunks"] == []
    assert sorted(out["denied_chunk_ids"]) == ["fin1", "hr1"]
    assert "withheld" in out["status_message"]
    # generate_answer, even if reached, has no authorized context to send to the LLM.
    gen = await nodes.generate_answer({**_state([HR, FIN]), **out})
    assert gen["status_message"] == "no_accessible_chunks"


async def test_check_auth_broken_policy_fails_closed(monkeypatch, tmp_path):
    from agent.state import FlowDecision
    from config import settings
    monkeypatch.setattr(settings, "context_aggregation_policy", str(tmp_path / "missing.yaml"))
    nodes = _wire(monkeypatch, [HR], _Auth())
    out = await nodes.check_auth(_state([HR]))      # even a single source is withheld
    assert out["flow"] == FlowDecision.LOCAL_DENIED
    assert out["allowed_chunk_ids"] == []
