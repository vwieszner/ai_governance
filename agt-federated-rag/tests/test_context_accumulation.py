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


# ── Federated answers: peer-reported labels in the signed envelope ────────────
#
# The graph only consults a peer when local retrieval is empty, so "HR locally + Finance
# via federation" is two releases to the same user. The per-user release ledger makes the
# union visible: every release is evaluated with the labels released from OTHER origins.

BETA_DID = "did:mesh:beta-test"
PEER_FIN_ANSWER = "Q4 revenue was $4.2M; opex $3.1M."


class _LLM:
    async def ainvoke(self, prompt):
        class _R:
            content = "relayed peer answer"
        return _R()


def _wire_peer(monkeypatch, chunks, auth):
    nodes = _wire(monkeypatch, chunks, auth)

    async def fake_llm():
        return _LLM()
    monkeypatch.setattr(nodes, "_get_llm", fake_llm)
    return nodes


def _peer_state(labels, verified=True, check_only=False):
    return {"query": "What was Q4 revenue?", "user_id": "alice", "task_id": "task-2",
            "fused_chunks": [], "allowed_chunk_ids": [], "pending_chunk_ids": [],
            "user_groups": [], "peer_status": "completed", "peer_answer": PEER_FIN_ANSWER,
            "peer_did": BETA_DID, "peer_division": "beta", "peer_data_labels": labels,
            "peer_labels_verified": verified, "check_only": check_only}


def test_peer_label_validation_is_strict():
    assert cg.validate_peer_labels(["financial", "hr"]) == frozenset({"financial", "hr"})
    assert cg.validate_peer_labels([]) == frozenset()                 # labelled: none
    for bad in (None, "financial", [1], ["Financial!"], ["x"] * 33, {"financial": 1}):
        assert cg.validate_peer_labels(bad) is None                   # → unlabeled


def test_unlabeled_peer_fail_modes():
    unlabeled = cg.Contribution(origin=BETA_DID, division="beta", labels=None)
    d = cg.evaluate_combined([HR], [unlabeled], _cfg())               # default: unknown
    assert d.outcome == cg.Outcome.ALLOW
    assert d.labels == frozenset({"hr", cg.UNLABELED_PEER_LABEL})     # NOT "no labels"
    # unknown counts toward the AGT backstop: {hr, legal, unlabeled-peer} >= 3.
    d = cg.evaluate_combined([HR, LEGAL], [unlabeled], _cfg())
    assert d.outcome == cg.Outcome.ESCALATE and d.reason.startswith("backstop:3_labels")
    d = cg.evaluate_combined([PLAIN], [unlabeled], _cfg(federation={"unlabeled_peer": "deny"}))
    assert d.outcome == cg.Outcome.DENY and d.reason == "unlabeled_peer:deny"
    d = cg.evaluate_combined([PLAIN], [unlabeled],
                             _cfg(federation={"unlabeled_peer": "escalate"}))
    assert d.outcome == cg.Outcome.ESCALATE
    assert d.clearance_ids == (cg.UNLABELED_PEER_CLEARANCE,)
    assert d.sources == (f"peer beta ({BETA_DID}) (unlabeled/unverified): []",)
    # Labels present but NOT from a verified response are ignored (treated as unlabeled).
    forged = cg.Contribution(origin=BETA_DID, labels=frozenset({"financial"}), verified=False)
    assert cg.evaluate_combined([HR], [forged], _cfg()).rules_applied == ()


def test_federation_config_is_validated():
    for bad in ({"unlabeled_peer": "allow"}, {"window_seconds": -1}, {"surprise": 1}):
        with pytest.raises(cg.ContextAggregationConfigError):
            _cfg(federation=bad)
    assert _cfg().unlabeled_peer == "unknown" and _cfg().window_seconds == 900


def test_ledger_window_and_origin_exclusion():
    led = cg.ReleaseLedger()
    hr = cg.Contribution(origin=cg.LOCAL_ORIGIN, labels=frozenset({"hr"}))
    fin = cg.Contribution(origin=BETA_DID, labels=frozenset({"financial"}))
    led.record("u", hr, now=1000.0)
    led.record("u", fin, now=1000.0)
    assert led.others("u", cg.LOCAL_ORIGIN, 900, now=1500.0) == [fin]
    assert led.others("u", BETA_DID, 900, now=1500.0) == [hr]
    assert led.others("u", BETA_DID, 900, now=2000.0) == []           # expired
    assert led.others("other-user", BETA_DID, 900, now=1001.0) == []
    led.record("u", hr, now=1000.0)
    assert led.others("u", BETA_DID, 0, now=1001.0) == []             # 0 = no memory


async def test_federated_finance_after_local_hr_escalates_with_sources(monkeypatch):
    from agent.graph import _route_after_peer_result
    from agent.state import FlowDecision
    auth = _Auth()
    nodes = _wire_peer(monkeypatch, [HR], auth)
    local = await nodes.check_auth(_state([HR]))
    assert local["flow"] == FlowDecision.LOCAL_ALLOWED                # HR alone is fine

    out = await nodes.handle_peer_result(_peer_state(["financial"]))
    assert out["flow"] == FlowDecision.LOCAL_NEEDS_APPROVAL
    assert out["pending_chunk_ids"] == ["mosaic-hr-finance"]
    assert out["answer"] is None and out["peer_answer"] is None       # nothing released
    assert _route_after_peer_result({**_peer_state(["financial"]), **out}) == "start_approval"
    srcs = out["approval_sources"]
    assert any(s.endswith("(earlier answer): hr_compensation_data.txt [hr]") for s in srcs)
    assert f"peer beta ({BETA_DID}): [financial]" in srcs
    assert ["mosaic-hr-finance"] in auth.calls


async def test_local_hr_after_federated_finance_escalates(monkeypatch):
    # Order-independent: a peer-only single label passes, then local HR hits the rule.
    from agent.state import FlowDecision
    nodes = _wire_peer(monkeypatch, [HR], _Auth())
    peer_out = await nodes.handle_peer_result(_peer_state(["financial"]))
    assert peer_out["flow"] == FlowDecision.REMOTE_APPROVED
    assert peer_out["answer"] == "relayed peer answer"
    out = await nodes.check_auth(_state([HR]))
    assert out["flow"] == FlowDecision.LOCAL_NEEDS_APPROVAL
    assert out["pending_chunk_ids"] == ["mosaic-hr-finance"]
    assert f"peer beta ({BETA_DID}): [financial]" in out["approval_sources"]


async def test_peer_only_single_label_passes(monkeypatch):
    from agent.state import FlowDecision
    nodes = _wire_peer(monkeypatch, [], _Auth())
    out = await nodes.handle_peer_result(_peer_state(["financial"]))
    assert out["flow"] == FlowDecision.REMOTE_APPROVED
    assert out["peer_answer"] == PEER_FIN_ANSWER


async def test_cleared_federated_combination_is_delivered(monkeypatch):
    from agent.state import FlowDecision
    nodes = _wire_peer(monkeypatch, [HR], _Auth(cleared={"mosaic-hr-finance"}))
    await nodes.check_auth(_state([HR]))
    out = await nodes.handle_peer_result(_peer_state(["financial"], check_only=True))
    assert out["flow"] == FlowDecision.REMOTE_APPROVED
    assert out["answer"] == PEER_FIN_ANSWER


async def test_federated_deny_rule_withholds_peer_answer(monkeypatch, tmp_path):
    from agent.state import FlowDecision
    from config import settings
    doc = yaml.safe_load(_DEFAULT_POLICY.read_text(encoding="utf-8"))
    doc["rules"][0]["outcome"] = "deny"
    p = tmp_path / "deny.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    monkeypatch.setattr(settings, "context_aggregation_policy", str(p))
    nodes = _wire_peer(monkeypatch, [HR], _Auth())
    await nodes.check_auth(_state([HR]))
    out = await nodes.handle_peer_result(_peer_state(["financial"]))
    assert out["flow"] == FlowDecision.REMOTE_DENIED
    assert out["peer_answer"] is None and "withheld" in out["status_message"]


@pytest.mark.parametrize("labels,verified", [(["financial"], False),      # not verified
                                             (["Financial!!"], True),     # malformed
                                             (None, False)])              # old envelope
async def test_unverified_or_absent_peer_labels_are_unknown(monkeypatch, labels, verified):
    from agent.state import FlowDecision
    nodes = _wire_peer(monkeypatch, [HR, LEGAL], _Auth())
    # Claimed "financial" is NOT trusted → no hr-finance rule; the answer still flows
    # (back-compat) because {hr, unlabeled-peer} is below the backstop.
    await nodes.check_auth(_state([HR]))
    out = await nodes.handle_peer_result(_peer_state(labels, verified=verified))
    assert out["flow"] == FlowDecision.REMOTE_APPROVED
    # ...but it is NOT "no labels": with {hr, legal} released locally the unknown peer label
    # makes 3 → the AGT backstop escalates instead of passing silently.
    cg.LEDGER.clear()
    await nodes.check_auth(_state([HR, LEGAL]))
    out = await nodes.handle_peer_result(_peer_state(labels, verified=verified))
    assert out["flow"] == FlowDecision.LOCAL_NEEDS_APPROVAL
    assert out["pending_chunk_ids"] == [
        cg.backstop_clearance_id({"hr", "legal", cg.UNLABELED_PEER_LABEL})]


async def test_start_approval_carries_contributing_sources(monkeypatch):
    """B: the approval request for a mosaic clearance names the contributing sources."""
    import approval_index
    nodes = _wire_peer(monkeypatch, [HR], _Auth())
    await nodes.check_auth(_state([HR]))
    esc = await nodes.handle_peer_result(_peer_state(["financial"]))

    class _FGA:
        async def set_pending_approval(self, user, cid): ...
        async def get_chunk_owner(self, cid): return None

    started, recorded = [], []

    class _Temporal:
        async def start_workflow(self, fn, inp, **kw): started.append(inp)

    async def fga():
        return _FGA()

    async def temporal():
        return _Temporal()

    async def record(approver, rid, user, query, sources=None):
        recorded.append(sources)
    monkeypatch.setattr(nodes, "_get_openfga", fga)
    monkeypatch.setattr(nodes, "_get_temporal", temporal)
    monkeypatch.setattr(approval_index, "record", record)
    out = await nodes.start_approval({**_peer_state(["financial"]), **esc})
    assert out["approval_request_id"]
    assert started[0].chunk_ids == ["mosaic-hr-finance"]
    assert started[0].sources == esc["approval_sources"] == recorded[0]
    assert any("hr_compensation_data.txt [hr]" in s for s in started[0].sources)
    assert any(s.startswith("peer beta") and "[financial]" in s for s in started[0].sources)


async def test_local_mosaic_escalation_lists_local_sources(monkeypatch):
    nodes = _wire(monkeypatch, [HR, FIN, PLAIN], _Auth())
    out = await nodes.check_auth(_state([HR, FIN, PLAIN]))
    srcs = out["approval_sources"]
    assert any(s.endswith("hr_compensation_data.txt [hr]") for s in srcs)
    assert any(s.endswith("q4_financial_results.txt [financial]") for s in srcs)
    assert not any("bias_testing" in s for s in srcs)                 # non-contributing


# ── Answering side: labels computed + carried in the signed /a2a/query response ──

def test_answering_peer_reports_labels_of_used_chunks_only():
    from agent.graph import _answer_data_labels
    from agent.state import FlowDecision
    st = {"flow": FlowDecision.LOCAL_ALLOWED, "answer": "a", "allowed_chunk_ids": ["fin1"],
          "fused_chunks": [FIN, HR]}
    assert _answer_data_labels(st) == ["financial"]          # HR not served → not reported
    assert _answer_data_labels({**st, "flow": FlowDecision.LOCAL_NEEDS_APPROVAL}) is None


def test_a2a_response_payload_carries_labels_only_when_completed():
    from api import main
    done = {"status_message": "completed", "answer": "x", "flow": "local_allowed",
            "task_id": "t", "data_labels": ["financial"]}
    p = main._a2a_query_response_payload(done, "t")
    assert p["status"] == "completed" and p["data_labels"] == ["financial"]
    assert set(p) == {"status", "answer", "task_id", "approval_request_id", "data_labels"}
    pend = main._a2a_query_response_payload({**done, "approval_request_id": "r"}, "t")
    assert "data_labels" not in pend
    unknown = main._a2a_query_response_payload({**done, "data_labels": None}, "t")
    assert "data_labels" not in unknown                      # omitted → requester: unlabeled


async def test_labels_are_covered_by_the_peer_response_signature(monkeypatch):
    """Real Ed25519 signing/verification (mesh.peer_client): labels in a validly signed
    response are verified; an old-envelope response has none (back-compat, unlabeled); a
    response whose labels were altered after signing is rejected outright."""
    import json
    import time
    import uuid

    import httpx
    from agentmesh.exceptions import AgentMeshError

    import mesh.agent_identity as ai
    from config import settings
    from mesh import peer_client as pc
    from mesh.agent_identity import AgentIdentity, _canonical_bytes

    self_id = AgentIdentity.create(name="alpha", sponsor="alpha@example.com")
    beta = AgentIdentity.create(name="beta", sponsor="beta@example.com")
    url = "http://beta-agent.internal:9100"
    monkeypatch.setattr(settings, "peer_trust_map", json.dumps({str(beta.did): {
        "issuer": "http://beta/realms/rag", "agent_url": url, "division_id": "beta",
        "public_jwk": json.dumps(beta.to_jwk(include_private=False))}}))
    monkeypatch.setattr(settings, "peer_agent_url", url)
    monkeypatch.setattr(settings, "peer_agent_did", str(beta.did))
    monkeypatch.setattr(ai, "_identity", self_id)
    monkeypatch.setattr(ai, "_identity_registry", None)
    monkeypatch.setattr(ai, "_seen_nonces", {})

    async def _no_redis(_did, _nonce):
        return None
    monkeypatch.setattr(ai, "_seen_nonce_redis", _no_redis)
    monkeypatch.setattr(pc, "_circuit_breakers", {})

    reply: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = {"status": "completed", "answer": PEER_FIN_ANSWER, "task_id": "t",
                "approval_request_id": None, **reply.get("extra", {})}
        signed = dict(body, ts=int(time.time()), nonce=str(uuid.uuid4()))
        signed["_agentmesh"] = {"sender_did": str(beta.did), "alg": "EdDSA",
                                "signature": beta.sign(_canonical_bytes(signed))}
        signed.update(reply.get("tamper", {}))
        return httpx.Response(200, json=signed)

    real_client = httpx.AsyncClient

    class _Client(real_client):
        def __init__(self, *a, **k):
            k.pop("verify", None)
            super().__init__(*a, transport=httpx.MockTransport(handler), **k)
    monkeypatch.setattr(pc.httpx, "AsyncClient", _Client)

    reply.update(extra={"data_labels": ["financial"]})
    r = await pc.call_peer_agent("q", "alice", "ctx", user_assertion={"sub": "a"})
    assert (r.data_labels, r.labels_verified) == (["financial"], True)

    reply.clear()                                            # old-envelope peer
    r = await pc.call_peer_agent("q", "alice", "ctx", user_assertion={"sub": "a"})
    assert (r.data_labels, r.labels_verified) == (None, False)
    assert r.answer == PEER_FIN_ANSWER                       # still delivered

    reply.update(extra={"data_labels": ["financial"]}, tamper={"data_labels": []})
    with pytest.raises(AgentMeshError):                      # stripped label → bad signature
        await pc.call_peer_agent("q", "alice", "ctx", user_assertion={"sub": "a"})
