"""In-process governed tool registry tests (local_tools.py).

Three concerns:
  1. the REAL tools compute correctly and SAFELY — pii_scan is a DLP screen (the no-leak
     invariant + Luhn validation are load-bearing security properties; do NOT relax them);
     compliance_lookup is a deterministic obligation KB (a clean miss must NOT raise);
     risk_assess is an EU AI Act risk-tier classifier (conservative default, never raises);
     classify is a data-sensitivity classifier (reuses the DLP detectors, no raw leak).
  2. per-division tool assignment (AGT_LOCAL_TOOLS) genuinely changes which tools a division
     serves, so the cross-agent delegation demo has real asymmetry.
  3. execution flows through the governed executor: run_local_tool passes every gate
     (policy → gateway → §4.2 credential boundary) and an unconfigured server / a
     credential-bearing argument still fails closed through the path.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from tools import local_tools
from tools import mcp as mcp_tools
from tools.local_tools import classify, compliance_lookup, fin_check, pii_scan, risk_assess


def _patch_enforce_ok(monkeypatch):
    async def ok(action, ctx):
        return None
    monkeypatch.setattr("agent.nodes._enforce", ok)


# ── tool.pii: a real PII / DLP screen ─────────────────────────────────────────
def test_pii_detects_email_card_ssn():
    # A Luhn-VALID card (4242424242424242), an email, and a US SSN — all three detected.
    text = "Contact alice@example.com, card 4242424242424242, SSN 123-45-6789."
    out = pii_scan({"text": text})
    assert out["has_pii"] is True
    types = {f["type"] for f in out["findings"]}
    assert {"EMAIL", "CARD", "SSN"} <= types
    assert out["counts"]["EMAIL"] == 1
    assert out["counts"]["CARD"] == 1
    assert out["counts"]["SSN"] == 1


def test_pii_findings_are_masked_last4_only_and_never_raw():
    # SECURITY (no-leak invariant): findings expose only a last-4 mask; the RAW PII value is
    # NOWHERE in the structured output. This is the whole point of a DLP tool.
    text = "card 4242424242424242 ssn 123-45-6789 mail alice@example.com"
    out = pii_scan({"text": text})
    serialized = json.dumps(out)
    # Raw values absent from the output entirely.
    assert "4242424242424242" not in serialized
    assert "123-45-6789" not in serialized
    assert "alice@example.com" not in serialized
    # Masks are last-4 only.
    for f in out["findings"]:
        assert f["masked"].startswith("****")
        assert len(f["masked"]) == 8 or f["masked"].count("*") == 4  # "****" + up to 4 tail
    by_type = {f["type"]: f["masked"] for f in out["findings"]}
    assert by_type["CARD"] == "****4242"
    assert by_type["SSN"] == "****6789"


def test_pii_redacted_replaces_each_span_with_marker():
    text = "card 4242424242424242 and ssn 123-45-6789"
    out = pii_scan({"text": text})
    assert "[CARD_REDACTED]" in out["redacted"]
    assert "[SSN_REDACTED]" in out["redacted"]
    # The raw spans are gone from the redacted text too.
    assert "4242424242424242" not in out["redacted"]
    assert "123-45-6789" not in out["redacted"]


def test_pii_luhn_invalid_card_is_not_flagged():
    # 4242424242424241 fails the Luhn checksum → must NOT be classified as a credit card
    # (a DLP tool that flagged every 16-digit number would be useless). It may match nothing.
    out = pii_scan({"text": "order id 4242424242424241 shipped"})
    assert not any(f["type"] == "CARD" for f in out["findings"])


def test_pii_detects_iban_ipv4_phone():
    out = pii_scan({"text": "IBAN GB82WEST12345698765432, host 192.168.1.1, tel +1 415 555 2671"})
    types = {f["type"] for f in out["findings"]}
    assert {"IBAN", "IPV4", "PHONE"} <= types


def test_pii_clean_text_has_no_pii():
    out = pii_scan({"text": "The quarterly governance review concluded without findings."})
    assert out["has_pii"] is False
    assert out["findings"] == []
    assert out["counts"] == {}
    assert out["redacted"] == "The quarterly governance review concluded without findings."


def test_pii_oversized_input_raises():
    # DoS guard: an input over the bound is refused before the regex engine runs on it.
    with pytest.raises(ValueError):
        pii_scan({"text": "a" * 20_001})


def test_pii_non_string_input_raises():
    with pytest.raises(ValueError):
        pii_scan({"text": 12345})


# ── tool.compliance: deterministic obligation lookup ──────────────────────────
def test_compliance_known_topic_returns_matches():
    out = compliance_lookup({"topic": "human oversight requirements for high-risk AI"})
    assert out["topic"].startswith("human oversight")
    assert out["matches"], "a known topic must return at least one obligation"
    # Each match is well-formed.
    for m in out["matches"]:
        assert set(m) == {"framework", "article", "summary"}
    frameworks = {m["framework"] for m in out["matches"]}
    assert "EU AI Act" in frameworks


def test_compliance_topic_matches_multiple_frameworks():
    # "automated decision" pulls in both GDPR Art. 22 and EU AI Act human-oversight.
    out = compliance_lookup({"topic": "automated decision making"})
    frameworks = {m["framework"] for m in out["matches"]}
    assert {"GDPR", "EU AI Act"} <= frameworks


def test_compliance_unknown_topic_returns_empty_not_raise():
    # A clean miss is a NORMAL outcome — empty matches, NEVER an exception.
    out = compliance_lookup({"topic": "favourite pizza toppings"})
    assert out == {"topic": "favourite pizza toppings", "matches": []}


def test_compliance_oversized_topic_raises():
    with pytest.raises(ValueError):
        compliance_lookup({"topic": "x" * 600})


def test_compliance_non_string_raises():
    with pytest.raises(ValueError):
        compliance_lookup({"topic": 42})


# ── tool.risk: EU AI Act risk-tier classifier ─────────────────────────────────
def test_risk_high_risk_description_returns_high_tier_with_obligations():
    out = risk_assess({"description": "An AI system for credit scoring and loan approval."})
    assert out["tier"] == "high"
    assert out["score"] == 75
    assert out["obligations"], "a high-risk tier must carry obligations"
    # Rationale names the matched signal (auditable, deterministic).
    assert "credit scoring" in out["rationale"] or "loan approval" in out["rationale"]


def test_risk_prohibited_description_returns_unacceptable():
    out = risk_assess({"description":
                       "Real-time remote biometric identification for mass surveillance."})
    assert out["tier"] == "unacceptable"
    assert out["score"] == 100
    assert any("PROHIBITED" in o for o in out["obligations"])


def test_risk_limited_description_returns_limited():
    out = risk_assess({"description": "A customer-support chatbot answering product FAQs."})
    assert out["tier"] == "limited"


def test_risk_benign_description_returns_minimal():
    out = risk_assess({"description": "A spam filter for the corporate mailbox."})
    assert out["tier"] == "minimal"
    assert out["score"] == 10


def test_risk_highest_signal_wins_over_lower():
    # A description carrying BOTH a chatbot (limited) and a biometric-surveillance
    # (unacceptable) signal must resolve to the highest tier present.
    out = risk_assess({"description":
                       "A chatbot front-end for real-time remote biometric identification."})
    assert out["tier"] == "unacceptable"


def test_risk_unknown_input_defaults_conservatively_and_never_raises():
    # No recognised signal → conservative 'limited' default, with a rationale, never minimal,
    # never an exception.
    out = risk_assess({"description": "A tool that schedules office-plant watering."})
    assert out["tier"] == "limited"
    assert "conservativ" in out["rationale"].lower()
    # Empty string is also a clean (non-raising) miss.
    assert risk_assess({"description": ""})["tier"] == "limited"


def test_risk_oversized_and_non_string_raise():
    with pytest.raises(ValueError):
        risk_assess({"description": "a" * 20_001})
    with pytest.raises(ValueError):
        risk_assess({"description": 123})


# ── tool.classify: data-sensitivity classifier ────────────────────────────────
def test_classify_card_and_confidential_marker_is_restricted():
    # Regulated PII (a Luhn-valid card) and a "confidential" marker → most-sensitive label.
    out = classify({"text": "CONFIDENTIAL memo. Card on file 4242424242424242."})
    assert out["label"] == "Restricted"
    assert out["handling"]
    # SECURITY: the raw card never appears in the signals/handling.
    assert "4242424242424242" not in json.dumps(out)


def test_classify_regulated_pii_alone_is_restricted():
    out = classify({"text": "Employee SSN 123-45-6789 on file."})
    assert out["label"] == "Restricted"
    assert "123-45-6789" not in json.dumps(out)


def test_classify_explicit_restricted_header():
    out = classify({"text": "Classification: Restricted\nThe figures follow."})
    assert out["label"] == "Restricted"


def test_classify_other_pii_is_confidential():
    out = classify({"text": "Reach the lead at alice@example.com for details."})
    assert out["label"] == "Confidential"
    assert "alice@example.com" not in json.dumps(out)


def test_classify_credential_is_restricted():
    out = classify({"text": "Deploy with API_KEY=sk-livesecretvalue in the env."})
    assert out["label"] == "Restricted"
    assert "sk-livesecretvalue" not in json.dumps(out)


def test_classify_internal_marker():
    out = classify({"text": "Internal use only — the FY26 roadmap draft."})
    assert out["label"] == "Internal"


def test_classify_clean_text_is_public():
    out = classify({"text": "Our public documentation explains how to get started."})
    assert out["label"] == "Public"
    assert out["signals"] == []


def test_classify_oversized_and_non_string_raise():
    with pytest.raises(ValueError):
        classify({"text": "a" * 20_001})
    with pytest.raises(ValueError):
        classify({"text": None})


# ── tool.fincheck: finance / AML transaction screen ───────────────────────────
def test_fincheck_sanctioned_counterparty_is_flagged():
    out = fin_check({"amount": 200, "currency": "USD", "counterparty": "Volkov Holdings"})
    assert out["flagged"] is True
    assert out["risk"] == "high"
    assert any("sanctions" in r for r in out["reasons"])
    # Case + whitespace are normalised before the watchlist comparison.
    out2 = fin_check({"amount": 200, "currency": "USD", "counterparty": "VOLKOV  holdings"})
    assert out2["flagged"] is True


def test_fincheck_large_amount_requires_disclosure():
    out = fin_check({"amount": 50000, "currency": "USD", "counterparty": "Acme Corp"})
    assert out["disclosure_required"] is True
    assert out["flagged"] is False
    assert any("disclosure" in r for r in out["reasons"])
    # Echoes the inputs it was given.
    assert out["amount"] == 50000
    assert out["currency"] == "USD"


def test_fincheck_high_risk_currency_elevates_risk():
    out = fin_check({"amount": 200, "currency": "KPW", "counterparty": "Acme Corp"})
    assert out["risk"] == "high"
    assert any("higher-risk jurisdiction" in r for r in out["reasons"])


def test_fincheck_clean_small_usd_transaction_is_not_flagged():
    out = fin_check({"amount": 500, "currency": "USD", "counterparty": "Acme Corp"})
    assert out["flagged"] is False
    assert out["disclosure_required"] is False
    assert out["risk"] == "low"
    assert out["reasons"] == []


def test_fincheck_all_three_controls_fire_together():
    out = fin_check({"amount": 50000, "currency": "KPW", "counterparty": "Redline Imports"})
    assert out["flagged"] is True
    assert out["disclosure_required"] is True
    assert out["risk"] == "high"
    assert len(out["reasons"]) == 3


def test_fincheck_validates_types_and_bounds():
    with pytest.raises(ValueError):
        fin_check({"amount": "lots", "currency": "USD", "counterparty": "Acme"})
    with pytest.raises(ValueError):
        fin_check({"amount": True, "currency": "USD", "counterparty": "Acme"})  # bool not number
    with pytest.raises(ValueError):
        fin_check({"amount": 10, "currency": 5, "counterparty": "Acme"})
    with pytest.raises(ValueError):
        fin_check({"amount": 10, "currency": "USD", "counterparty": "A" * 300})


# ── per-division tool assignment (AGT_LOCAL_TOOLS) ────────────────────────────
_ALL_SERVERS = {"pii-scan", "compliance-lookup", "risk-score", "data-classify", "fin-check"}


def test_filter_unset_serves_all_tools(monkeypatch):
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    assert local_tools.server_for_capability("tool.pii") == "pii-scan"
    assert local_tools.server_for_capability("tool.compliance") == "compliance-lookup"
    assert local_tools.server_for_capability("tool.risk") == "risk-score"
    assert local_tools.server_for_capability("tool.classify") == "data-classify"
    assert local_tools.server_for_capability("tool.fincheck") == "fin-check"
    names = {c["name"] for c in local_tools.local_server_configs()}
    assert names == _ALL_SERVERS


def test_filter_full_capability_id_restricts_to_one_tool(monkeypatch):
    # "compliance division" pattern: serves ONLY tool.pii.
    monkeypatch.setenv("AGT_LOCAL_TOOLS", "tool.pii")
    assert local_tools.server_for_capability("tool.pii") == "pii-scan"
    assert local_tools.server_for_capability("tool.compliance") is None
    names = {c["name"] for c in local_tools.local_server_configs()}
    assert names == {"pii-scan"}
    # capability_for also reflects the filter: the disabled server reports None.
    assert local_tools.capability_for("pii-scan") == "tool.pii"
    assert local_tools.capability_for("compliance-lookup") is None


def test_filter_accepts_short_names(monkeypatch):
    # Short-name CSV ("pii,compliance") enables both.
    monkeypatch.setenv("AGT_LOCAL_TOOLS", "pii,compliance")
    names = {c["name"] for c in local_tools.local_server_configs()}
    assert names == {"pii-scan", "compliance-lookup"}
    # Just "compliance" → only compliance-lookup.
    monkeypatch.setenv("AGT_LOCAL_TOOLS", "compliance")
    assert local_tools.server_for_capability("tool.compliance") == "compliance-lookup"
    assert local_tools.server_for_capability("tool.pii") is None
    names = {c["name"] for c in local_tools.local_server_configs()}
    assert names == {"compliance-lookup"}


def test_filter_unknown_token_enables_nothing(monkeypatch):
    # A typo / unknown capability never silently enables a real tool.
    monkeypatch.setenv("AGT_LOCAL_TOOLS", "tool.bogus")
    assert local_tools.server_for_capability("tool.pii") is None
    assert local_tools.server_for_capability("tool.compliance") is None
    assert local_tools.local_server_configs() == []


def test_filter_subset_with_new_tools(monkeypatch):
    # A division can own any SUBSET — e.g. the "risk + classification" department serves
    # tool.risk + tool.classify but NOT pii/compliance (which live on other divisions).
    monkeypatch.setenv("AGT_LOCAL_TOOLS", "risk,classify")
    assert local_tools.server_for_capability("tool.risk") == "risk-score"
    assert local_tools.server_for_capability("tool.classify") == "data-classify"
    assert local_tools.server_for_capability("tool.pii") is None
    assert local_tools.server_for_capability("tool.compliance") is None
    names = {c["name"] for c in local_tools.local_server_configs()}
    assert names == {"risk-score", "data-classify"}


# ── registry helpers ──────────────────────────────────────────────────────────
def test_capability_mapping(monkeypatch):
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    assert local_tools.capability_for("pii-scan") == "tool.pii"
    assert local_tools.capability_for("compliance-lookup") == "tool.compliance"
    assert local_tools.capability_for("risk-score") == "tool.risk"
    assert local_tools.capability_for("data-classify") == "tool.classify"
    assert local_tools.capability_for("fin-check") == "tool.fincheck"
    assert local_tools.capability_for("nope") is None
    assert local_tools.server_for_capability("tool.pii") == "pii-scan"
    assert local_tools.server_for_capability("tool.compliance") == "compliance-lookup"
    assert local_tools.server_for_capability("tool.risk") == "risk-score"
    assert local_tools.server_for_capability("tool.classify") == "data-classify"
    assert local_tools.server_for_capability("tool.fincheck") == "fin-check"
    assert local_tools.server_for_capability("tool.nope") is None


def test_local_server_configs_shape(monkeypatch):
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    configs = {c["name"]: c for c in local_tools.local_server_configs()}
    assert set(configs) == _ALL_SERVERS
    pii_cfg = configs["pii-scan"]
    assert pii_cfg["auth_mode"] == "service_rebac"
    assert pii_cfg["require_tls"] is False
    assert pii_cfg["url"] == ""
    assert pii_cfg["capability"] == "tool.pii"
    assert "scan" in pii_cfg["tools"]


# ── execution through the governance gates ────────────────────────────────────
def test_run_local_tool_executes_through_gates(monkeypatch):
    _patch_enforce_ok(monkeypatch)
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    # Start from a clean (empty) mcp_servers; run_local_tool registers the locals itself.
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()

    out = asyncio.run(local_tools.run_local_tool(
        "pii-scan", "scan", {"text": "ping alice@example.com"}))
    assert out["has_pii"] is True
    assert any(f["type"] == "EMAIL" for f in out["findings"])

    out = asyncio.run(local_tools.run_local_tool(
        "compliance-lookup", "lookup", {"topic": "transparency"}))
    assert out["matches"]

    out = asyncio.run(local_tools.run_local_tool(
        "risk-score", "assess", {"description": "credit scoring for loan approval"}))
    assert out["tier"] == "high"

    out = asyncio.run(local_tools.run_local_tool(
        "data-classify", "classify", {"text": "Card 4242424242424242 on file"}))
    assert out["label"] == "Restricted"

    out = asyncio.run(local_tools.run_local_tool(
        "fin-check", "screen",
        {"amount": 50000, "currency": "USD", "counterparty": "Volkov Holdings"}))
    assert out["flagged"] is True
    assert out["disclosure_required"] is True


def test_ensure_local_servers_registered_is_idempotent(monkeypatch):
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    local_tools.ensure_local_servers_registered()
    first = json.loads(mcp_tools.settings.mcp_servers)
    names = sorted(s["name"] for s in first)
    assert names == sorted(_ALL_SERVERS)
    # Calling again does not duplicate entries.
    local_tools.ensure_local_servers_registered()
    second = json.loads(mcp_tools.settings.mcp_servers)
    assert len(second) == len(first)


def test_ensure_local_servers_preserves_existing(monkeypatch):
    # An already-configured (real) MCP server must survive the merge.
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers",
                        '[{"name":"jira","url":"https://mcp/jira","allowed_auth_methods":["oauth2"]}]')
    mcp_tools.reset_cache()
    local_tools.ensure_local_servers_registered()
    names = sorted(s["name"] for s in json.loads(mcp_tools.settings.mcp_servers))
    assert names == sorted(_ALL_SERVERS | {"jira"})


def test_filtered_division_only_registers_its_tool(monkeypatch):
    # A division serving only tool.pii registers ONLY pii-scan in the gateway settings.
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setenv("AGT_LOCAL_TOOLS", "tool.pii")
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    local_tools.ensure_local_servers_registered()
    names = sorted(s["name"] for s in json.loads(mcp_tools.settings.mcp_servers))
    assert names == ["pii-scan"]
    # And calling the compliance tool it does NOT serve fails closed at the gateway.
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(local_tools.run_local_tool(
            "compliance-lookup", "lookup", {"topic": "transparency"}))


def test_stale_gateway_is_reset_so_local_tool_does_not_spuriously_fail(monkeypatch):
    """Regression (ordering hazard): a gateway cached from a DIFFERENT settings.mcp_servers
    that lacked the local servers must NOT cause run_local_tool to fail closed once settings
    list the local servers again. ensure_local_servers_registered detects the stale cache and
    resets it. Order-independent on its OWN — no autouse reset crutch needed."""
    _patch_enforce_ok(monkeypatch)
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)

    # 1. Warm the executor's gateway from a settings value WITHOUT the local servers.
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers",
                        '[{"name":"jira","url":"https://mcp/jira","allowed_auth_methods":["oauth2"]}]')
    mcp_tools.reset_cache()
    mcp_tools._load_servers()                       # builds + CACHES the stale gateway
    assert "pii-scan" not in (mcp_tools._server_cfg or {})   # cache predates our servers

    # 2. Now settings DOES list the local servers, but the cached gateway is stale.
    settings_with_locals = json.dumps(
        [{"name": "jira", "url": "https://mcp/jira", "allowed_auth_methods": ["oauth2"]}]
        + local_tools.local_server_configs()
    )
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", settings_with_locals)

    # 3. run_local_tool calls ensure_local_servers_registered, which must spot the stale
    #    gateway and reset it so the call succeeds rather than raising "not configured".
    out = asyncio.run(local_tools.run_local_tool(
        "pii-scan", "scan", {"text": "ping alice@example.com"}))
    assert out["has_pii"] is True
    # The gateway was rebuilt and now includes the local servers (jira preserved too).
    assert {"jira", "pii-scan", "compliance-lookup"}.issubset(set(mcp_tools._server_cfg or {}))


def test_unconfigured_server_fails_closed_via_local_caller(monkeypatch):
    # Governance still applies when wiring local_caller directly: a server that is NOT in
    # settings.mcp_servers is rejected at the gateway (gate 2) before local_caller runs.
    _patch_enforce_ok(monkeypatch)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")  # nothing configured
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(mcp_tools.call_mcp_tool("pii-scan", "scan", {"text": "x"},
                                            caller=local_tools.local_caller))


def test_policy_denial_blocks_local_tool(monkeypatch):
    # Gate 1 (policy default-deny) still fires for local tools.
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)

    async def deny(action, ctx):
        raise PermissionError("policy denied")
    monkeypatch.setattr("agent.nodes._enforce", deny)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    with pytest.raises(PermissionError):
        asyncio.run(local_tools.run_local_tool("pii-scan", "scan", {"text": "x"}))


def test_credential_in_arguments_fails_closed_via_run_local_tool(monkeypatch):
    # §4.2 boundary holds through the new path: a credential field in the arguments is
    # refused (McpToolError) before the tool runs. Proves the guard isn't bypassed.
    _patch_enforce_ok(monkeypatch)
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(local_tools.run_local_tool(
            "pii-scan", "scan", {"text": "x", "token": "SECRET"}))


def test_unknown_tool_on_local_server_fails_closed(monkeypatch):
    # A configured server but a tool name it does not serve → McpToolError from local_caller.
    _patch_enforce_ok(monkeypatch)
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(local_tools.run_local_tool("pii-scan", "nonexistent", {"text": "x"}))


def test_tool_value_error_wraps_to_mcptoolerror(monkeypatch):
    # A ValueError from the tool (e.g. oversized input) must surface as McpToolError through
    # the governed path — NOT leak as a raw exception. local_caller wraps (ValueError, ...).
    _patch_enforce_ok(monkeypatch)
    monkeypatch.delenv("AGT_LOCAL_TOOLS", raising=False)
    monkeypatch.setattr(mcp_tools.settings, "mcp_servers", "")
    mcp_tools.reset_cache()
    with pytest.raises(mcp_tools.McpToolError):
        asyncio.run(local_tools.run_local_tool("pii-scan", "scan", {"text": "a" * 20_001}))
