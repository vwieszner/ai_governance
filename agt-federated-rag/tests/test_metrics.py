"""Prometheus metrics tests (Phase-1 item 13).

The /metrics counters are fed by the same agt_audit hook as the audit chain — pin that an
agt_audit event bumps its counter and that render_prometheus emits valid text format.
"""
from __future__ import annotations


def test_agt_audit_event_increments_metric(monkeypatch):
    import audit_log
    # isolate the counter
    monkeypatch.setattr(audit_log, "_metrics", {})
    audit_log._audit_processor(None, "info", {"event": "auth_decision", "agt_audit": True, "allowed": True})
    audit_log._audit_processor(None, "info", {"event": "auth_decision", "agt_audit": True, "allowed": False})
    audit_log._audit_processor(None, "info", {"event": "noise", "x": 1})   # not agt_audit -> ignored
    out = audit_log.render_prometheus()
    assert 'agt_audit_events_total{event="auth_decision"} 2' in out
    assert "agt_audit_events_sum 2" in out
    assert "noise" not in out


def test_render_prometheus_is_valid_textformat(monkeypatch):
    import audit_log
    monkeypatch.setattr(audit_log, "_metrics", {"a2a_query_signature_invalid": 3})
    out = audit_log.render_prometheus()
    # HELP/TYPE headers present; metric line well-formed
    assert "# TYPE agt_audit_events_total counter" in out
    assert 'agt_audit_events_total{event="a2a_query_signature_invalid"} 3' in out
    assert out.endswith("\n")


def test_metrics_endpoint_gated_when_token_set(monkeypatch):
    # /metrics is open by default but requires the bearer token when METRICS_TOKEN is set,
    # so the governance counters aren't world-readable recon.
    import asyncio
    from api import main

    # token unset -> open
    monkeypatch.setattr(main.settings, "metrics_token", "")
    assert asyncio.run(main.metrics(authorization=None)).status_code == 200

    # token set -> 401 without/with-wrong header, 200 with correct
    monkeypatch.setattr(main.settings, "metrics_token", "scrape-secret")
    import pytest
    with pytest.raises(main.HTTPException) as ei:
        asyncio.run(main.metrics(authorization=None))
    assert ei.value.status_code == 401
    with pytest.raises(main.HTTPException):
        asyncio.run(main.metrics(authorization="Bearer wrong"))
    assert asyncio.run(main.metrics(authorization="Bearer scrape-secret")).status_code == 200
