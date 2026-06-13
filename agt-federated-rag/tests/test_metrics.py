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
