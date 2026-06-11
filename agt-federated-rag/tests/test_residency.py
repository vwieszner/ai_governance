"""Data-residency enforcement tests (IMPLEMENTATION_PLAN.md M6, NFR-1).

Pins the fail-closed guard: when residency_mode == 'local', inference may NOT egress to
an external endpoint; in 'external' mode it may. In-boundary = loopback / private IP /
internal DNS (a self-hosted inference sidecar).
"""
from __future__ import annotations

import pytest


def test_is_inboundary_url():
    from residency import is_inboundary_url
    assert is_inboundary_url("http://localhost:11434/v1")
    assert is_inboundary_url("http://127.0.0.1:9000")
    assert is_inboundary_url("http://llm.svc.cluster.local/v1")
    assert is_inboundary_url("http://10.0.1.5:8080")          # private IPv4
    assert not is_inboundary_url("https://integrate.api.nvidia.com/v1")
    assert not is_inboundary_url("https://api.openai.com/v1")
    assert not is_inboundary_url("")


def test_local_mode_blocks_external_egress(make_settings, monkeypatch):
    import residency
    monkeypatch.setattr(residency, "settings", make_settings(residency_mode="local"))
    with pytest.raises(RuntimeError):
        residency.assert_inference_allowed("https://integrate.api.nvidia.com/v1", "LLM")


def test_local_mode_allows_inboundary_endpoint(make_settings, monkeypatch):
    import residency
    monkeypatch.setattr(residency, "settings", make_settings(residency_mode="local"))
    residency.assert_inference_allowed("http://localhost:11434/v1", "LLM")        # no raise
    residency.assert_inference_allowed("http://inference.svc.cluster.local", "LLM")  # no raise


def test_external_mode_allows_external_endpoint(make_settings, monkeypatch):
    import residency
    monkeypatch.setattr(residency, "settings", make_settings(residency_mode="external"))
    residency.assert_inference_allowed("https://integrate.api.nvidia.com/v1", "LLM")  # no raise
