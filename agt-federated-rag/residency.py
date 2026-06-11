"""Data-residency / inference-egress enforcement (IMPLEMENTATION_PLAN.md M6, NFR-1).

When a division runs with ``residency_mode == "local"``, inference (LLM generation +
intent classification) must stay WITHIN the division boundary — no egress to a public
hosted endpoint (e.g. NVIDIA NIM). This module is the fail-closed guard: the LLM client
factories call :func:`assert_inference_allowed` before constructing a client, so a
mis-deployment surfaces immediately as a clear error instead of silently shipping prompts
(which may contain authorized chunk text) to an external provider.

Retrieval embeddings already run in-boundary (FastEmbed, on-device) so they are not an
egress vector; this guard therefore focuses on the LLM endpoint (``OPENAI_API_BASE``).
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from config import settings

_INBOUNDARY_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
# Internal DNS suffixes (k8s service DNS, private domains). A local self-hosted inference
# sidecar/service resolves to one of these or to a private/loopback IP.
_INBOUNDARY_SUFFIXES = (".internal", ".local", ".svc", ".cluster.local", ".svc.cluster.local")


def is_inboundary_url(url: str) -> bool:
    """True if ``url`` resolves inside the division boundary — loopback, a private IP,
    or an internal DNS name — i.e. NOT a public hosted endpoint."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    if host in _INBOUNDARY_HOSTS or any(host.endswith(s) for s in _INBOUNDARY_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def assert_inference_allowed(base_url: str, kind: str = "inference") -> None:
    """M6/NFR-1: in ``residency_mode == "local"``, refuse to egress *kind* to an external
    endpoint. In ``"external"`` mode (the default) any endpoint is allowed.

    Raises:
        RuntimeError: residency is local but ``base_url`` is a public endpoint.
    """
    if settings.residency_mode == "local" and not is_inboundary_url(base_url):
        host = urlparse(base_url).hostname or base_url
        raise RuntimeError(
            f"residency_mode=local forbids external {kind} egress to {host!r}. "
            f"Point OPENAI_API_BASE at a self-hosted / in-boundary endpoint, or set "
            f"residency_mode=external if egress is permitted for this division."
        )
