"""
SRE instrumentation built on the Microsoft Agent Governance Toolkit's
``agent_sre`` package — request-level SLO tracking for the API server.

The toolkit's ``agent_sre.slo`` provides ``SLI`` (a Service Level Indicator,
abstract) and ``SLO`` (a Service Level Objective with an error budget). This
module supplies a concrete latency SLI and a pure-ASGI middleware that records
one good/bad event per HTTP request against an ``agent_sre`` SLO.
"""
from __future__ import annotations

import time
from typing import Any

import structlog
from agent_sre.slo import SLI, SLO, SLIValue

log = structlog.get_logger(__name__)


class LatencyComplianceSLI(SLI):
    """Concrete ``agent_sre`` SLI: fraction of requests within the latency budget.

    Each request records 1.0 (within budget) or 0.0 (breached). ``collect()``
    returns the mean over the configured window — the measured compliance ratio.
    """

    def collect(self) -> SLIValue:
        values = self.values_in_window()
        if not values:
            return SLIValue(name=self.name, value=1.0)
        ratio = sum(v.value for v in values) / len(values)
        return SLIValue(name=self.name, value=ratio)


class SREMiddleware:
    """
    Pure-ASGI middleware that records request latency against an ``agent_sre``
    SLO. Pure ASGI (not BaseHTTPMiddleware) so it never buffers SSE responses.

    For every HTTP request it measures wall-clock latency and records a good/bad
    event (good = latency <= slo_latency_p99_ms). ``agent_sre`` maintains the SLI
    window and error budget; breaches are observable via ``slo.evaluate()``.
    """

    def __init__(self, app: Any, slo_latency_p99_ms: float) -> None:
        self.app = app
        self._budget_ms = slo_latency_p99_ms
        self._sli = LatencyComplianceSLI(
            name="request_latency_compliance",
            target=0.99,
            window="1h",
        )
        self._slo = SLO(
            name="api_latency_slo",
            indicators=[self._sli],
            description=f"99% of requests served within {slo_latency_p99_ms:.0f} ms",
            agent_id="federated-rag-agent",
        )

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.monotonic()
        try:
            await self.app(scope, receive, send)
        finally:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            good = elapsed_ms <= self._budget_ms
            try:
                self._sli.record(1.0 if good else 0.0, metadata={"latency_ms": elapsed_ms})
                self._slo.record_event(good=good)
            except Exception as exc:  # noqa: BLE001 — instrumentation must never break a request
                log.warning("sre_record_failed", error=str(exc))
            if not good:
                log.warning(
                    "sre_latency_slo_breach",
                    latency_ms=round(elapsed_ms, 1),
                    budget_ms=self._budget_ms,
                )
