"""Egress-safety SSRF denylist (A2-SSRF), dependency-free.

Lives in its own module (no ``config`` import) so non-RAG layers can reuse it without pulling in
division settings — e.g. transport/ocsp.py vets the OCSP responder URL inside the TLS handshake.
``rag.retriever._is_egress_unsafe_raas_host`` re-exports :func:`is_egress_unsafe_host`.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

# ── Egress-safety denylist (SSRF, A2-SSRF) ────────────────────────────────────
# Distinct from the residency in-boundary check: these targets are ALWAYS refused for
# a RaaS endpoint, regardless of residency_mode, because contacting them is never a
# legitimate retrieval call and is a classic SSRF pivot — cloud-metadata services and
# link-local space. A RaaS URL is operator config, so this guards a mis-config /
# malicious-operator surface; the residency guard (separately) keeps the query
# in-boundary in local mode. Both must pass.
METADATA_HOSTNAMES = {
    "metadata.google.internal",     # GCP metadata service
}


# Loopback by NAME. The literal-IP check below already refuses 127.0.0.0/8 and ::1; without
# this, `http://localhost:...` reached the same loopback target the IP form is refused for
# (an inconsistency — the policy is "loopback is never a valid egress target", not "the
# string 127.0.0.1 is"). RFC 6761 reserves `localhost` and every `*.localhost` name for
# loopback; the others are the common /etc/hosts aliases.
LOOPBACK_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


def is_loopback_host(host: str) -> bool:
    """True if ``host`` (a URL hostname, any case) names loopback — by name or literal IP."""
    h = (host or "").lower().rstrip(".")
    if h in LOOPBACK_HOSTNAMES or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def is_egress_unsafe_host(url: str) -> bool:
    """True if ``url`` points at a cloud-metadata / link-local / loopback target that a
    RaaS endpoint must never be allowed to reach (SSRF denylist)."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return True   # unparseable host → refuse (fail-closed)
    if host in METADATA_HOSTNAMES:
        return True
    if is_loopback_host(host):
        return True   # loopback by name (localhost, *.localhost, …) — same as 127.0.0.1
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # a DNS name (not a literal IP) — residency guard handles boundary
    # Block the cloud-metadata IP, all link-local (169.254/16, fe80::/10), loopback
    # (127/8, ::1), and the unspecified/“this host” ranges as RaaS egress targets.
    return bool(
        ip.is_link_local        # 169.254.0.0/16, fe80::/10 — incl. the AWS/Azure metadata IP
        or ip.is_loopback       # 127.0.0.0/8, ::1
        or ip.is_unspecified    # 0.0.0.0, ::
        or ip.is_multicast
        or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None
            and (ip.ipv4_mapped.is_link_local or ip.ipv4_mapped.is_loopback))
    )
