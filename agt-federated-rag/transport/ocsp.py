"""OCSP revocation checking for INBOUND mTLS peers (NFR-3; complements the CRL gate in mtls.py).

WHERE THE DECISION RUNS (design note): Python's ``ssl`` module exposes no in-handshake verify
callback, so OpenSSL can't be asked to consult an OCSP responder while it validates the client
chain (and server-side stapling is not exposed at all — see mtls.server_context). The earliest
point Python sees the AUTHENTICATED peer leaf is the instant the handshake completes — but that
``do_handshake`` runs synchronously ON THE EVENT LOOP inside asyncio's SSL protocol, so a
responder round-trip there (up to ``timeout``) would stall every other connection. So the
decision is split in two, both installed by ``mtls.tls_serving_kwargs`` (no route can forget it):

  1. Handshake hook (``install_on_context(..., defer_misses=True)``): CACHE HITS ONLY — a known
     REVOKED / hard-mode non-GOOD peer is still refused inside ``do_handshake`` (an
     :class:`OCSPRevocationError` aborts the handshake). A miss never does I/O here.
  2. Connection gate (:func:`gated_http_protocol`): uvicorn's HTTP protocol subclassed so that
     ``connection_made`` (called by asyncio only after the handshake) reads the verified leaf
     from the transport, pauses reading, and ``await``s the OCSP decision in a worker thread.
     Until it resolves, no byte reaches the HTTP parser (anything already decrypted is held in
     a bounded buffer), so no ASGI scope exists and no route can run; deny → the connection is
     closed, allow → held bytes are replayed and reading resumes. Chosen over an ASGI
     middleware because uvicorn does not expose the TLS object/peer cert in the ASGI scope
     (mapping scope["client"] back to a TLS session would be racy), and a protocol-level gate
     covers every app served — not only those that remember to add a middleware.

Concurrency: fetches are SINGLE-FLIGHT per (issuer key hash, serial) — N concurrent connections
for one cert cause one responder round-trip (thread-level in :meth:`OCSPChecker.check`, plus
loop-level in :meth:`OCSPChecker.acheck` so they don't each hold an executor thread). Cached
answers are REFRESHED AHEAD in the background once within ``refresh_before`` of nextUpdate, so a
steadily-connecting peer never waits on the responder; a failed early refresh keeps the
still-valid cached answer (it is authenticated and fresh until nextUpdate), while any
authenticated answer (incl. REVOKED) replaces it immediately.

``server_context(..., ocsp_checker=c)`` without the gate (``defer_misses=False``, e.g. a
non-asyncio caller) keeps the original fully-synchronous in-handshake check: correct, but a miss
blocks the calling thread for up to ``timeout``.

Validation of a response (RFC 6960): status SUCCESSFUL; signed by the issuing CA itself OR by a
delegated responder cert carried in the response that the CA issued with the id-kp-OCSPSigning
EKU; the SingleResponse's CertID matches (issuer name/key hash + serial); our nonce echoed when
the responder echoes one (pre-signed responses legitimately omit it — freshness bounds replay);
thisUpdate not in the future; nextUpdate not passed (or, absent a nextUpdate, thisUpdate no
older than ``max_age``). Results are cached per (issuer key hash, serial) until nextUpdate.

Modes (``TLS_OCSP_MODE``): ``off`` (default — no behaviour change), ``soft`` (a responder that
is unreachable / answers garbage / says UNKNOWN → allow + warn: availability over revocation
freshness), ``hard`` (fail CLOSED on anything but an authenticated GOOD). A validly-signed
REVOKED always denies whenever OCSP is enabled.

Errors (outage / bad response) are negatively cached for ``error_ttl`` so an outage costs one
bounded fetch per window, not one per connection.
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import os
import secrets
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import structlog
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

from rag.egress_guard import is_egress_unsafe_host

log = structlog.get_logger(__name__)

MODES = ("off", "soft", "hard")
_SKEW = datetime.timedelta(minutes=5)

Fetcher = Callable[[str, bytes, float], bytes]


class OCSPRevocationError(ssl.SSLError):
    """Raised from the handshake hook to refuse a peer (revoked, or hard-mode non-GOOD)."""


@dataclass
class OCSPResult:
    status: str                  # "good" | "revoked" | "unknown" | "error"
    detail: str = ""
    expires: datetime.datetime | None = None


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ── Config (env-sourced, mirrors crl_path_for: config.py needn't grow fields) ──

def ocsp_mode_for(s) -> str:
    """``tls_ocsp_mode`` setting, else ``TLS_OCSP_MODE`` env; default ``off``. An unknown value
    raises (fail loud — a typo must not silently disable the revocation check)."""
    mode = (getattr(s, "tls_ocsp_mode", "") or os.environ.get("TLS_OCSP_MODE", "")
            or "off").strip().lower()
    if mode not in MODES:
        raise ValueError(f"TLS_OCSP_MODE={mode!r} is invalid — expected one of {MODES}")
    return mode


def ocsp_responder_override_for(s) -> str:
    """Optional responder URL that overrides each cert's AIA OCSP URL (``TLS_OCSP_RESPONDER_URL``)."""
    return (getattr(s, "tls_ocsp_responder_url", "")
            or os.environ.get("TLS_OCSP_RESPONDER_URL", "")).strip()


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


# ── SSRF hygiene for the responder fetch ───────────────────────────────────────

def responder_url_unsafe(url: str) -> str:
    """Return a reason string if ``url`` must not be fetched, else "".

    Reuses the RaaS SSRF denylist (rag.egress_guard: metadata / link-local / unspecified /
    multicast) with ONE deliberate exception: LOOPBACK is allowed. The responder URL is never request-derived —
    it is the AIA of a cert our CA already verified, or operator config — and a responder (or
    an OCSP-caching sidecar) on localhost is a normal deployment shape. Only http(s) schemes."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return f"scheme {p.scheme!r} not allowed"
    host = (p.hostname or "").lower()
    is_loopback = host == "localhost"
    try:
        is_loopback = is_loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if not is_loopback and is_egress_unsafe_host(url):
        return f"host {host!r} is on the egress denylist (metadata/link-local)"
    return ""


def http_fetch(url: str, body: bytes, timeout: float) -> bytes:
    """POST an OCSP request (RFC 6960 A.1). No redirects (a 3xx could pivot the fetch past the
    SSRF check) and no ambient proxy env (the responder is federation infra)."""
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as c:
        r = c.post(url, content=body, headers={"Content-Type": "application/ocsp-request",
                                               "Accept": "application/ocsp-response"})
    if r.status_code != 200:
        raise OSError(f"OCSP responder HTTP {r.status_code}")
    return r.content


# ── Response verification ─────────────────────────────────────────────────────

def _verify_sig(signer: x509.Certificate, resp: ocsp.OCSPResponse) -> None:
    pub = signer.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(resp.signature, resp.tbs_response_bytes,
                   ec.ECDSA(resp.signature_hash_algorithm))
    elif isinstance(pub, rsa.RSAPublicKey):
        pub.verify(resp.signature, resp.tbs_response_bytes, padding.PKCS1v15(),
                   resp.signature_hash_algorithm)
    else:
        pub.verify(resp.signature, resp.tbs_response_bytes)  # Ed25519/Ed448


def _key_hash(cert: x509.Certificate, issuer: x509.Certificate, alg) -> tuple[bytes, bytes]:
    """(issuer_name_hash, issuer_key_hash) for ``alg`` — computed via cryptography's own CertID
    builder so the key-bitstring extraction is exactly RFC 6960's for any key type."""
    req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, alg).build()
    return req.issuer_name_hash, req.issuer_key_hash


def _signer_for(resp: ocsp.OCSPResponse, leaf: x509.Certificate,
                issuer: x509.Certificate, now: datetime.datetime) -> x509.Certificate:
    """The cert whose key signed ``resp``: the issuer itself, or a CA-issued delegated
    OCSP-signing cert embedded in the response. Raises ValueError if neither."""
    _, issuer_sha1 = _key_hash(leaf, issuer, hashes.SHA1())  # noqa: S303 — RFC 6960 ResponderID
    if resp.responder_key_hash == issuer_sha1 or resp.responder_name == issuer.subject:
        return issuer
    for cand in resp.certificates:
        try:
            cand.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature):
            continue
        try:
            eku = cand.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            continue
        if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
            continue
        if not (cand.not_valid_before_utc - _SKEW <= now <= cand.not_valid_after_utc + _SKEW):
            continue
        return cand
    raise ValueError("response not signed by the issuer or a CA-delegated OCSP signer")


def validate_response(der: bytes, leaf: x509.Certificate, issuer: x509.Certificate,
                      nonce: bytes | None, *, now: datetime.datetime,
                      max_age: datetime.timedelta,
                      default_ttl: datetime.timedelta) -> OCSPResult:
    """Fully validate a DER OCSP response for ``leaf``. Never raises: problems → status error."""
    try:
        resp = ocsp.load_der_ocsp_response(der)
    except ValueError as exc:
        return OCSPResult("error", f"unparseable response: {exc}")
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return OCSPResult("error", f"responder status {resp.response_status.name}")
    try:
        signer = _signer_for(resp, leaf, issuer, now)
        _verify_sig(signer, resp)
    except (ValueError, InvalidSignature, TypeError) as exc:
        return OCSPResult("error", f"bad responder signature: {exc or type(exc).__name__}")
    if nonce is not None:
        try:
            got = resp.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        except x509.ExtensionNotFound:
            got = None   # pre-signed responses omit the nonce; freshness checks still bound replay
        if got is not None and got != nonce:
            return OCSPResult("error", "nonce mismatch (replayed response?)")
    single = None
    for sr in resp.responses:
        if sr.serial_number != leaf.serial_number:
            continue
        if (sr.issuer_name_hash, sr.issuer_key_hash) == _key_hash(leaf, issuer, sr.hash_algorithm):
            single = sr
            break
    if single is None:
        return OCSPResult("error", "no SingleResponse for this cert (CertID mismatch)")
    this_u, next_u = single.this_update_utc, single.next_update_utc
    if this_u > now + _SKEW:
        return OCSPResult("error", f"thisUpdate {this_u.isoformat()} is in the future")
    if next_u is not None:
        if now > next_u + _SKEW:
            return OCSPResult("error", f"stale response: nextUpdate {next_u.isoformat()} passed")
        expires = next_u
    else:
        if now - this_u > max_age:
            return OCSPResult("error", f"stale response: thisUpdate {this_u.isoformat()} "
                                       f"older than max_age and no nextUpdate")
        expires = now + default_ttl
    status = single.certificate_status
    if status == ocsp.OCSPCertStatus.REVOKED:
        when = single.revocation_time_utc
        return OCSPResult("revoked", f"revoked at {when.isoformat() if when else '?'}", expires)
    if status == ocsp.OCSPCertStatus.UNKNOWN:
        return OCSPResult("unknown", "responder does not know this certificate", expires)
    return OCSPResult("good", "", expires)


# ── Checker (fetch + cache + policy) ───────────────────────────────────────────

class _Flight:
    """One in-progress responder query that concurrent callers for the same cert wait on."""
    __slots__ = ("done", "result")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: OCSPResult | None = None


class OCSPChecker:
    """Per-serving-context OCSP gate. ``issuers`` are the trusted CA certs (TLS_CA_FILE)."""

    def __init__(self, issuers: list[x509.Certificate], mode: str, *,
                 responder_url: str = "", timeout: float = 3.0,
                 max_age: float = 3600.0, default_ttl: float = 300.0, error_ttl: float = 30.0,
                 refresh_before: float = 60.0, fetch: Fetcher | None = None,
                 clock: Callable[[], datetime.datetime] = _now) -> None:
        if mode not in MODES:
            raise ValueError(f"invalid OCSP mode {mode!r}")
        self.issuers, self.mode = issuers, mode
        self.responder_url, self.timeout = responder_url, timeout
        self.max_age = datetime.timedelta(seconds=max_age)
        self.default_ttl = datetime.timedelta(seconds=default_ttl)
        self.error_ttl = datetime.timedelta(seconds=error_ttl)
        self.refresh_before = datetime.timedelta(seconds=refresh_before)
        self.fetch = fetch or http_fetch
        self.clock = clock
        self._lock = threading.Lock()
        self._cache: dict[tuple[bytes, int], OCSPResult] = {}
        self._inflight: dict[tuple[bytes, int], _Flight] = {}    # thread-level single-flight
        self._afutures: dict = {}                                  # (loop, key) → executor future
        self.fetches = 0     # observability / tests: number of responder round-trips

    @classmethod
    def from_ca_file(cls, ca_path: str, mode: str, **kw) -> "OCSPChecker":
        return cls(x509.load_pem_x509_certificates(Path(ca_path).read_bytes()), mode, **kw)

    def _issuer_of(self, leaf: x509.Certificate) -> x509.Certificate | None:
        for ca in self.issuers:
            if ca.subject != leaf.issuer:
                continue
            try:
                leaf.verify_directly_issued_by(ca)
                return ca
            except (ValueError, TypeError, InvalidSignature):
                continue
        return None

    def _url_for(self, leaf: x509.Certificate) -> str:
        if self.responder_url:
            return self.responder_url
        try:
            aia = leaf.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        except x509.ExtensionNotFound:
            return ""
        for ad in aia:
            if ad.access_method == AuthorityInformationAccessOID.OCSP:
                return ad.access_location.value
        return ""

    def _key(self, leaf: x509.Certificate):
        """(issuer, cache key) — cache key is (issuer SHA-1 key hash, serial); (None, None) if
        the leaf was not issued by a configured CA."""
        issuer = self._issuer_of(leaf)
        if issuer is None:
            return None, None
        return issuer, (_key_hash(leaf, issuer, hashes.SHA1())[1], leaf.serial_number)  # noqa: S303

    def _peek(self, leaf: x509.Certificate):
        """(key, still-valid cached result or None, within the refresh-ahead window). No I/O."""
        issuer, key = self._key(leaf)
        if issuer is None:
            return None, None, False
        now = self.clock()
        with self._lock:
            hit = self._cache.get(key)
        if hit is None or hit.expires is None or now >= hit.expires:
            return key, None, False
        near = hit.status != "error" and hit.expires - now <= self.refresh_before
        return key, hit, near

    def cached(self, leaf: x509.Certificate) -> OCSPResult | None:
        """The still-valid cached result for ``leaf``, else None. Never fetches (handshake-safe)."""
        return self._peek(leaf)[1]

    def check(self, leaf: x509.Certificate) -> OCSPResult:
        """Cached result, else query the responder (BLOCKING, ≤ ``timeout``). Single-flight: a
        concurrent caller for the same cert waits on the in-flight query instead of re-fetching."""
        issuer, key = self._key(leaf)
        if issuer is None:
            return OCSPResult("error", "issuer not among the configured CA certs")
        return self._single_flight(leaf, issuer, key, force=False)

    def refresh(self, leaf: x509.Certificate) -> OCSPResult:
        """Re-query although a valid answer is cached (refresh-ahead). A failed refresh keeps the
        still-valid cached answer; any authenticated answer (incl. REVOKED) replaces it."""
        issuer, key = self._key(leaf)
        if issuer is None:
            return OCSPResult("error", "issuer not among the configured CA certs")
        return self._single_flight(leaf, issuer, key, force=True)

    def _single_flight(self, leaf, issuer, key, *, force: bool) -> OCSPResult:
        with self._lock:
            hit = self._cache.get(key)
            if (not force and hit is not None and hit.expires is not None
                    and self.clock() < hit.expires):
                return hit
            flight = self._inflight.get(key)
            leader = flight is None
            if leader:
                flight = self._inflight[key] = _Flight()
        if not leader:
            if not flight.done.wait(self.timeout + 10.0) or flight.result is None:
                return OCSPResult("error", "in-flight OCSP query did not complete")
            return flight.result
        res = None
        try:
            now = self.clock()
            res = self._query(leaf, issuer, now)
            if res.status == "error":
                res.expires = now + self.error_ttl   # negative cache: don't stall every handshake
            with self._lock:
                prev = self._cache.get(key)
                if (force and res.status == "error" and prev is not None
                        and prev.status != "error" and prev.expires is not None
                        and self.clock() < prev.expires):
                    log.warning("ocsp_refresh_failed_keeping_cached", serial=leaf.serial_number,
                                detail=res.detail, cached=prev.status)
                    res = prev
                else:
                    self._cache[key] = res
            return res
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            flight.result = res
            flight.done.set()

    async def acheck(self, leaf: x509.Certificate) -> OCSPResult:
        """Non-blocking :meth:`check` for the event loop: a cache hit returns at once (and kicks a
        background refresh when near nextUpdate); a miss runs the query in the default executor,
        de-duplicated per loop so N waiters for one cert share ONE executor job."""
        key, hit, near = self._peek(leaf)
        loop = asyncio.get_running_loop()
        if hit is not None:
            if near:
                self._refresh_in_background(loop, key, leaf)
            return hit
        if key is None:
            return self.check(leaf)          # issuer mismatch: pure CPU, no fetch
        fkey = (loop, key)
        fut = self._afutures.get(fkey)
        if fut is None:
            fut = loop.run_in_executor(None, self.check, leaf)
            self._afutures[fkey] = fut
            fut.add_done_callback(lambda _f: self._afutures.pop(fkey, None))
        return await asyncio.shield(fut)

    def _refresh_in_background(self, loop, key, leaf) -> None:
        fkey = (loop, key)
        with self._lock:
            busy = key in self._inflight
        if busy or fkey in self._afutures:
            return
        fut = loop.run_in_executor(None, self.refresh, leaf)
        self._afutures[fkey] = fut
        fut.add_done_callback(lambda _f: self._afutures.pop(fkey, None))

    def _query(self, leaf, issuer, now) -> OCSPResult:
        url = self._url_for(leaf)
        if not url:
            return OCSPResult("error", "no OCSP responder URL (no AIA, no TLS_OCSP_RESPONDER_URL)")
        why = responder_url_unsafe(url)
        if why:
            return OCSPResult("error", f"responder URL refused: {why}")
        nonce = secrets.token_bytes(16)
        req = (ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA256())
               .add_extension(x509.OCSPNonce(nonce), critical=False).build())
        self.fetches += 1
        try:
            der = self.fetch(url, req.public_bytes(Encoding.DER), self.timeout)
        except Exception as exc:  # noqa: BLE001 — any transport failure is a responder outage
            return OCSPResult("error", f"responder unreachable: {type(exc).__name__}: {exc}")
        return validate_response(der, leaf, issuer, nonce, now=self.clock(),
                                 max_age=self.max_age, default_ttl=self.default_ttl)

    def verdict(self, res: OCSPResult) -> bool:
        """Policy: GOOD allows, REVOKED always denies, anything else allows only in soft mode."""
        if res.status == "good":
            return True
        if res.status == "revoked":
            return False
        return self.mode == "soft"

    def decide(self, leaf: x509.Certificate) -> tuple[bool, OCSPResult]:
        """(allow, result) under this checker's mode (may block on a cache miss)."""
        res = self.check(leaf)
        return self.verdict(res), res

    async def adecide(self, leaf: x509.Certificate) -> tuple[bool, OCSPResult]:
        """(allow, result) without blocking the event loop."""
        res = await self.acheck(leaf)
        return self.verdict(res), res

    def audit(self, leaf: x509.Certificate, allow: bool, res: OCSPResult) -> None:
        cn = leaf.subject.rfc4514_string()
        if allow and res.status != "good":
            log.warning("ocsp_soft_fail_allowed", peer=cn, serial=leaf.serial_number,
                        status=res.status, detail=res.detail, agt_audit=True)
        if not allow:
            log.warning("ocsp_peer_refused", peer=cn, serial=leaf.serial_number,
                        status=res.status, detail=res.detail, mode=self.mode, agt_audit=True)

    def _refusal(self, leaf: x509.Certificate, res: OCSPResult) -> OCSPRevocationError:
        return OCSPRevocationError(
            f"OCSP: peer {leaf.subject.rfc4514_string()} serial {leaf.serial_number} refused "
            f"({res.status}{': ' + res.detail if res.detail else ''})")

    def enforce(self, leaf_der: bytes | None) -> None:
        """Raise OCSPRevocationError to refuse the peer; return to allow. May block on a miss."""
        if self.mode == "off" or not leaf_der:
            return
        leaf = x509.load_der_x509_certificate(leaf_der)
        allow, res = self.decide(leaf)
        self.audit(leaf, allow, res)
        if not allow:
            raise self._refusal(leaf, res)

    def enforce_cached(self, leaf_der: bytes | None) -> None:
        """Handshake-safe :meth:`enforce`: decides only from a valid cached answer and never
        fetches. A miss returns — the connection gate then decides before any route runs."""
        if self.mode == "off" or not leaf_der:
            return
        leaf = x509.load_der_x509_certificate(leaf_der)
        res = self.cached(leaf)
        if res is None:
            return
        if not self.verdict(res):
            self.audit(leaf, False, res)
            raise self._refusal(leaf, res)


def install_on_context(ctx: ssl.SSLContext, checker: OCSPChecker, *,
                       defer_misses: bool = False) -> ssl.SSLContext:
    """Make every server-side handshake on ``ctx`` run ``checker`` on the verified peer leaf.

    asyncio (and so uvicorn) builds its TLS objects via ``ctx.wrap_bio`` → ``sslobject_class``,
    so overriding it per-context hooks the real serving path without touching uvicorn.
    ``defer_misses=True`` (ONLY together with :func:`gated_http_protocol`): the hook decides from
    the cache alone and never does I/O on the event loop; a miss is decided by the gate."""
    base = ctx.sslobject_class
    enforce = checker.enforce_cached if defer_misses else checker.enforce

    class _OCSPCheckingSSLObject(base):  # type: ignore[misc, valid-type]
        def do_handshake(self):
            super().do_handshake()
            if self.server_side:
                enforce(self.getpeercert(binary_form=True))

    ctx.sslobject_class = _OCSPCheckingSSLObject
    ctx.ocsp_checker = checker  # type: ignore[attr-defined]  # introspection / tests
    ctx.ocsp_deferred = defer_misses  # type: ignore[attr-defined]
    return ctx


GATE_BUFFER_LIMIT = 64 * 1024   # bytes held per connection while its OCSP decision is pending


def gated_http_protocol(checker: OCSPChecker, base: type | None = None) -> type:
    """A uvicorn HTTP protocol class (``uvicorn.Config(http=...)``) that holds each new TLS
    connection until ``checker`` has decided on its verified peer leaf — asynchronously, so the
    event loop keeps serving other connections while a responder is slow. Denied → closed before
    a single request byte is parsed, so no ASGI scope / route ever sees it."""
    if base is None:
        from uvicorn.protocols.http.auto import AutoHTTPProtocol as base

    class OCSPGatedHTTPProtocol(base):  # type: ignore[misc, valid-type]
        ocsp_checker = checker

        def connection_made(self, transport):
            self._ocsp_open = False
            self._ocsp_buf = bytearray()
            self._ocsp_task = None
            super().connection_made(transport)
            ssl_obj = transport.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj is not None else None
            try:
                leaf = x509.load_der_x509_certificate(der) if der else None
            except ValueError:
                leaf = None
            if leaf is None:   # unreachable under CERT_REQUIRED — fail closed regardless
                log.warning("ocsp_gate_no_peer_cert", agt_audit=True)
                transport.close()
                return
            hit = checker.cached(leaf)
            if hit is not None:                    # steady state: decide inline, no I/O
                allow = checker.verdict(hit)
                checker.audit(leaf, allow, hit)
                self._ocsp_settle(allow)
                return
            transport.pause_reading()
            self._ocsp_task = asyncio.get_running_loop().create_task(self._ocsp_decide(leaf))

        async def _ocsp_decide(self, leaf):
            try:
                allow, res = await checker.adecide(leaf)
                checker.audit(leaf, allow, res)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — an internal fault must fail CLOSED
                log.warning("ocsp_gate_error", error=f"{type(exc).__name__}: {exc}",
                            agt_audit=True)
                allow = False
            self._ocsp_settle(allow)

        def _ocsp_settle(self, allow: bool) -> None:
            if self.transport.is_closing():
                return
            if not allow:
                self.transport.close()
                return
            self._ocsp_open = True
            held, self._ocsp_buf = bytes(self._ocsp_buf), bytearray()
            if held:
                super().data_received(held)
            flow = getattr(self, "flow", None)
            if not getattr(flow, "read_paused", False) and not self.transport.is_closing():
                self.transport.resume_reading()

        def data_received(self, data: bytes) -> None:
            if self._ocsp_open:
                super().data_received(data)
                return
            self._ocsp_buf += data                 # never reaches the HTTP parser until allowed
            if len(self._ocsp_buf) > GATE_BUFFER_LIMIT:
                self.transport.close()

        def connection_lost(self, exc):
            if self._ocsp_task is not None and not self._ocsp_task.done():
                self._ocsp_task.cancel()
            super().connection_lost(exc)

    return OCSPGatedHTTPProtocol


def checker_from_env(ca_path: str, mode: str, responder_url: str = "") -> OCSPChecker:
    return OCSPChecker.from_ca_file(
        ca_path, mode, responder_url=responder_url,
        timeout=_float_env("TLS_OCSP_TIMEOUT", 3.0),
        max_age=_float_env("TLS_OCSP_MAX_AGE", 3600.0),
        default_ttl=_float_env("TLS_OCSP_DEFAULT_TTL", 300.0),
        refresh_before=_float_env("TLS_OCSP_REFRESH_BEFORE", 60.0))
