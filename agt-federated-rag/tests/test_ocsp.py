"""OCSP revocation checking for inbound mTLS peers (NFR-3) — hermetic tests.

Responses are built + signed with ``cryptography.x509.ocsp`` and served by an injected fetcher
(no network), so every validation branch is pinned: GOOD / REVOKED / UNKNOWN, a forged or
untrusted responder signature, stale responses, nonce replay, responder outage in soft vs hard
mode, the per-serial cache (until nextUpdate), delegated responder certs, and the real
handshake hook (a revoked peer is refused inside ``do_handshake``). The live counterpart against
a real ``openssl ocsp`` responder is examples/mtls-ocsp/prove_ocsp_live.py.
"""
from __future__ import annotations

import asyncio
import datetime
import socket
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp as xocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests.test_transport import _handshake_ok
from transport import mtls, ocsp

NOW = datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
H = datetime.timedelta(hours=1)
DER = serialization.Encoding.DER


@pytest.fixture
def pki(tmp_path):
    ca_key, ca_cert = mtls.generate_ca()
    ca_path = tmp_path / "ca.crt"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server = mtls.issue_division_cert(ca_key, ca_cert, "alpha", ocsp_url="http://127.0.0.1:1/")
    client = mtls.issue_division_cert(ca_key, ca_cert, "beta", ocsp_url="http://127.0.0.1:1/")
    s_crt, s_key = server.write(tmp_path, "server")
    c_crt, c_key = client.write(tmp_path, "client")
    return {"ca_key": ca_key, "ca_cert": ca_cert, "ca": str(ca_path), "leaf": client.cert,
            "s_crt": s_crt, "s_key": s_key, "c_crt": c_crt, "c_key": c_key}


def _response(pki, status, *, nonce=None, this=NOW - H, next_=NOW + H,
              signer_cert=None, signer_key=None, embed=None, leaf=None):
    signer_cert = signer_cert or pki["ca_cert"]
    signer_key = signer_key or pki["ca_key"]
    kw = {}
    if status == xocsp.OCSPCertStatus.REVOKED:
        kw = {"revocation_time": NOW - 2 * H, "revocation_reason": None}
    else:
        kw = {"revocation_time": None, "revocation_reason": None}
    b = (xocsp.OCSPResponseBuilder()
         .add_response(cert=leaf or pki["leaf"], issuer=pki["ca_cert"], algorithm=hashes.SHA256(),
                       cert_status=status, this_update=this, next_update=next_, **kw)
         .responder_id(xocsp.OCSPResponderEncoding.HASH, signer_cert))
    if nonce is not None:
        b = b.add_extension(x509.OCSPNonce(nonce), critical=False)
    if embed:
        b = b.certificates(embed)
    return b.sign(signer_key, hashes.SHA256()).public_bytes(DER)


class _Responder:
    """Fake fetcher: echoes the request nonce into a freshly signed response."""

    def __init__(self, pki, status=xocsp.OCSPCertStatus.GOOD, echo_nonce=True, **kw):
        self.pki, self.status, self.echo, self.kw, self.calls = pki, status, echo_nonce, kw, []
        self.down = False

    def __call__(self, url, body, timeout):
        self.calls.append(url)
        if self.down:
            raise ConnectionRefusedError("responder down")
        req = xocsp.load_der_ocsp_request(body)
        nonce = req.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        if self.echo is not True:
            nonce = self.echo or None          # False → omit; bytes → wrong nonce
        return _response(self.pki, self.status, nonce=nonce, **self.kw)


def _checker(pki, mode, fetch, clock=lambda: NOW):
    return ocsp.OCSPChecker([pki["ca_cert"]], mode, fetch=fetch, clock=clock)


def _rogue():
    return mtls.generate_ca("Rogue Responder")


# ── statuses ───────────────────────────────────────────────────────────────────

def test_good_status_allowed(pki):
    allow, res = _checker(pki, "hard", _Responder(pki)).decide(pki["leaf"])
    assert (allow, res.status) == (True, "good")


@pytest.mark.parametrize("mode", ["soft", "hard"])
def test_revoked_always_denied(pki, mode):
    allow, res = _checker(pki, mode, _Responder(pki, xocsp.OCSPCertStatus.REVOKED)).decide(pki["leaf"])
    assert (allow, res.status) == (False, "revoked")


def test_unknown_status_hard_denies_soft_allows(pki):
    r = _Responder(pki, xocsp.OCSPCertStatus.UNKNOWN)
    assert _checker(pki, "hard", r).decide(pki["leaf"])[0] is False
    allow, res = _checker(pki, "soft", r).decide(pki["leaf"])
    assert (allow, res.status) == (True, "unknown")


# ── response authenticity / freshness ─────────────────────────────────────────

def test_response_signed_by_untrusted_key_rejected(pki):
    rk, rc = _rogue()
    r = _Responder(pki, xocsp.OCSPCertStatus.GOOD, signer_cert=rc, signer_key=rk, embed=[rc])
    allow, res = _checker(pki, "hard", r).decide(pki["leaf"])
    assert allow is False and res.status == "error" and "signature" in res.detail


def test_tampered_signature_claiming_ca_responder_rejected(pki):
    # responder_id says "the CA" but the signature bytes are corrupted (last byte of the
    # trailing signature BIT STRING flipped) → the CA-key signature check fails.
    inner = _Responder(pki, echo_nonce=False)

    def tampered(url, body, timeout):
        der = bytearray(inner(url, body, timeout))
        der[-1] ^= 0x01
        return bytes(der)

    allow, res = _checker(pki, "hard", tampered).decide(pki["leaf"])
    assert allow is False and "signature" in res.detail


def _delegate(pki, with_eku=True):
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ocsp-signer")]))
         .issuer_name(pki["ca_cert"].subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW - 24 * H).not_valid_after(NOW + 24 * H))
    if with_eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
    return key, b.sign(pki["ca_key"], hashes.SHA256())


def test_delegated_responder_with_ocsp_signing_eku_accepted(pki):
    dk, dc = _delegate(pki)
    r = _Responder(pki, signer_cert=dc, signer_key=dk, embed=[dc])
    assert _checker(pki, "hard", r).decide(pki["leaf"]) [1].status == "good"


def test_delegated_responder_without_eku_rejected(pki):
    dk, dc = _delegate(pki, with_eku=False)
    r = _Responder(pki, signer_cert=dc, signer_key=dk, embed=[dc])
    allow, res = _checker(pki, "hard", r).decide(pki["leaf"])
    assert allow is False and "signature" in res.detail


def test_stale_response_rejected(pki):
    r = _Responder(pki, this=NOW - 48 * H, next_=NOW - 24 * H)
    allow, res = _checker(pki, "hard", r).decide(pki["leaf"])
    assert allow is False and "stale" in res.detail


def test_old_response_without_next_update_rejected(pki):
    r = _Responder(pki, this=NOW - 5 * H, next_=None)       # > max_age (1h) old, no nextUpdate
    assert "stale" in _checker(pki, "hard", r).decide(pki["leaf"])[1].detail


def test_future_this_update_rejected(pki):
    r = _Responder(pki, this=NOW + H, next_=NOW + 2 * H)
    assert "future" in _checker(pki, "hard", r).decide(pki["leaf"])[1].detail


def test_nonce_mismatch_rejected_but_absent_nonce_ok(pki):
    bad = _Responder(pki, echo_nonce=b"\x00" * 16)
    assert "nonce" in _checker(pki, "hard", bad).decide(pki["leaf"])[1].detail
    # A pre-signed response with NO nonce is accepted (freshness bounds replay instead).
    assert _checker(pki, "hard", _Responder(pki, echo_nonce=False)).decide(pki["leaf"])[0] is True


def test_response_for_a_different_serial_rejected(pki):
    other = mtls.issue_division_cert(pki["ca_key"], pki["ca_cert"], "gamma").cert
    r = _Responder(pki, leaf=other)       # GOOD — but for gamma, not the presented cert
    allow, res = _checker(pki, "hard", r).decide(pki["leaf"])
    assert allow is False and "CertID" in res.detail


# ── outage, cache, URL ────────────────────────────────────────────────────────

def test_responder_down_soft_allows_hard_denies(pki):
    r = _Responder(pki)
    r.down = True
    allow, res = _checker(pki, "soft", r).decide(pki["leaf"])
    assert allow is True and "unreachable" in res.detail
    assert _checker(pki, "hard", r).decide(pki["leaf"])[0] is False


def test_cache_until_next_update_then_refetch(pki):
    t = [NOW]
    r = _Responder(pki, next_=NOW + H)
    c = _checker(pki, "hard", r, clock=lambda: t[0])
    assert c.decide(pki["leaf"])[0] and c.decide(pki["leaf"])[0]
    assert c.fetches == 1                                   # second call served from cache
    t[0] = NOW + 2 * H                                      # past nextUpdate → refetch
    r.kw = {"this": t[0], "next_": t[0] + H}
    assert c.decide(pki["leaf"])[0] and c.fetches == 2


def test_error_is_negatively_cached_briefly(pki):
    t = [NOW]
    r = _Responder(pki)
    r.down = True
    c = _checker(pki, "soft", r, clock=lambda: t[0])
    c.decide(pki["leaf"])
    c.decide(pki["leaf"])
    assert c.fetches == 1                                   # outage doesn't stall each handshake
    t[0] = NOW + datetime.timedelta(seconds=31)
    c.decide(pki["leaf"])
    assert c.fetches == 2


def test_uses_aia_url_unless_overridden(pki):
    r = _Responder(pki)
    _checker(pki, "hard", r).decide(pki["leaf"])
    assert r.calls == ["http://127.0.0.1:1/"]
    c = ocsp.OCSPChecker([pki["ca_cert"]], "hard", responder_url="http://127.0.0.2:9/", fetch=r,
                         clock=lambda: NOW)
    c.decide(pki["leaf"])
    assert r.calls[-1] == "http://127.0.0.2:9/"


def test_no_responder_url_is_an_error(pki):
    leaf = mtls.issue_division_cert(pki["ca_key"], pki["ca_cert"], "noaia", ocsp_url="").cert
    with pytest.raises(x509.ExtensionNotFound):
        leaf.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    allow, res = _checker(pki, "hard", _Responder(pki)).decide(leaf)
    assert allow is False and "no OCSP responder URL" in res.detail


@pytest.mark.parametrize("url,unsafe", [
    ("http://169.254.169.254/latest/meta-data", True),     # cloud metadata
    ("http://metadata.google.internal/", True),
    ("file:///etc/passwd", True),
    ("http://127.0.0.1:20080/", False),                     # loopback responder sidecar: allowed
    ("http://localhost:20080/", False),
    ("http://ocsp.federation.local/", False),
])
def test_responder_url_ssrf_hygiene(url, unsafe):
    assert bool(ocsp.responder_url_unsafe(url)) is unsafe


def test_ssrf_unsafe_aia_never_fetched(pki):
    r = _Responder(pki)
    c = ocsp.OCSPChecker([pki["ca_cert"]], "soft", responder_url="http://169.254.169.254/",
                         fetch=r, clock=lambda: NOW)
    assert "refused" in c.decide(pki["leaf"])[1].detail and r.calls == []


# ── the real handshake hook + config wiring ───────────────────────────────────

def _served(pki, checker):
    return mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"], ocsp_checker=checker)


def test_handshake_refuses_revoked_and_accepts_good(pki):
    good = mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])
    ok_ctx = _served(pki, ocsp.OCSPChecker([pki["ca_cert"]], "hard", fetch=_Responder(pki),
                                                    clock=lambda: NOW))
    assert _handshake_ok(ok_ctx, good) is True
    rev = _Responder(pki, xocsp.OCSPCertStatus.REVOKED)
    rev_ctx = _served(pki, ocsp.OCSPChecker([pki["ca_cert"]], "soft", fetch=rev,
                                                     clock=lambda: NOW))
    assert _handshake_ok(rev_ctx, mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])) is False
    assert len(rev.calls) == 1 and rev_ctx.ocsp_checker.check(pki["leaf"]).status == "revoked"


def test_handshake_hook_raises_ssl_error(pki):
    c = ocsp.OCSPChecker([pki["ca_cert"]], "hard",
                         fetch=_Responder(pki, xocsp.OCSPCertStatus.REVOKED), clock=lambda: NOW)
    with pytest.raises(ocsp.OCSPRevocationError) as ei:
        c.enforce(pki["leaf"].public_bytes(DER))
    assert "revoked" in str(ei.value)


class _S:
    def __init__(self, pki, mode=""):
        self.require_mtls = True
        self.tls_cert_file, self.tls_key_file, self.tls_ca_file = pki["s_crt"], pki["s_key"], pki["ca"]
        self.tls_ocsp_mode = mode


def test_ocsp_off_by_default_no_behaviour_change(pki, monkeypatch):
    monkeypatch.delenv("TLS_OCSP_MODE", raising=False)
    monkeypatch.delenv("TLS_CRL_FILE", raising=False)
    monkeypatch.setattr(mtls, "CRL_FILE", "")
    assert ocsp.ocsp_mode_for(_S(pki)) == "off"
    kw = mtls.tls_serving_kwargs(_S(pki))
    assert "ssl_context_factory" not in kw and kw["ssl_certfile"] == pki["s_crt"]


def test_ocsp_mode_wires_checker_into_served_context(pki, monkeypatch):
    monkeypatch.setattr(mtls, "CRL_FILE", "")
    monkeypatch.setenv("TLS_OCSP_MODE", "hard")
    monkeypatch.setenv("TLS_OCSP_RESPONDER_URL", "http://127.0.0.1:20999/")
    s = _S(pki)
    ctx = mtls.tls_serving_kwargs(s)["ssl_context_factory"](None, None)
    assert ctx.ocsp_checker.mode == "hard"
    assert ctx.ocsp_checker.responder_url == "http://127.0.0.1:20999/"


def test_invalid_ocsp_mode_fails_loud(pki, monkeypatch):
    monkeypatch.setenv("TLS_OCSP_MODE", "hrad")
    with pytest.raises(ValueError):
        mtls.tls_serving_kwargs(_S(pki))


def test_serving_kwargs_pair_deferred_context_with_gate(pki, monkeypatch):
    # The deferring handshake (cache-only) is only ever handed out WITH the async gate.
    monkeypatch.setattr(mtls, "CRL_FILE", "")
    monkeypatch.setenv("TLS_OCSP_MODE", "soft")
    kw = mtls.tls_serving_kwargs(_S(pki))
    ctx = kw["ssl_context_factory"](None, None)
    assert ctx.ocsp_deferred is True
    assert kw["http"].ocsp_checker is ctx.ocsp_checker


# ── non-blocking: single-flight, refresh-ahead, deferred handshake, live event loop ─────────────

class _SlowResponder(_Responder):
    """Thread-safe fake responder that sleeps ``delay`` before answering (a slow OCSP server)."""

    def __init__(self, pki, delay, **kw):
        super().__init__(pki, **kw)
        self.delay, self._mu = delay, threading.Lock()

    def __call__(self, url, body, timeout):
        with self._mu:
            self.calls.append(url)
        time.sleep(self.delay)
        if self.down:
            raise ConnectionRefusedError("responder down")
        nonce = xocsp.load_der_ocsp_request(body).extensions.get_extension_for_class(
            x509.OCSPNonce).value.nonce
        return _response(self.pki, self.status, nonce=nonce, **self.kw)


def test_single_flight_threads_one_fetch(pki):
    r = _SlowResponder(pki, 0.3)
    c = _checker(pki, "hard", r)
    out = []
    ts = [threading.Thread(target=lambda: out.append(c.decide(pki["leaf"]))) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert [a for a, _ in out] == [True] * 8
    assert c.fetches == 1 and len(r.calls) == 1


def test_single_flight_async_one_fetch(pki):
    r = _SlowResponder(pki, 0.3)
    c = _checker(pki, "hard", r)

    async def go():
        return await asyncio.gather(*(c.adecide(pki["leaf"]) for _ in range(20)))

    res = asyncio.run(go())
    assert all(a for a, _ in res) and c.fetches == 1 and len(r.calls) == 1


def test_refresh_ahead_in_background(pki):
    t = [NOW]
    r = _SlowResponder(pki, 0.0, next_=NOW + H)
    c = ocsp.OCSPChecker([pki["ca_cert"]], "hard", fetch=r, clock=lambda: t[0],
                         refresh_before=120)

    async def go():
        assert (await c.adecide(pki["leaf"]))[0] and c.fetches == 1
        t[0] = NOW + H - datetime.timedelta(seconds=60)      # inside the refresh window
        # 1) a failed early refresh keeps the still-valid cached GOOD (not downgraded to error)
        r.down = True
        assert (await c.adecide(pki["leaf"]))[1].status == "good"   # answered from cache at once
        await asyncio.sleep(0.2)
        assert c.fetches == 2 and c.cached(pki["leaf"]).status == "good"
        # 2) an authenticated REVOKED from a refresh replaces it immediately
        r.down, r.status = False, xocsp.OCSPCertStatus.REVOKED
        r.kw = {"this": t[0], "next_": t[0] + H}
        await c.adecide(pki["leaf"])
        await asyncio.sleep(0.2)
        assert c.fetches == 3
        return await c.adecide(pki["leaf"])

    allow, res = asyncio.run(go())
    assert (allow, res.status) == (False, "revoked")


def test_deferred_handshake_never_fetches_but_refuses_cached_revoked(pki):
    r = _SlowResponder(pki, 2.0)
    c = _checker(pki, "hard", r)
    ctx = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"], ocsp_checker=c,
                              ocsp_defer=True)
    t0 = time.monotonic()
    assert _handshake_ok(ctx, mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])) is True
    assert time.monotonic() - t0 < 1.0 and r.calls == []       # miss: no I/O in the handshake
    rev = _checker(pki, "soft", _Responder(pki, xocsp.OCSPCertStatus.REVOKED))
    rev.check(pki["leaf"])                                       # cached REVOKED
    rctx = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"], ocsp_checker=rev,
                               ocsp_defer=True)
    assert _handshake_ok(rctx, mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])) is False


def _free_port() -> int:
    for port in range(20900, 21000):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("no free port in 20900-20999")


class _PerCertResponder:
    """Answers per serial: ``plan[serial] = (delay, status, cert)``."""

    def __init__(self, pki, plan):
        self.pki, self.plan, self.calls = pki, plan, []

    def __call__(self, url, body, timeout):
        req = xocsp.load_der_ocsp_request(body)
        delay, status, cert = self.plan[req.serial_number]
        self.calls.append(req.serial_number)
        time.sleep(delay)
        nonce = req.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        return _response(self.pki, status, nonce=nonce, leaf=cert)


@pytest.mark.parametrize("deferred", [True, False])
def test_slow_responder_does_not_block_event_loop(pki, tmp_path, deferred):
    """Real uvicorn mTLS server: peer A's OCSP fetch takes 2s; a concurrent request from peer B
    (answer cached) must complete promptly. ``deferred=False`` is the old in-handshake check —
    the control proving this test detects a blocked loop. A slow REVOKED peer never hits the app."""
    import httpx
    import uvicorn

    certs = {}
    for div in ("gamma", "epsilon"):
        pair = mtls.issue_division_cert(pki["ca_key"], pki["ca_cert"], div,
                                        ocsp_url="http://127.0.0.1:1/")
        certs[div] = (pair.cert, *pair.write(tmp_path, div))
    good, revoked = xocsp.OCSPCertStatus.GOOD, xocsp.OCSPCertStatus.REVOKED
    fetch = _PerCertResponder(pki, {
        pki["leaf"].serial_number: (2.0, good, pki["leaf"]),
        certs["gamma"][0].serial_number: (0.0, good, certs["gamma"][0]),
        certs["epsilon"][0].serial_number: (1.0, revoked, certs["epsilon"][0])})
    checker = _checker(pki, "hard", fetch)
    checker.check(certs["gamma"][0])                              # B's answer is cached
    hits = []

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        hits.append(scope["client"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    port = _free_port()
    kw = {"ssl_context_factory": lambda _c, _d: mtls.server_context(
        pki["s_crt"], pki["s_key"], pki["ca"], ocsp_checker=checker, ocsp_defer=deferred)}
    if deferred:
        kw["http"] = ocsp.gated_http_protocol(checker)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", **kw)
    # Another test may have imported api.main (truststore.inject_into_ssl rebinds ssl.SSLContext,
    # failing uvicorn's isinstance check on our genuine context) — load the config without it.
    with mtls._genuine_ssl():
        config.load()
    server = uvicorn.Server(config)
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    try:
        for _ in range(200):
            if server.started:
                break
            time.sleep(0.05)
        results = {}

        def call(name, crt, key):
            t0 = time.monotonic()
            try:
                with httpx.Client(verify=mtls.client_context(pki["ca"], crt, key),
                                  trust_env=False, timeout=10) as cl:
                    results[name] = (cl.get(f"https://localhost:{port}/").status_code,
                                     time.monotonic() - t0)
            except httpx.HTTPError as exc:
                results[name] = (type(exc).__name__, time.monotonic() - t0)

        slow = threading.Thread(target=call, args=("A", pki["c_crt"], pki["c_key"]))
        slow.start()
        time.sleep(0.3)                                   # A is now waiting on its OCSP fetch
        call("B", certs["gamma"][1], certs["gamma"][2])
        slow.join()
        if deferred:
            assert results["B"][0] == 200 and results["B"][1] < 0.75, results
            assert results["A"][0] == 200 and results["A"][1] >= 1.9, results
            n = len(hits)
            call("R", certs["epsilon"][1], certs["epsilon"][2])          # slow + REVOKED
            assert results["R"][0] != 200 and len(hits) == n, results    # never reached the app
        else:
            assert results["B"][1] >= 1.4, results        # old path: B stalled behind A's fetch
    finally:
        server.should_exit = True
        th.join(10)
