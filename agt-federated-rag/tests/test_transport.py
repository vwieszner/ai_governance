"""M7 transport-hardening tests (IMPLEMENTATION_PLAN.md M7, NFR-3): mTLS + CRL revocation.

Real TLS handshakes (driven in-memory via SSL MemoryBIO — deterministic across platforms,
the same technique CPython's own ssl test suite uses) pin the security properties:
  - a peer with NO client cert is rejected (mTLS required, no anonymous bypass);
  - a peer cert signed by a DIFFERENT (rogue) CA is rejected (no trust bypass);
  - a CA-signed peer cert handshakes successfully;
  - a CRL-revoked cert is detected by the revocation gate;
  - the peer cert's CN identifies the division (cert-identity).
"""
from __future__ import annotations

import ssl
import time
from pathlib import Path

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from transport import mtls


@pytest.fixture
def pki(tmp_path):
    ca_key, ca_cert = mtls.generate_ca()
    ca_path = tmp_path / "ca.crt"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server = mtls.issue_division_cert(ca_key, ca_cert, "alpha")
    client = mtls.issue_division_cert(ca_key, ca_cert, "beta")
    s_crt, s_key = server.write(tmp_path, "server")
    c_crt, c_key = client.write(tmp_path, "client")
    # a cert from a DIFFERENT CA — must NOT be trusted by our server.
    rogue_key, rogue_ca = mtls.generate_ca("Rogue CA")
    r_crt, r_key = mtls.issue_division_cert(rogue_key, rogue_ca, "evil").write(tmp_path, "rogue")
    return {"ca": str(ca_path), "s_crt": s_crt, "s_key": s_key, "c_crt": c_crt, "c_key": c_key,
            "r_crt": r_crt, "r_key": r_key, "ca_key": ca_key, "ca_cert": ca_cert,
            "client_cert": client.cert, "tmp_path": tmp_path}


def _handshake_ok(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext,
                  server_hostname: str = "localhost") -> bool:
    """Drive a full TLS handshake between the two contexts in memory (MemoryBIO).

    A real handshake — cert exchange + chain verification + (on the server) the
    CERT_REQUIRED client-cert demand all execute — but with no sockets/threads, so it is
    deterministic on every platform. Returns True iff BOTH peers complete the handshake;
    any verification failure (no client cert, rogue CA, hostname mismatch) surfaces as an
    ssl.SSLError on one side → False.
    """
    c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname=server_hostname)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    c_done = s_done = False
    try:
        for _ in range(40):
            if not c_done:
                try:
                    client.do_handshake()
                    c_done = True
                except ssl.SSLWantReadError:
                    pass
            s_in.write(c_out.read())
            if not s_done:
                try:
                    server.do_handshake()
                    s_done = True
                except ssl.SSLWantReadError:
                    pass
            c_in.write(s_out.read())
            if c_done and s_done:
                return True
        return False
    except ssl.SSLError:
        return False


def test_mtls_required_no_client_cert_rejected(pki):
    sctx = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"])
    no_cert = mtls.client_context(pki["ca"])               # no client cert
    assert _handshake_ok(sctx, no_cert) is False


def test_ca_signed_client_cert_accepted(pki):
    sctx = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"])
    good = mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])
    assert _handshake_ok(sctx, good) is True


def test_rogue_ca_cert_rejected(pki):
    # signed by a different CA — no trust bypass.
    sctx = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"])
    rogue = mtls.client_context(pki["ca"], pki["r_crt"], pki["r_key"])
    assert _handshake_ok(sctx, rogue) is False


def test_revoked_cert_detected(pki):
    crl = mtls.build_crl(pki["ca_key"], pki["ca_cert"], [pki["client_cert"].serial_number])
    assert mtls.is_revoked(pki["client_cert"], crl) is True
    other = mtls.issue_division_cert(pki["ca_key"], pki["ca_cert"], "gamma")
    assert mtls.is_revoked(other.cert, crl) is False        # non-revoked cert not flagged


def _write_crl(pki, revoked_serials, name="fed.crl"):
    """Build + persist a CRL for the fixture CA revoking the given serials; return its path."""
    crl = mtls.build_crl(pki["ca_key"], pki["ca_cert"], revoked_serials)
    return mtls.write_crl(crl, pki["tmp_path"] / name)


def test_revoked_client_cert_rejected_at_handshake(pki):
    # NFR-3: a CA-signed but REVOKED client cert must be rejected fail-closed by the serving
    # context — not merely detectable by the helper. Proven via a real (MemoryBIO) handshake.
    crl_path = _write_crl(pki, [pki["client_cert"].serial_number])
    sctx = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"], crl_path=crl_path)
    revoked = mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])
    assert _handshake_ok(sctx, revoked) is False


def test_unrevoked_client_cert_still_accepted_with_crl(pki):
    # Positive control: with CRL checking ON, a CA-signed cert that is NOT on the CRL still
    # handshakes (the gate rejects only revoked serials, not every cert).
    crl_path = _write_crl(pki, [])                       # empty CRL — nobody revoked
    sctx = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"], crl_path=crl_path)
    good = mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])
    assert _handshake_ok(sctx, good) is True


def test_crl_refresh_picks_up_newly_revoked_serial(pki):
    # The serving context reloads a republished CRL (mtime cache): a client that handshakes
    # now is rejected after its serial is added to the CRL at the same path.
    crl_path = _write_crl(pki, [], name="refresh.crl")    # initially empty
    s1 = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"], crl_path=crl_path)
    good = mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])
    assert _handshake_ok(s1, good) is True                # accepted before revocation

    time.sleep(0.01)                                      # ensure the republished CRL has a new mtime
    _write_crl(pki, [pki["client_cert"].serial_number], name="refresh.crl")  # republish revoking it
    s2 = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"], crl_path=crl_path)
    revoked = mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])
    assert _handshake_ok(s2, revoked) is False            # rejected after refresh


def test_no_crl_configured_behaves_as_before(pki):
    # Backward-compatible: with NO crl_path, the context has no revocation gate — a cert that
    # WOULD be revoked still handshakes (we never silently weaken; we just don't gate when
    # revocation was never configured). The CRL gate only activates when a CRL is supplied.
    sctx = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"])   # no crl_path
    client = mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])
    assert _handshake_ok(sctx, client) is True


def test_missing_crl_file_fails_loud(pki):
    # A configured-but-absent CRL must fail loud, NOT fail open (silently "no revocations").
    with pytest.raises(FileNotFoundError):
        mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"],
                            crl_path=str(pki["tmp_path"] / "does-not-exist.crl"))


def test_issued_cert_carries_crl_distribution_point(pki):
    # NFR-3: issued certs advertise where the CRL is published (CRLDistributionPoints), so a
    # real relying party can locate the revocation list.
    ext = pki["client_cert"].extensions.get_extension_for_class(x509.CRLDistributionPoints)
    uris = [n.value for dp in ext.value for n in (dp.full_name or [])]
    assert any(u.startswith("http") for u in uris)


def test_issued_cert_carries_aia_ocsp_url(pki):
    # NFR-3 OCSP readiness: issued certs advertise an OCSP responder via the Authority
    # Information Access extension, so a deployed responder is reachable for online revocation
    # checks / stapling (enforcement is a deploy-time step — responder + front-end stapling).
    from cryptography.x509.oid import AuthorityInformationAccessOID
    ext = pki["client_cert"].extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    ocsp_urls = [ad.access_location.value for ad in ext.value
                 if ad.access_method == AuthorityInformationAccessOID.OCSP]
    assert ocsp_urls and any(u.startswith("http") for u in ocsp_urls)


def test_ocsp_staple_hook_validated_fail_loud(pki):
    # OCSP stapling readiness hook: a configured-but-missing staple file fails loud (mirrors the
    # CRL posture), never silently ignored. Enforcement still needs a TLS front-end (the stdlib
    # can't staple) — server_context VALIDATES the hook only.
    with pytest.raises(FileNotFoundError):
        mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"],
                            ocsp_staple_file=str(pki["tmp_path"] / "no-such-staple.ocsp"))


def test_ocsp_staple_file_for_reads_env(monkeypatch):
    # The deploy wiring point: ocsp_staple_file_for sources from the env when config.py has no
    # field, so a deployment can wire stapling without code changes.
    monkeypatch.setenv("TLS_OCSP_STAPLE_FILE", "/etc/agt/alpha.ocsp")
    assert mtls.ocsp_staple_file_for(_S(require_mtls=False)) == "/etc/agt/alpha.ocsp"


def test_issue_federation_certs_emits_enforceable_crl(tmp_path):
    # End-to-end: issuance also writes the CA key + an (empty) CRL, and regenerate_crl can
    # revoke a division so the serving context rejects it at the handshake.
    out = mtls.issue_federation_certs(tmp_path, ["alpha", "beta"])
    assert Path(out["_crl"]).exists() and Path(out["_ca_key"]).exists()
    # un-revoked beta handshakes against alpha's CRL-checking server.
    s_ok = mtls.server_context(out["alpha"][0], out["alpha"][1], out["_ca"], crl_path=out["_crl"])
    beta = mtls.client_context(out["_ca"], out["beta"][0], out["beta"][1])
    assert _handshake_ok(s_ok, beta) is True
    # revoke beta's serial → regenerate the CRL → beta is now rejected.
    beta_cert = x509.load_pem_x509_certificate(Path(out["beta"][0]).read_bytes())
    mtls.regenerate_crl(out["_ca"], out["_ca_key"], out["_crl"], [beta_cert.serial_number])
    s_rev = mtls.server_context(out["alpha"][0], out["alpha"][1], out["_ca"], crl_path=out["_crl"])
    beta2 = mtls.client_context(out["_ca"], out["beta"][0], out["beta"][1])
    assert _handshake_ok(s_rev, beta2) is False


def test_cert_identifies_division(pki):
    cn = pki["client_cert"].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "beta"


class _S:
    """Minimal settings stand-in for the wiring helpers."""
    def __init__(self, require_mtls, cert="", key="", ca=""):
        self.require_mtls = require_mtls
        self.tls_cert_file, self.tls_key_file, self.tls_ca_file = cert, key, ca


def test_tls_serving_kwargs_off_by_default():
    # Default posture (require_mtls false) → plain HTTP, no ssl kwargs.
    assert mtls.tls_serving_kwargs(_S(require_mtls=False)) == {}
    assert mtls.peer_tls_context(_S(require_mtls=False)) is None


def test_tls_serving_kwargs_demands_client_cert_when_enabled(pki):
    s = _S(require_mtls=True, cert=pki["s_crt"], key=pki["s_key"], ca=pki["ca"])
    kw = mtls.tls_serving_kwargs(s)
    assert kw["ssl_certfile"] == pki["s_crt"]
    assert kw["ssl_ca_certs"] == pki["ca"]
    assert kw["ssl_cert_reqs"] == ssl.CERT_REQUIRED       # mutual TLS, not optional
    # outbound side builds a client context presenting our cert. (Don't isinstance-check
    # against ssl.SSLContext: truststore.inject_into_ssl, active once api.main is imported,
    # rebinds it to a subclass while our context is the genuine base — see _genuine_ssl.)
    ctx = mtls.peer_tls_context(s)
    assert ctx is not None and hasattr(ctx, "wrap_bio")


def test_require_mtls_without_certs_fails_loud():
    # A security downgrade (serving plaintext while claiming mTLS) must never happen silently.
    with pytest.raises(RuntimeError):
        mtls.tls_serving_kwargs(_S(require_mtls=True))
    with pytest.raises(RuntimeError):
        mtls.peer_tls_context(_S(require_mtls=True))


def test_issue_federation_certs_roundtrip_handshakes(tmp_path):
    # The issued CA + division certs must actually mTLS-handshake (end-to-end issuance).
    out = mtls.issue_federation_certs(tmp_path, ["alpha", "beta"])
    sctx = mtls.server_context(out["alpha"][0], out["alpha"][1], out["_ca"])
    cctx = mtls.client_context(out["_ca"], out["beta"][0], out["beta"][1])
    assert _handshake_ok(sctx, cctx) is True


def test_mtls_holds_under_truststore_injection(pki):
    """The app calls truststore.inject_into_ssl() (verify against the OS trust store).
    A federation cert is signed by our PRIVATE CA — absent from any OS store — so the
    contexts must build genuine stdlib SSLContexts that honour our loaded CA regardless.
    Pin it: with truststore injected, a CA-signed mTLS handshake must STILL succeed."""
    truststore = pytest.importorskip("truststore")
    truststore.inject_into_ssl()
    try:
        sctx = mtls.server_context(pki["s_crt"], pki["s_key"], pki["ca"])
        good = mtls.client_context(pki["ca"], pki["c_crt"], pki["c_key"])
        assert _handshake_ok(sctx, good) is True
    finally:
        truststore.extract_from_ssl()


def test_agent_server_config_loads_with_crl_under_truststore(tmp_path, monkeypatch):
    """Regression: api.main injects truststore at import, which rebinds ssl.SSLContext; the
    genuine CRL-checking serving context then failed uvicorn's isinstance check in
    Config.load (TypeError) — the agent could not START with require_mtls + a CRL/OCSP.
    run() now builds the config via _uvicorn_config, which must load cleanly AND leave
    truststore injected for the rest of the process (outbound HTTPS)."""
    import truststore

    from api import main  # noqa: F401  (the production module; it injects at import)

    was_injected = ssl.SSLContext is truststore.SSLContext
    truststore.inject_into_ssl()   # the production state, regardless of test order
    try:
        _check_agent_server_config(tmp_path, monkeypatch, main, truststore)
    finally:
        if not was_injected:
            truststore.extract_from_ssl()


def _check_agent_server_config(tmp_path, monkeypatch, main, truststore):
    assert ssl.SSLContext is truststore.SSLContext  # the precondition that triggered the bug
    certs = mtls.issue_federation_certs(tmp_path, ["alpha"])
    crt, key = certs["alpha"]
    monkeypatch.setattr(main.settings, "require_mtls", True, raising=False)
    monkeypatch.setattr(main.settings, "tls_cert_file", crt, raising=False)
    monkeypatch.setattr(main.settings, "tls_key_file", key, raising=False)
    monkeypatch.setattr(main.settings, "tls_ca_file", certs["_ca"], raising=False)
    monkeypatch.setattr(mtls, "CRL_FILE", certs["_crl"])   # TLS_CRL_FILE (not a settings field)

    kw = mtls.tls_serving_kwargs(main.settings)
    assert "ssl_context_factory" in kw            # the CRL path, the one that used to fail
    config = main._uvicorn_config(kw)
    assert config.loaded
    assert config.ssl is not None and config.ssl.verify_mode == ssl.CERT_REQUIRED
    assert ssl.SSLContext is truststore.SSLContext  # truststore restored after loading
