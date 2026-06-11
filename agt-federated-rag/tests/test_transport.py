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

import pytest

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
            "client_cert": client.cert}


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


def test_cert_identifies_division(pki):
    cn = pki["client_cert"].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "beta"
