"""mTLS transport hardening + CRL revocation (IMPLEMENTATION_PLAN.md M7, NFR-3/NFR-5).

A division-federation private CA issues a client/server cert per division; cross-division
and discovery endpoints require mutual TLS — a peer with no client cert, a self-signed
cert, or a CRL-revoked cert is rejected. This module builds the CA + division certs, the
client-cert-REQUIRED server SSL context + the client SSL context, and an application-layer
CRL revocation check (mirrors the CRL/OCSP gate on the data path).

Cert-identity: each division cert's CN + SAN is the division_id, so after the handshake the
peer's certificate identifies WHICH division connected (defence-in-depth on top of the
DID-signed application layer).

The agent serves mTLS only when ``settings.require_mtls`` is true (default false → HTTP, so
existing deployments are unaffected); the machinery + its proofs are independent of that.
"""
from __future__ import annotations

import datetime
import ssl
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_DAY = datetime.timedelta(days=1)


@dataclass
class CertPair:
    key_pem: bytes
    cert_pem: bytes
    cert: x509.Certificate
    ca_cert_pem: bytes = b""        # the issuing CA, appended so the peer gets the full chain

    def write(self, dirpath, name: str) -> tuple[str, str]:
        from pathlib import Path
        d = Path(dirpath)
        kp, cp = d / f"{name}.key", d / f"{name}.crt"
        kp.write_bytes(self.key_pem)
        # Write leaf + CA so load_cert_chain presents the full chain — some OpenSSL builds
        # won't anchor a bare leaf to a separately-loaded root during the handshake.
        cp.write_bytes(self.cert_pem + self.ca_cert_pem)
        return str(cp), str(kp)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def generate_ca(common_name: str = "AGT Federation CA") -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(_now() - _DAY).not_valid_after(_now() + 3650 * _DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue_division_cert(ca_key, ca_cert, division_id: str) -> CertPair:
    """Issue a CA-signed cert whose CN + SAN identify the division."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, division_id)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(_now() - _DAY).not_valid_after(_now() + 365 * _DAY)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                    x509.DNSName(division_id)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return CertPair(
        key_pem=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()),
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        cert=cert,
        ca_cert_pem=ca_cert.public_bytes(serialization.Encoding.PEM),
    )


def build_crl(ca_key, ca_cert, revoked_serials: list[int]) -> x509.CertificateRevocationList:
    b = (x509.CertificateRevocationListBuilder()
         .issuer_name(ca_cert.subject)
         .last_update(_now() - _DAY).next_update(_now() + 30 * _DAY))
    for serial in revoked_serials:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(_now()).build())
    return b.sign(ca_key, hashes.SHA256())


def is_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> bool:
    """Application-layer CRL check (the data-path revocation gate)."""
    return crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None


def server_context(cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """Server SSL context that REQUIRES a client certificate signed by our CA (mTLS).
    (check_hostname is a client-side setting; not applicable on a server context.)"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED          # no client cert → handshake rejected
    return ctx


def client_context(ca_path: str, cert_path: str | None = None, key_path: str | None = None,
                   verify_hostname: bool = True) -> ssl.SSLContext:
    """Client SSL context. Hostname verification is ON by default (the peer cert's SAN
    carries `localhost` + the division_id, so a real connect with the right server_hostname
    passes) — never disable it in production: that would allow a MITM with any CA-signed
    cert to impersonate the peer. The data-path DID signature is defence-in-depth on top."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_path)
    ctx.check_hostname = verify_hostname
    if cert_path and key_path:
        ctx.load_cert_chain(cert_path, key_path)
    return ctx
