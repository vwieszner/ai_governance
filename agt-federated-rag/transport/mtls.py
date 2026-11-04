"""mTLS transport hardening + CRL revocation (IMPLEMENTATION_PLAN.md M7, NFR-3/NFR-5).

A division-federation private CA issues a client/server cert per division; cross-division
and discovery endpoints require mutual TLS — a peer with no client cert, a self-signed
cert, or a CRL-revoked cert is rejected. This module builds the CA + division certs, the
client-cert-REQUIRED server SSL context + the client SSL context, and an application-layer
CRL revocation check (mirrors the CRL/OCSP gate on the data path). Optional OCSP checking of
the inbound peer leaf lives in transport/ocsp.py and is installed by server_context.

Cert-identity: each division cert's CN + SAN is the division_id, so after the handshake the
peer's certificate identifies WHICH division connected (defence-in-depth on top of the
DID-signed application layer).

The agent serves mTLS only when ``settings.require_mtls`` is true (default false → HTTP, so
existing deployments are unaffected); the machinery + its proofs are independent of that.
"""
from __future__ import annotations

import contextlib
import datetime
import os
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

_DAY = datetime.timedelta(days=1)

# CRL distribution point baked into issued certs (where a real deployment publishes the CRL)
# and the default on-disk CRL path the serving context reloads. Both overridable by env so
# config.py needn't grow a field for this revocation surface (NFR-3). Empty CRL path → no CRL
# configured → the mTLS path behaves exactly as before (backward-compatible, fail-open only
# when revocation was never wired). When a CRL IS configured we enforce it fail-closed.
CRL_DISTRIBUTION_URL = os.environ.get(
    "TLS_CRL_URL", "https://federation.local/crl/federation-ca.crl"
)
CRL_FILE = os.environ.get("TLS_CRL_FILE", "")

# OCSP responder URL baked into issued certs via the Authority Information Access (AIA)
# extension, so a relying party can do an ONLINE revocation check (lower latency than a CRL
# for a freshly-revoked serial) (NFR-3). It advertises WHERE the responder lives; the inbound
# OCSP CHECK that consults it is transport/ocsp.py (TLS_OCSP_MODE=soft|hard, default off).
# Overridable by env (or issue_division_cert(ocsp_url=...) / the issuer script's --ocsp-url).
# Empty → no AIA/OCSP extension is added (the CRL gate still applies), keeping issuance
# backward-compatible.
OCSP_RESPONDER_URL = os.environ.get(
    "TLS_OCSP_URL", "http://ocsp.federation.local"
)


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


@contextlib.contextmanager
def _genuine_ssl():
    """Run the enclosed block with the GENUINE stdlib ``ssl.SSLContext`` in effect.

    The app (api.main, workflow.worker) calls ``truststore.inject_into_ssl()``, which
    rebinds ``ssl.SSLContext`` to verify against the OPERATING SYSTEM trust store and
    IGNORE ``load_verify_locations`` — correct for outbound TLS to public endpoints, but
    WRONG for federation mTLS (a division cert is signed by our PRIVATE CA, absent from
    any OS store). We can't merely construct a genuine context: truststore rebinds the
    ``ssl.SSLContext`` MODULE GLOBAL, and the stdlib ``verify_mode`` setter does
    ``super(SSLContext, SSLContext)`` against that global → infinite recursion when set
    while truststore is active. So we extract truststore (its own public API) for the whole
    build+configure, then re-inject so the rest of the process is unaffected.
    """
    try:
        import truststore
        injected = ssl.SSLContext is getattr(truststore, "SSLContext", None)
    except Exception:
        injected = False
    if injected:
        truststore.extract_from_ssl()
    try:
        yield
    finally:
        if injected:
            truststore.inject_into_ssl()


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


def issue_division_cert(ca_key, ca_cert, division_id: str,
                        ocsp_url: str | None = None) -> CertPair:
    """Issue a CA-signed cert whose CN + SAN identify the division.

    ``ocsp_url`` overrides the AIA OCSP responder URL baked into the cert (default: the
    ``TLS_OCSP_URL`` module setting; "" → no AIA extension)."""
    ocsp_url = OCSP_RESPONDER_URL if ocsp_url is None else ocsp_url
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
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
        # CRLDistributionPoints: where a relying party fetches the issuer's CRL to check this
        # cert's revocation status. Points a real deployment at the published CRL (NFR-3); the
        # in-process serving gate loads the CRL from disk, this advertises it in the cert itself.
        .add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(CRL_DISTRIBUTION_URL)],
                relative_name=None, reasons=None, crl_issuer=None)
        ]), critical=False)
    )
    # AuthorityInformationAccess (OCSP): advertise the responder so a relying party can do an
    # ONLINE revocation check / OCSP stapling once a responder is deployed (NFR-3 readiness).
    # Added only when an OCSP URL is set so issuance stays backward-compatible when it isn't.
    # ENFORCEMENT on the inbound side is transport/ocsp.py (TLS_OCSP_MODE=soft|hard).
    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url)),
            ]), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
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


def write_crl(crl: x509.CertificateRevocationList, path) -> str:
    """Persist a CRL as PEM at ``path`` (the file the serving context reloads). Returns the path."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return str(p)


# ── CRL load / refresh cache (the on-the-wire revocation gate) ─────────────────
#
# OpenSSL enforces revocation at the TLS layer when the verifying SSLContext has
# VERIFY_CRL_CHECK_LEAF set AND a CRL for the presented cert's issuer is loaded into the
# verify store. The CRL must be supplied via a verify FILE (cafile): loading it via cadata=
# does NOT associate the CRL with its issuer, so OpenSSL then rejects every cert with
# "unable to get certificate CRL". So we materialise one combined PEM file (CA cert + CRL)
# and load it via cafile. The bundle is cached keyed on (ca_path, crl_path) + the CRL file's
# mtime, so a freshly-published CRL (a newly-revoked serial) is picked up on the next context
# build — without restarting the process — while an unchanged CRL reuses the cached file.

_crl_cache_lock = threading.Lock()
_crl_cache: dict[tuple[str, str], tuple[float, str]] = {}


def load_crl_bundle(ca_path: str, crl_path: str) -> str:
    """Materialise a combined ``CA-cert + CRL`` PEM verify file and return its path, refreshing
    it when the CRL's mtime changes. Raises if the CRL path is set but absent or unparseable —
    a configured-but-missing/corrupt CRL is a misconfiguration we must NOT silently treat as
    "no revocations" (that would fail OPEN). Caller passes crl_path only when CRL is configured."""
    mtime = os.path.getmtime(crl_path)        # raises FileNotFoundError → fail loud
    key = (ca_path, crl_path)
    with _crl_cache_lock:
        cached = _crl_cache.get(key)
        if cached and cached[0] == mtime:
            return cached[1]
    ca_pem = Path(ca_path).read_bytes()
    crl_pem = Path(crl_path).read_bytes()
    # Validate it parses as a CRL — a corrupt/empty file must fail loud, not fail open.
    x509.load_pem_x509_crl(crl_pem)
    bundle_path = Path(crl_path).with_suffix(".cabundle.pem")
    bundle_path.write_bytes(ca_pem.rstrip() + b"\n" + crl_pem)
    with _crl_cache_lock:
        _crl_cache[key] = (mtime, str(bundle_path))
    return str(bundle_path)


def server_context(cert_path: str, key_path: str, ca_path: str,
                   crl_path: str | None = None,
                   ocsp_staple_file: str | None = None,
                   ocsp_checker=None, ocsp_defer: bool = False) -> ssl.SSLContext:
    """Server SSL context that REQUIRES a client certificate signed by our CA (mTLS).
    (check_hostname is a client-side setting; not applicable on a server context.)

    When ``crl_path`` is given, revocation is ENFORCED at the handshake: VERIFY_CRL_CHECK_LEAF
    is set and the issuer's CRL is loaded, so a CA-signed-but-revoked client cert is rejected
    fail-closed (NFR-3). When ``crl_path`` is None the context behaves exactly as before
    (no revocation gate) — backward-compatible for deployments that never configured a CRL.

    OCSP STAPLING (readiness, NFR-3): ``ocsp_staple_file`` is the documented config HOOK for
    OCSP stapling — a deployment fetches a signed OCSP response for THIS server cert from the
    responder advertised in the cert's AIA extension (OCSP_RESPONDER_URL) and points this at
    it. NOTE / HONEST LIMITATION: Python's stdlib ``ssl`` has no API to set a stapled OCSP
    response on a server context (only the client side can request/verify one via
    ``SSLSocket.get_verified_chain`` / a callback), so stapling MUST be terminated at a TLS
    front-end that supports it (nginx ``ssl_stapling on;`` + ``ssl_stapling_verify on;``, Envoy,
    or HAProxy) — see THREAT_MODEL §3 (nginx edge) and the deploy note. We therefore VALIDATE
    the hook (fail loud if a path is configured but absent — same posture as the CRL) but do
    NOT silently pretend to staple. Passing it without a front-end that staples is a no-op at
    the Python layer by design, documented here so it is never mistaken for enforcement.

    OCSP CHECKING (enforced, NFR-3): ``ocsp_checker`` (a ``transport.ocsp.OCSPChecker``) queries
    the peer cert's OCSP responder right after OpenSSL verifies the chain, inside the handshake
    object, and aborts the connection on REVOKED (or any non-GOOD in hard mode) — see
    transport/ocsp.py for why it is post-verify rather than an OpenSSL callback. With
    ``ocsp_defer=True`` the handshake decides from the OCSP cache only (no I/O on the event loop)
    and a miss is decided by ``ocsp.gated_http_protocol`` — use it ONLY with that gate (which
    ``tls_serving_kwargs`` always installs alongside)."""
    if ocsp_staple_file:
        # Fail loud on a configured-but-missing staple, mirroring load_crl_bundle: a
        # misconfigured stapling path must not be silently ignored.
        if not Path(ocsp_staple_file).exists():
            raise FileNotFoundError(
                f"ocsp_staple_file configured but not found: {ocsp_staple_file!r} — OCSP "
                f"stapling must be terminated at the TLS front-end (nginx/Envoy); this is the "
                f"readiness hook, not stdlib-enforced. See server_context docstring."
            )
    with _genuine_ssl():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.verify_mode = ssl.CERT_REQUIRED      # no client cert → handshake rejected
        if crl_path:
            # Load CA + CRL from one combined PEM file (cafile) and turn on leaf CRL checking.
            # Rebuilt via the mtime-keyed cache so a republished CRL is enforced on next build.
            ctx.load_verify_locations(cafile=load_crl_bundle(ca_path, crl_path))
            ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        else:
            ctx.load_verify_locations(ca_path)
        if ocsp_checker is not None and ocsp_checker.mode != "off":
            from transport.ocsp import install_on_context
            install_on_context(ctx, ocsp_checker, defer_misses=ocsp_defer)
    return ctx


def client_context(ca_path: str, cert_path: str | None = None, key_path: str | None = None,
                   verify_hostname: bool = True) -> ssl.SSLContext:
    """Client SSL context. Hostname verification is ON by default (the peer cert's SAN
    carries `localhost` + the division_id, so a real connect with the right server_hostname
    passes) — never disable it in production: that would allow a MITM with any CA-signed
    cert to impersonate the peer. The data-path DID signature is defence-in-depth on top."""
    with _genuine_ssl():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(ca_path)
        ctx.check_hostname = verify_hostname
        if cert_path and key_path:
            ctx.load_cert_chain(cert_path, key_path)
    return ctx


# ── Settings-driven wiring (used by the API server + peer client) ──────────────

def crl_path_for(s) -> str:
    """The configured CRL path (revocation gate), or "" when none is configured.

    Sourced from a ``tls_crl_file`` setting if config.py grows one, else the ``TLS_CRL_FILE``
    env (the ``CRL_FILE`` module constant). Empty → no CRL configured → no revocation gate
    (backward-compatible). Non-empty → revocation is ENFORCED fail-closed on the mTLS path."""
    return getattr(s, "tls_crl_file", "") or CRL_FILE


def ocsp_staple_file_for(s) -> str:
    """The configured OCSP-staple file (readiness hook), or "" when none is configured.

    Sourced from a ``tls_ocsp_staple_file`` setting if config.py grows one, else the
    ``TLS_OCSP_STAPLE_FILE`` env. Empty → no stapling configured (backward-compatible). When
    set, ``server_context`` validates the file exists (fail loud); ENFORCEMENT of stapling
    still requires a TLS front-end (nginx/Envoy) — the stdlib can't staple (see server_context
    docstring). This is the config point so a deployment can wire it without code changes."""
    return getattr(s, "tls_ocsp_staple_file", "") or os.environ.get("TLS_OCSP_STAPLE_FILE", "")


def tls_serving_kwargs(s) -> dict:
    """uvicorn ssl_* kwargs to SERVE mTLS, or {} when mTLS isn't enabled/configured.

    Returns CERT_REQUIRED serving (mutual TLS) so a peer with no client cert is rejected
    at the TLS layer. When a CRL is configured (``crl_path_for``), revocation is ENFORCED at
    the handshake via an ``ssl_context_factory`` that builds a CRL-checking server_context —
    a CA-signed-but-revoked client cert is rejected (NFR-3). Raises if require_mtls is set but
    the cert paths are missing — fail loud rather than silently fall back to plaintext (a
    security downgrade).
    """
    if not getattr(s, "require_mtls", False):
        return {}
    cert, key, ca = s.tls_cert_file, s.tls_key_file, s.tls_ca_file
    if not (cert and key and ca):
        raise RuntimeError(
            "require_mtls=true but TLS_CERT_FILE / TLS_KEY_FILE / TLS_CA_FILE are not all set "
            "— refusing to serve plaintext. Run scripts/issue_division_certs.py."
        )
    crl = crl_path_for(s)
    staple = ocsp_staple_file_for(s)
    from transport.ocsp import (checker_from_env, gated_http_protocol, ocsp_mode_for,
                                ocsp_responder_override_for)
    ocsp_mode = ocsp_mode_for(s)            # raises on a typo'd mode (fail loud)
    checker = (checker_from_env(ca, ocsp_mode, ocsp_responder_override_for(s))
               if ocsp_mode != "off" else None)
    if crl or staple or checker:
        # uvicorn's built-in ssl_* path can't set verify_flags / load a CRL (or validate an
        # OCSP staple hook), so hand it a factory that returns our hardened server_context. The
        # factory is invoked per (re)bind, so load_crl_bundle's mtime cache refreshes a
        # republished CRL on a reload. ``staple`` is the OCSP-stapling readiness hook (validated
        # by server_context; enforcement still needs a TLS front-end — see its docstring).
        # ``checker`` (TLS_OCSP_MODE=soft|hard) adds the post-verify OCSP gate; it is created
        # once here so its per-serial cache survives a rebind. The handshake only consults the
        # OCSP cache (ocsp_defer); a miss is decided asynchronously by the gated HTTP protocol
        # before any request byte is parsed, so a slow responder never stalls the event loop
        # (transport/ocsp.py design note). Returned TOGETHER: never the deferring context alone.
        def _factory(_config, _default):
            return server_context(cert, key, ca, crl_path=crl or None,
                                  ocsp_staple_file=staple or None, ocsp_checker=checker,
                                  ocsp_defer=checker is not None)
        kw: dict = {"ssl_context_factory": _factory}
        if checker is not None:
            kw["http"] = gated_http_protocol(checker)
        return kw
    return {
        "ssl_certfile": cert,
        "ssl_keyfile": key,
        "ssl_ca_certs": ca,
        "ssl_cert_reqs": ssl.CERT_REQUIRED,   # mutual TLS: client cert demanded
    }


def peer_tls_context(s) -> ssl.SSLContext | None:
    """Client SSL context presenting THIS division's cert for outbound peer mTLS, or None.

    Activates whenever the division's TLS cert/key/CA are all configured — INDEPENDENT of
    require_mtls. This decoupling is what the nginx-edge production mode needs: the agent
    itself serves plain HTTP behind nginx (require_mtls=false), but still presents its
    client cert when calling a PEER's mTLS ingress (an https PEER_AGENT_URL). httpx only
    applies the context to https URLs, so it is harmless for a plain-http peer.
    """
    cert, key, ca = (getattr(s, "tls_cert_file", ""), getattr(s, "tls_key_file", ""),
                     getattr(s, "tls_ca_file", ""))
    if not (cert and key and ca):
        # require_mtls without certs is a misconfiguration; fail loud only in that case.
        if getattr(s, "require_mtls", False):
            raise RuntimeError(
                "require_mtls=true but TLS cert/key/ca paths are not all set — cannot make "
                "a mutually-authenticated peer call."
            )
        return None
    return client_context(ca, cert, key)


def _write_ca_key(ca_key, path) -> str:
    p = Path(path)
    p.write_bytes(ca_key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return str(p)


def issue_federation_certs(out_dir, division_ids: list[str], ca_name: str = "AGT Federation CA",
                           ocsp_url: str | None = None):
    """Generate one shared CA + a per-division cert/key under out_dir, returning
    {division_id: (cert_path, key_path), '_ca': ca_path, '_ca_key': key_path, '_crl': crl_path}.
    Also persists the CA private key + an initial (empty) CRL so revocation can be enforced and
    later regenerated (see regenerate_crl). Idempotent at the directory level (overwrites).
    Used by scripts/issue_division_certs.py."""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = generate_ca(ca_name)
    ca_path = d / "federation-ca.crt"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_key_path = _write_ca_key(ca_key, d / "federation-ca.key")
    # Initial empty CRL — present (so the issuer has a CRL: the gate fails-closed only on a
    # REVOKED serial, not on every cert) but revoking nobody yet. Republished by regenerate_crl.
    crl_path = write_crl(build_crl(ca_key, ca_cert, []), d / "federation-ca.crl")
    result: dict = {"_ca": str(ca_path), "_ca_key": ca_key_path, "_crl": crl_path}
    for div in division_ids:
        pair = issue_division_cert(ca_key, ca_cert, div, ocsp_url=ocsp_url)
        crt, key = pair.write(d, div)
        result[div] = (crt, key)
    return result


def regenerate_crl(ca_cert_path, ca_key_path, crl_path, revoked_serials: list[int]) -> str:
    """(Re)build the CA's CRL from the persisted CA cert+key, revoking ``revoked_serials``, and
    write it to ``crl_path``. Run after revoking a division cert; the serving context reloads it
    (mtime cache) on next bind. Returns the CRL path."""
    ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    ca_key = serialization.load_pem_private_key(Path(ca_key_path).read_bytes(), password=None)
    return write_crl(build_crl(ca_key, ca_cert, revoked_serials), crl_path)
