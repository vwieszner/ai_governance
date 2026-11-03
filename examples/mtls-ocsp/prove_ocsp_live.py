"""LIVE proof: inbound mTLS OCSP revocation checking against a REAL ``openssl ocsp`` responder.

    python examples/mtls-ocsp/prove_ocsp_live.py        # needs the `openssl` CLI on PATH

What it does (all key material goes to a fresh temp dir — never the repo):
  1. Issues a federation CA + division certs with the repo's issuing code
     (transport.mtls.issue_federation_certs — what scripts/issue_division_certs.py runs), with
     the AIA OCSP URL pointed at a local responder.
  2. Writes an OpenSSL CA index (beta, epsilon = Valid; gamma = Revoked; delta absent → unknown)
     and starts ``openssl ocsp`` as the responder (signs with the CA key, nextUpdate +5min).
  3. Serves HTTPS with uvicorn using EXACTLY the agent's serving wiring
     (transport.mtls.tls_serving_kwargs → ssl_context_factory → server_context + the OCSP
     handshake hook), one server in hard mode and one in soft mode; the (empty) CRL is also
     loaded so the proof shows OCSP catching a revocation the CRL doesn't list yet.
  4. Makes real mTLS requests with each client cert and asserts accept/refuse, then kills the
     responder to show hard (fail-closed) vs soft (fail-open + warn) and the per-serial cache.

Ports: responder 20480, hard server 20443, soft server 20444 (host ports 20000-20999).
"""
from __future__ import annotations

import datetime
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agt-federated-rag"))

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from cryptography import x509  # noqa: E402

from transport import mtls  # noqa: E402

OCSP_PORT, HARD_PORT, SOFT_PORT = 20480, 20443, 20444
OCSP_URL = f"http://127.0.0.1:{OCSP_PORT}"
FAILS: list[str] = []


def _wait_port(port: int, timeout: float = 15.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"port {port} never opened")


def _index_line(cert: x509.Certificate, revoked: bool) -> str:
    exp = cert.not_valid_after_utc.strftime("%y%m%d%H%M%SZ")
    rev = datetime.datetime.now(datetime.timezone.utc).strftime("%y%m%d%H%M%SZ") if revoked else ""
    serial = format(cert.serial_number, "X")
    serial = serial if len(serial) % 2 == 0 else "0" + serial
    return "\t".join(["R" if revoked else "V", exp, rev, serial, "unknown",
                      "/" + cert.subject.rfc4514_string()])


async def _app(scope, receive, send):
    """Minimal ASGI app: reached ONLY if the TLS layer (incl. the OCSP hook) accepted the peer."""
    if scope["type"] != "http":
        return
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"hello, authenticated peer"})


class _Settings:
    def __init__(self, out, mode):
        self.require_mtls = True
        self.tls_cert_file, self.tls_key_file = out["alpha"]
        self.tls_ca_file = out["_ca"]
        self.tls_crl_file = out["_crl"]          # empty CRL: CRL gate on, nobody listed
        self.tls_ocsp_mode = mode                 # responder URL comes from each cert's AIA


def _serve(out, mode, port):
    kwargs = mtls.tls_serving_kwargs(_Settings(out, mode))
    assert "ssl_context_factory" in kwargs
    server = uvicorn.Server(uvicorn.Config(_app, host="127.0.0.1", port=port,
                                           log_level="warning", **kwargs))
    threading.Thread(target=server.run, daemon=True).start()
    _wait_port(port)
    return server


def _call(out, port, div, expect_ok: bool, label: str) -> None:
    crt, key = out[div]
    ctx = mtls.client_context(out["_ca"], crt, key)
    try:
        with httpx.Client(verify=ctx, trust_env=False, timeout=10) as c:
            r = c.get(f"https://localhost:{port}/")
        got = f"ACCEPTED HTTP {r.status_code} {r.text!r}"
        ok = r.status_code == 200
    except Exception as exc:  # noqa: BLE001
        got = f"REFUSED ({type(exc).__name__}: {str(exc)[:70]})"
        ok = False
    verdict = "PASS" if ok == expect_ok else "FAIL"
    if verdict == "FAIL":
        FAILS.append(label)
    print(f"[{verdict}] {label:<58} -> {got}")


def main() -> int:
    if not shutil.which("openssl"):
        print("openssl CLI not found", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="agt-ocsp-proof-"))
    divs = ["alpha", "beta", "gamma", "delta", "epsilon"]
    out = mtls.issue_federation_certs(tmp, divs, ocsp_url=OCSP_URL)
    certs = {d: x509.load_pem_x509_certificate(Path(out[d][0]).read_bytes()) for d in divs}
    aia = certs["beta"].extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    print(f"[setup] issued CA + {divs} under {tmp}; beta AIA OCSP = "
          f"{[a.access_location.value for a in aia]}")

    idx = tmp / "index.txt"
    idx.write_text("".join(_index_line(certs[d], d == "gamma") + "\n"
                           for d in ("alpha", "beta", "gamma", "epsilon")))
    (tmp / "index.txt.attr").write_text("unique_subject = no\n")
    print("[setup] openssl CA index:\n  " + idx.read_text().strip().replace("\n", "\n  "))
    responder = subprocess.Popen(
        ["openssl", "ocsp", "-index", str(idx), "-port", str(OCSP_PORT),
         "-rsigner", out["_ca"], "-rkey", out["_ca_key"], "-CA", out["_ca"], "-nmin", "5"],
        stdout=subprocess.DEVNULL, stderr=(tmp / "responder.log").open("wb"))
    try:
        # Wait for its "waiting for OCSP client connections" banner. (Don't probe the port with
        # a bare connect: `openssl ocsp` serves one connection at a time and would block on it.)
        end = time.time() + 15
        while b"waiting for OCSP" not in (tmp / "responder.log").read_bytes():
            if time.time() > end or responder.poll() is not None:
                raise RuntimeError("openssl ocsp did not start: "
                                   + (tmp / "responder.log").read_text(errors="replace"))
            time.sleep(0.1)
        print(f"[setup] openssl ocsp responder pid={responder.pid} on {OCSP_URL}")
        for d in ("beta", "gamma", "delta"):
            r = subprocess.run(["openssl", "ocsp", "-issuer", out["_ca"], "-cert", out[d][0],
                                "-url", OCSP_URL, "-CAfile", out["_ca"]],
                               capture_output=True, text=True, timeout=15)
            lines = [ln.strip() for ln in (r.stdout + r.stderr).splitlines() if ln.strip()]
            print(f"[openssl-client] {d}: " + " | ".join(lines[:3]))

        hard = _serve(out, "hard", HARD_PORT)
        soft = _serve(out, "soft", SOFT_PORT)
        print(f"[setup] uvicorn mTLS servers: hard=:{HARD_PORT} soft=:{SOFT_PORT} "
              f"(tls_serving_kwargs → ssl_context_factory, CRL + OCSP)\n")

        _call(out, HARD_PORT, "beta", True, "hard: beta (OCSP good)")
        _call(out, HARD_PORT, "gamma", False, "hard: gamma (OCSP REVOKED, not on CRL)")
        _call(out, HARD_PORT, "delta", False, "hard: delta (OCSP unknown)")
        _call(out, SOFT_PORT, "gamma", False, "soft: gamma (REVOKED always denies)")
        _call(out, SOFT_PORT, "delta", True, "soft: delta (unknown → allow + warn)")

        responder.terminate()
        responder.wait(10)
        print(f"\n[outage] openssl ocsp responder stopped (rc={responder.returncode})")
        _call(out, HARD_PORT, "beta", True, "hard, responder down: beta (cached GOOD)")
        _call(out, HARD_PORT, "epsilon", False, "hard, responder down: epsilon (uncached)")
        _call(out, SOFT_PORT, "epsilon", True, "soft, responder down: epsilon (fail-open)")
        _call(out, SOFT_PORT, "gamma", False, "soft, responder down: gamma (cached REVOKED)")
        hard.should_exit = soft.should_exit = True
    finally:
        if responder.poll() is None:
            responder.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{'ALL PASS' if not FAILS else 'FAILURES: ' + ', '.join(FAILS)}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
