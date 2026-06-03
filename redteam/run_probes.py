"""
Red-team probe runner — adversarial probes against BOTH federated-RAG solutions.

  A2A solution (federated-rag):      cluster-a :8000   cluster-b :8002
  AGT solution (agt-federated-rag):  cluster-a :8010   cluster-b :8012

Rules of engagement (see probe_lib.py): this script NEVER modifies backend
source. It only sends HTTP requests and classifies the observed response. Each
probe declares the EXPECTED-SAFE behaviour and an honest verdict:

  DEFENDED  — the control rejected the attack as designed (the win condition).
  VULNERABLE— the attack succeeded / leaked / bypassed a control. Needs a fix.
  EXPECTED  — "attack" is actually correct authorization (e.g. a user denied a
              chunk they were never granted). Not a vuln; proves the control.
  BLOCKED   — could not run (backend down, dependency missing). Re-run later.

Run with the project venv python from the repo root:
    .venv\\Scripts\\python.exe redteam\\run_probes.py
Writes redteam/RED_FINDINGS.md.
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx

# Import shared helpers. Works whether run as `python redteam/run_probes.py`
# (cwd = repo root) or from inside redteam/.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_lib as pl  # noqa: E402

OPENFGA = "http://localhost:8089"

# (name, base_url, kind) — kind drives which submit/endpoints a probe uses.
TARGETS = [
    ("A2A cluster-a", pl.A2A_A, "a2a"),
    ("A2A cluster-b", pl.A2A_B, "a2a"),
    ("AGT cluster-a", pl.AGT_A, "agt"),
    ("AGT cluster-b", pl.AGT_B, "agt"),
]


@dataclass
class Finding:
    probe: str
    target: str
    attempt: str
    observed: str
    expected: str
    verdict: str  # DEFENDED | VULNERABLE | EXPECTED | BLOCKED
    note: str = ""


FINDINGS: list[Finding] = []


def record(**kw) -> Finding:
    f = Finding(**kw)
    FINDINGS.append(f)
    tag = {"DEFENDED": "[+]", "VULNERABLE": "[!]", "EXPECTED": "[=]", "BLOCKED": "[.]"}.get(f.verdict, "[?]")
    print(f"{tag} {f.verdict:10} {f.target:14} {f.probe}  ->  {f.observed[:80]}")
    return f


# ── submit helpers per solution ───────────────────────────────────────────────

def submit(kind: str, base: str, token: str | None, query: str, max_seconds: float = 25.0) -> dict:
    """Submit a query to whichever endpoint the solution exposes."""
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if kind == "a2a":
        return pl.post_sse(base + "/tasks/send", headers, pl.a2a_send_body(query), max_seconds)
    return pl.post_sse(base + "/query", headers, {"query": query}, max_seconds)


def is_up(base: str) -> bool:
    try:
        return httpx.get(base + "/health", timeout=pl.TIMEOUT).status_code == 200
    except Exception:
        return False


def answer_from_events(events: list[str]) -> str:
    """Pull any answer text out of collected SSE data events."""
    ans = ""
    for e in events:
        try:
            d = json.loads(e)
        except Exception:
            continue
        if isinstance(d, dict):
            if d.get("answer"):
                ans = d["answer"]
            # A2A nests the final text under status.message / artifacts
            msg = (d.get("status") or {}).get("message") if isinstance(d.get("status"), dict) else None
            if isinstance(msg, str) and msg:
                ans = ans or msg
    return ans


# ── Probes ────────────────────────────────────────────────────────────────────

def p_no_auth(name: str, base: str, kind: str) -> None:
    r = submit(kind, base, None, "What is our data retention policy?", max_seconds=15)
    st = r["status"]
    ok = st in (401, 403)
    record(probe="P1 no-auth submit", target=name,
           attempt="POST submit with NO Authorization header",
           observed=f"HTTP {st} {r['raw'][:120]!r}",
           expected="401/403 (authentication required)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_alg_none(name: str, base: str, kind: str) -> None:
    claims = {"sub": "00000000-0000-0000-0000-000000000000", "preferred_username": "attacker",
              "aud": ["agent-cluster-a", "agent-agt-a"], "realm_access": {"roles": ["admin"]},
              "exp": int(time.time()) + 3600, "iss": f"{pl.KEYCLOAK}/realms/{pl.REALM}"}
    forged = pl.forge_alg_none(claims)
    r = submit(kind, base, forged, "What is our data retention policy?", max_seconds=15)
    st = r["status"]
    ok = st in (401, 403)
    record(probe="P2 alg:none JWT forgery", target=name,
           attempt="submit with an unsigned alg:none token claiming admin",
           observed=f"HTTP {st}",
           expected="401 (algorithm pinned; unsigned token rejected)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_tampered_sig(name: str, base: str, kind: str) -> None:
    try:
        tok = pl.get_token("alice")
    except Exception as e:
        record(probe="P3 tampered signature", target=name, attempt="flip signature bytes of a real token",
               observed=f"could not mint token: {e}", expected="401", verdict="BLOCKED")
        return
    bad = pl.tamper_signature(tok)
    r = submit(kind, base, bad, "What is our data retention policy?", max_seconds=15)
    st = r["status"]
    ok = st in (401, 403)
    record(probe="P3 tampered signature", target=name,
           attempt="real token with corrupted signature bytes",
           observed=f"HTTP {st}",
           expected="401 (signature verification fails)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_garbage_bearer(name: str, base: str, kind: str) -> None:
    r = submit(kind, base, "not-a-jwt-at-all", "hello", max_seconds=15)
    st = r["status"]
    ok = st in (401, 403)
    record(probe="P4 malformed bearer", target=name,
           attempt="Authorization: Bearer not-a-jwt-at-all",
           observed=f"HTTP {st}", expected="401 (reject malformed token)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_idor_task_read(name: str, base: str, kind: str) -> None:
    """A2A only: alice creates a task, bob tries to read it."""
    if kind != "a2a":
        return
    try:
        alice = pl.get_token("alice")
        bob = pl.get_token("bob")
    except Exception as e:
        record(probe="P5 IDOR cross-user task read", target=name, attempt="alice creates task, bob reads it",
               observed=f"token mint failed: {e}", expected="404", verdict="BLOCKED")
        return
    # Create a task as alice and grab its id from the SSE stream.
    r = submit(kind, base, alice, "What is our data retention policy?", max_seconds=20)
    task_id = ""
    for e in r["events"]:
        try:
            d = json.loads(e)
        except Exception:
            continue
        task_id = d.get("id") or d.get("taskId") or (d.get("status", {}) or {}).get("id") or task_id
    if not task_id:
        record(probe="P5 IDOR cross-user task read", target=name,
               attempt="alice creates a task, bob GETs /tasks/{id}",
               observed=f"could not capture a task_id (status {r['status']})",
               expected="404 for bob", verdict="BLOCKED",
               note="submit may have errored (LLM timeout) before emitting id")
        return
    rb = httpx.get(base + f"/tasks/{task_id}", headers=pl.auth_header(bob), timeout=pl.TIMEOUT)
    ok = rb.status_code in (403, 404)
    record(probe="P5 IDOR cross-user task read", target=name,
           attempt=f"bob GET /tasks/{task_id[:8]}… (alice's task)",
           observed=f"HTTP {rb.status_code} {rb.text[:100]!r}",
           expected="404 (deny-by-default ownership; do not confirm existence)",
           verdict="DEFENDED" if ok else "VULNERABLE")
    # And unauthenticated read of the same id.
    ru = httpx.get(base + f"/tasks/{task_id}", timeout=pl.TIMEOUT)
    record(probe="P6 unauth task read", target=name,
           attempt=f"GET /tasks/{task_id[:8]}… with no token",
           observed=f"HTTP {ru.status_code}", expected="401",
           verdict="DEFENDED" if ru.status_code in (401, 403) else "VULNERABLE")


def p_rebac_denied_chunk(name: str, base: str, kind: str) -> None:
    """alice has only pending_approval (NOT viewer) on the salary chunk, so the
    answer must NEVER contain the salary data — she should get the pending-approval
    message instead. A returned salary figure would be a real ReBAC leak.

    The correct outcome (pending, no data) is classified EXPECTED — it proves the
    pending_approval relation does not grant read access.
    """
    try:
        tok = pl.get_token("alice")  # alice: pending_approval on salary, not viewer
    except Exception as e:
        record(probe="P7 ReBAC pending-not-read leakage", target=name, attempt="alice (pending only) asks salary",
               observed=f"token mint failed: {e}", expected="no salary data leaked", verdict="BLOCKED")
        return
    r = submit(kind, base, tok, "What are the salary bands for senior engineers?", max_seconds=30)
    ans = answer_from_events(r["events"])
    # The pending-approval message contains no salary figures; a real leak would
    # carry the band content (salary/band/compensation wording + a number).
    leaked = bool(ans) and any(w in ans.lower() for w in ("salary", "band", "compensation")) \
        and any(c.isdigit() for c in ans) and "pending" not in ans.lower()
    record(probe="P7 ReBAC pending-not-read leakage", target=name,
           attempt="alice (pending_approval only) asks for restricted salary data",
           observed=f"HTTP {r['status']}; answer={'<empty/pending>' if not ans else ans[:80]!r}",
           expected="pending-approval message, NO salary data (pending != read)",
           verdict="VULNERABLE" if leaked else "EXPECTED",
           note="EXPECTED = pending_approval correctly does not grant read")


def p_approval_hmac_forgery(name: str, base: str, kind: str) -> None:
    if kind != "a2a":
        return
    rid = "00000000-0000-0000-0000-000000000000"
    exp = int(time.time()) + 3600
    r = httpx.get(base + f"/approve/{rid}", params={"decision": "approve", "exp": exp, "token": "deadbeef"},
                  timeout=pl.TIMEOUT)
    ok = r.status_code in (401, 403)
    record(probe="P8 approval HMAC forgery", target=name,
           attempt="GET /approve with a guessed/wrong HMAC token",
           observed=f"HTTP {r.status_code} {r.text[:80]!r}",
           expected="401 (HMAC verification fails)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_approval_replay(name: str, base: str, kind: str) -> None:
    if kind != "a2a":
        return
    rid = "11111111-1111-1111-1111-111111111111"
    exp = int(time.time()) - 60  # already expired
    r = httpx.get(base + f"/approve/{rid}", params={"decision": "approve", "exp": exp, "token": "whatever"},
                  timeout=pl.TIMEOUT)
    ok = r.status_code in (401, 403)
    record(probe="P9 approval link replay (expired)", target=name,
           attempt="GET /approve with exp in the past",
           observed=f"HTTP {r.status_code} {r.text[:80]!r}",
           expected="401 (expired link rejected before HMAC)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_callback_forgery_a2a(name: str, base: str, kind: str) -> None:
    if kind != "a2a":
        return
    try:
        tok = pl.get_token("alice")  # rag-ui token: NOT a peer agent client_id
    except Exception as e:
        record(probe="P10 A2A callback forgery", target=name, attempt="non-peer posts a status callback",
               observed=f"token mint failed: {e}", expected="403", verdict="BLOCKED")
        return
    body = {"status": {"state": "completed", "message": "PWNED"}}
    r = httpx.post(base + "/tasks/abc123/callback", headers=pl.auth_header(tok), json=body, timeout=pl.TIMEOUT)
    ok = r.status_code in (401, 403)
    record(probe="P10 A2A callback forgery", target=name,
           attempt="user token (client_id rag-ui, not a peer) POSTs /tasks/{id}/callback",
           observed=f"HTTP {r.status_code} {r.text[:80]!r}",
           expected="403 (caller client_id not in peer allowlist)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_agt_a2a_query_unsigned(name: str, base: str, kind: str) -> None:
    if kind != "agt":
        return
    # No _agentmesh signature envelope at all.
    body = {"query": "What was our Q4 revenue?", "user_id": "alice"}
    r = httpx.post(base + "/a2a/query", json=body, timeout=pl.TIMEOUT)
    ok = r.status_code in (401, 403)
    record(probe="P11 AGT /a2a/query unsigned", target=name,
           attempt="POST /a2a/query with NO Ed25519 signature envelope",
           observed=f"HTTP {r.status_code} {r.text[:80]!r}",
           expected="401 (DID signature required)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_agt_a2a_query_forged(name: str, base: str, kind: str) -> None:
    if kind != "agt":
        return
    # Fabricated _agentmesh block with a bogus signature.
    body = {"query": "What was our Q4 revenue?", "user_id": "alice",
            "_agentmesh": {"did": "did:mesh:deadbeef", "signature": pl.b64url(b"\x00" * 64),
                           "public_key": pl.b64url(b"\x01" * 32), "algorithm": "Ed25519"}}
    r = httpx.post(base + "/a2a/query", json=body, timeout=pl.TIMEOUT)
    ok = r.status_code in (401, 403)
    record(probe="P12 AGT /a2a/query forged signature", target=name,
           attempt="POST /a2a/query with a fabricated DID + bogus signature",
           observed=f"HTTP {r.status_code} {r.text[:80]!r}",
           expected="401/403 (signature invalid OR signer != configured peer)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_agt_callback_unsigned(name: str, base: str, kind: str) -> None:
    if kind != "agt":
        return
    r = httpx.post(base + "/tasks/abc123/callback", json={"status": {"state": "completed"}}, timeout=pl.TIMEOUT)
    ok = r.status_code in (401, 403)
    record(probe="P13 AGT callback unsigned", target=name,
           attempt="POST /tasks/{id}/callback with no DID signature",
           observed=f"HTTP {r.status_code} {r.text[:80]!r}",
           expected="401 (DID signature required)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_oversized_query(name: str, base: str, kind: str) -> None:
    try:
        tok = pl.get_token("alice")
    except Exception as e:
        record(probe="P14 oversized query DoS", target=name, attempt="submit a huge query",
               observed=f"token mint failed: {e}", expected="400", verdict="BLOCKED")
        return
    big = "A" * 100_000
    r = submit(kind, base, tok, big, max_seconds=15)
    st = r["status"]
    ok = st in (400, 413, 422)
    record(probe="P14 oversized query DoS", target=name,
           attempt="submit a 100 000-char query",
           observed=f"HTTP {st}",
           expected="400/413 (max_query_length enforced before work)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_openfga_no_key() -> None:
    try:
        r = httpx.get(OPENFGA + "/stores", timeout=pl.TIMEOUT)
    except Exception as e:
        record(probe="P15 direct OpenFGA (no key)", target="OpenFGA :8089",
               attempt="GET /stores without preshared key",
               observed=f"connection error: {e}", expected="401", verdict="BLOCKED")
        return
    ok = r.status_code in (401, 403)
    record(probe="P15 direct OpenFGA (no key)", target="OpenFGA :8089",
           attempt="GET /stores without the preshared key",
           observed=f"HTTP {r.status_code} {r.text[:80]!r}",
           expected="401 (preshared-key auth)",
           verdict="DEFENDED" if ok else "VULNERABLE")


def p_client_credentials_guess() -> None:
    for cid in ("agent-cluster-a", "agent-agt-a"):
        res = pl.client_credentials_token(cid, "wrong-secret-guess")
        st = res["status"]
        ok = st in (400, 401, 403)
        record(probe="P16 client_credentials secret guess", target=f"Keycloak {cid}",
               attempt=f"client_credentials grant for {cid} with a guessed secret",
               observed=f"HTTP {st}",
               expected="400/401 (bad client credentials)",
               verdict="DEFENDED" if ok else "VULNERABLE")


def p_secret_leakage(name: str, base: str, kind: str) -> None:
    paths = ["/health", "/.well-known/agent-card.json"] + (["/identity"] if kind == "agt" else [])
    leaked_terms = ("private", "secret", "password", "BEGIN PRIVATE", "client_secret", "api_token", "hmac")
    worst = "DEFENDED"
    seen = []
    for p in paths:
        try:
            r = httpx.get(base + p, timeout=pl.TIMEOUT)
        except Exception:
            continue
        body = r.text.lower()
        hit = [t for t in leaked_terms if t in body]
        # "public_key"/"public" is fine; only flag the private/secret terms.
        hit = [t for t in hit if t not in ("public",)]
        seen.append(f"{p}:{r.status_code}{'(' + ','.join(hit) + ')' if hit else ''}")
        if hit:
            worst = "VULNERABLE"
    record(probe="P17 secret leakage in public responses", target=name,
           attempt=f"GET {', '.join(paths)} and scan body for secrets",
           observed="; ".join(seen) or "no readable endpoints",
           expected="no private keys / secrets / passwords in responses",
           verdict=worst)


PROBES_PER_TARGET: list[Callable[[str, str, str], None]] = [
    p_no_auth, p_alg_none, p_tampered_sig, p_garbage_bearer,
    p_idor_task_read, p_rebac_denied_chunk,
    p_approval_hmac_forgery, p_approval_replay, p_callback_forgery_a2a,
    p_agt_a2a_query_unsigned, p_agt_a2a_query_forged, p_agt_callback_unsigned,
    p_oversized_query, p_secret_leakage,
]


def main() -> None:
    print("=== Red-team probe run ===\n")
    for name, base, kind in TARGETS:
        if not is_up(base):
            record(probe="(all probes)", target=name, attempt="health check",
                   observed=f"{base}/health unreachable", expected="up", verdict="BLOCKED")
            continue
        for probe in PROBES_PER_TARGET:
            try:
                probe(name, base, kind)
            except Exception as e:  # a probe crash must not abort the run
                record(probe=probe.__name__, target=name, attempt="(probe raised)",
                       observed=f"{type(e).__name__}: {e}", expected="-", verdict="BLOCKED")
    # Infra-level probes (not per-backend)
    p_openfga_no_key()
    p_client_credentials_guess()

    write_report()


def write_report() -> None:
    counts: dict[str, int] = {}
    for f in FINDINGS:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    out = Path(__file__).resolve().parent / "RED_FINDINGS.md"
    lines = [
        "# RED_FINDINGS.md — Red-team adversarial probe results",
        "",
        f"_Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} by redteam/run_probes.py_",
        "",
        "Targets: A2A (federated-rag) :8000/:8002, AGT (agt-federated-rag) :8010/:8012, "
        "OpenFGA :8089, Keycloak :8087.",
        "",
        "Verdicts: **DEFENDED** = control rejected the attack as designed; "
        "**VULNERABLE** = real bypass/leak (fix at root); "
        "**EXPECTED** = correct authorization (not a vuln); "
        "**BLOCKED** = could not run (re-run).",
        "",
        "## Summary",
        "",
        "| Verdict | Count |",
        "|---------|-------|",
    ]
    for v in ("DEFENDED", "VULNERABLE", "EXPECTED", "BLOCKED"):
        lines.append(f"| {v} | {counts.get(v, 0)} |")
    vulns = [f for f in FINDINGS if f.verdict == "VULNERABLE"]
    lines += ["", f"**Real vulnerabilities found: {len(vulns)}**", ""]
    if vulns:
        lines.append("### ⚠ VULNERABLE — needs blue-team fix")
        for f in vulns:
            lines += [f"- **{f.probe}** on {f.target}: {f.attempt} → observed `{f.observed}` "
                      f"(expected {f.expected}). {f.note}"]
        lines.append("")
    lines += ["## All probe results", "",
              "| Probe | Target | Verdict | Observed | Expected |",
              "|-------|--------|---------|----------|----------|"]
    for f in FINDINGS:
        obs = f.observed.replace("|", "\\|")[:90]
        exp = f.expected.replace("|", "\\|")
        lines.append(f"| {f.probe} | {f.target} | {f.verdict} | {obs} | {exp} |")
    lines.append("")
    Path(out).write_text("\n".join(lines), encoding="utf-8")
    print(f"\n=== wrote {out} ===")
    print("  " + "  ".join(f"{v}={counts.get(v,0)}" for v in ("DEFENDED", "VULNERABLE", "EXPECTED", "BLOCKED")))


if __name__ == "__main__":
    main()
