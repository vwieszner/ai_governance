"""agtctl — admin CLI for the AGT federated-RAG deployment (Phase-1 item 12).

Day-2 operations without writing code or poking OpenFGA by hand. Operates per division via
the generated artifacts (infra/generated/<id>/{secrets,state}.json) + the division manifest.

    agtctl status                                   # health of every division
    agtctl doctor   --division alpha                # post-deploy smoke checks
    agtctl list     --division beta --doc q4_financial_results
    agtctl grant    --division beta --group finance --doc q4_financial_results
    agtctl grant    --division beta --user alice@example.com --home alpha --doc q4_financial_results
    agtctl grant    --division beta --user alice@example.com --doc q4_financial_results --relation pending_approval
    agtctl revoke   --division beta --user alice@example.com --home alpha --doc q4_financial_results

Grants accept a USER (namespaced by its home division's issuer) or a GROUP (group#member
viewer userset, the baseline-access path). `--relation` is viewer (default) | pending_approval.
This is the scriptable twin of the seed flow + /access/revoke — same principals, same tuples.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

REALM = "rag"
PORT_OFFSETS = {"agent": 0, "openfga": 1, "keycloak": 2, "temporal": 3,
                "temporal_ui": 4, "qdrant": 5, "redis": 6}


# ── pure helpers (unit-tested) ──────────────────────────────────────────────────

def issuer_namespace(iss: str) -> str:
    """Identical to auth.token_validator.issuer_namespace (seed/runtime parity)."""
    return hashlib.sha256(iss.rstrip("/").encode("utf-8")).hexdigest()[:16]


def principal(email: str, issuer: str) -> str:
    return f"{email.strip().lower()}|{issuer_namespace(issuer)}"


def subject_ref(kind: str, value: str, issuer: str | None) -> str:
    """OpenFGA subject string. user -> 'user:<principal>'; group -> 'group:<g>#member'."""
    if kind == "group":
        return value if value.startswith("group:") else f"group:{value}#member"
    if not issuer:
        raise ValueError("user grant requires an issuer (the user's home division)")
    return f"user:{principal(value, issuer)}"


def manifest_port_base(division: str) -> int:
    import yaml
    m = yaml.safe_load((ROOT / "infra" / "divisions" / f"{division}.yml").read_text(encoding="utf-8"))
    return int(m["port_base"])


def division_issuer(division: str) -> str:
    base = manifest_port_base(division)
    return f"http://localhost:{base + PORT_OFFSETS['keycloak']}/realms/{REALM}"


# ── live context (OpenFGA REST) ─────────────────────────────────────────────────

def _ctx(division: str) -> dict:
    base = manifest_port_base(division)
    gen = ROOT / "infra" / "generated" / division
    secrets = json.loads((gen / "secrets.json").read_text(encoding="utf-8"))
    state = json.loads((gen / "state.json").read_text(encoding="utf-8"))
    return {
        "ofga": f"http://127.0.0.1:{base + PORT_OFFSETS['openfga']}",
        "qdrant": f"http://127.0.0.1:{base + PORT_OFFSETS['qdrant']}",
        "agent": f"http://127.0.0.1:{base + PORT_OFFSETS['agent']}",
        "token": secrets.get("openfga_api_token", ""),
        "store_id": state["store_id"],
        "model_id": state["model_id"],
    }


def _req(method: str, url: str, token: str = "", body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    resp = urllib.request.urlopen(r, timeout=15)
    raw = resp.read()
    return json.loads(raw) if raw.strip() else None


def _chunks_for_doc(ctx: dict, title: str) -> list[str]:
    out = _req("POST", f"{ctx['qdrant']}/collections/knowledge_base/points/scroll", body={
        "limit": 512, "with_payload": True, "with_vector": False})
    ids = []
    for pt in out.get("result", {}).get("points", []):
        pl = pt.get("payload", {})
        t = pl.get("title") or (pl.get("metadata") or {}).get("title", "")
        cid = pl.get("chunk_id", "")
        if t == title and cid:
            ids.append(cid)
    return ids


def _write(ctx: dict, subject: str, relation: str, chunk_id: str, delete=False) -> None:
    key = {"tuple_keys": [{"user": subject, "relation": relation, "object": f"chunk:{chunk_id}"}]}
    body = {"authorization_model_id": ctx["model_id"], ("deletes" if delete else "writes"): key}
    try:
        _req("POST", f"{ctx['ofga']}/stores/{ctx['store_id']}/write", ctx["token"], body)
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:160].lower()
        if "already exist" in detail or "did not exist" in detail or "does not exist" in detail:
            return   # idempotent
        raise


# ── commands ─────────────────────────────────────────────────────────────────────

def cmd_status(_args) -> int:
    divs = sorted(p.stem for p in (ROOT / "infra" / "divisions").glob("*.yml"))
    rc = 0
    for d in divs:
        base = manifest_port_base(d)
        try:
            h = _req("GET", f"http://127.0.0.1:{base}/health")
            print(f"  {d:8} :{base}  UP   {json.dumps(h)}")
        except Exception as e:
            print(f"  {d:8} :{base}  DOWN ({type(e).__name__})")
            rc = 1
    return rc


def cmd_doctor(args) -> int:
    d = args.division
    ctx = _ctx(d)
    ok = True
    for name, url in [("agent /health", f"{ctx['agent']}/health"),
                      ("openfga", f"{ctx['ofga']}/healthz"),
                      ("qdrant", f"{ctx['qdrant']}/healthz")]:
        try:
            _req("GET", url); print(f"  [OK]   {name}")
        except Exception as e:
            print(f"  [FAIL] {name}: {type(e).__name__}"); ok = False
    return 0 if ok else 1


def _resolve_chunks(ctx, doc):
    cids = _chunks_for_doc(ctx, doc)
    if not cids:
        print(f"  document '{doc}' has no chunks in this division"); raise SystemExit(2)
    return cids


def cmd_grant(args) -> int:
    ctx = _ctx(args.division)
    issuer = division_issuer(args.home) if args.user else None
    subj = subject_ref("group" if args.group else "user", args.group or args.user, issuer)
    relation = args.relation
    cids = _resolve_chunks(ctx, args.doc)
    for cid in cids:
        _write(ctx, subj, relation, cid)
    print(f"  granted {subj} {relation} on '{args.doc}' ({len(cids)} chunks)")
    return 0


def cmd_revoke(args) -> int:
    ctx = _ctx(args.division)
    issuer = division_issuer(args.home) if args.user else None
    subj = subject_ref("group" if args.group else "user", args.group or args.user, issuer)
    cids = _resolve_chunks(ctx, args.doc)
    for cid in cids:
        _write(ctx, subj, "viewer", cid, delete=True)
    print(f"  revoked {subj} viewer on '{args.doc}' ({len(cids)} chunks)")
    return 0


def cmd_list(args) -> int:
    ctx = _ctx(args.division)
    cids = _resolve_chunks(ctx, args.doc)
    print(f"  '{args.doc}' -> {len(cids)} chunk(s); tuples:")
    for cid in cids:
        out = _req("POST", f"{ctx['ofga']}/stores/{ctx['store_id']}/read", ctx["token"],
                   {"tuple_key": {"object": f"chunk:{cid}"}})
        for t in out.get("tuples", []):
            k = t["key"]
            print(f"    {k['user']:50} {k['relation']:16} {k['object']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="agtctl", description="AGT federated-RAG admin CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(func=cmd_status)
    pd = sub.add_parser("doctor"); pd.add_argument("--division", required=True); pd.set_defaults(func=cmd_doctor)

    def add_grant_args(p, with_relation):
        p.add_argument("--division", required=True)
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--user"); g.add_argument("--group")
        p.add_argument("--home", help="home division of a --user (defaults to --division)")
        p.add_argument("--doc", required=True)
        if with_relation:
            p.add_argument("--relation", choices=["viewer", "pending_approval"], default="viewer")

    pg = sub.add_parser("grant"); add_grant_args(pg, True); pg.set_defaults(func=cmd_grant)
    pr = sub.add_parser("revoke"); add_grant_args(pr, False); pr.set_defaults(func=cmd_revoke)
    pl = sub.add_parser("list"); pl.add_argument("--division", required=True); pl.add_argument("--doc", required=True); pl.set_defaults(func=cmd_list)
    return ap


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    # default --home to --division for user grants
    if getattr(args, "user", None) and not getattr(args, "home", None):
        args.home = args.division
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
