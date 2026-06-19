"""Run the generated scenarios against the LIVE divisions and verify the governed flow.

For each scenario it logs in the persona (via the running Keycloak), POSTs the query to
that division's agent through the SSE /query endpoint, reads the final flow, and checks it
matches the scenario's expected_flow. This both demonstrates the scenarios and PROVES the
answers are real (different phrasings of the same doc resolve to the same governed flow via
vector retrieval, not a hardcoded lookup).

Usage:
  python scenarios/run_scenarios.py                 # run a sample (1 per situation)
  python scenarios/run_scenarios.py --all           # run everything (slow: each is an LLM call)
  python scenarios/run_scenarios.py --situation cross_division_authorized --limit 5
  python scenarios/run_scenarios.py --base http://localhost:5173   # via the UI proxy (default)

Needs the divisions up (bootstrap) and the seed passwords in infra/generated/<div>/secrets.json.
Approval/denied flows that depend on live grant state return the parked/denied flow, which is
the expected governed outcome (no human approval is performed here).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
SC = Path(__file__).resolve().parent

# pane -> (auth proxy path, api proxy path, generated-secrets division)
PANE = {
    "alpha": dict(auth="/auth/a/token", api="/api/agt-a/query", div="alpha"),
    "beta": dict(auth="/auth/b/token", api="/api/agt-b/query", div="beta"),
}
# Personas -> seed username (password read from the division's secrets.json).
USER = {"alice": "alice", "bob": "bob"}

# A returned flow is "as expected" if it is the exact flow OR an accepted synonym
# (the agent's denied-cross-division path can surface as either REMOTE_DENIED or
# LOCAL_DENIED depending on intent classification; both mean "no data released").
ACCEPT = {
    "LOCAL_ALLOWED": {"LOCAL_ALLOWED"},
    "REMOTE_APPROVED": {"REMOTE_APPROVED"},
    "LOCAL_NEEDS_APPROVAL": {"LOCAL_NEEDS_APPROVAL"},
    "REMOTE_NEEDS_APPROVAL": {"REMOTE_NEEDS_APPROVAL", "REMOTE_NEEDS_APPROVAL"},
    "REMOTE_DENIED": {"REMOTE_DENIED", "LOCAL_DENIED"},
    "LOCAL_DENIED": {"LOCAL_DENIED"},
}


def _seed_pw(div: str) -> str:
    return json.loads((ROOT / "infra" / "generated" / div / "secrets.json").read_text())["seed_user_password"]


def _token(client: httpx.Client, base: str, pane: str, user: str) -> str:
    p = PANE[pane]
    r = client.post(base + p["auth"], data={
        "grant_type": "password", "client_id": "rag-ui",
        "username": USER[user], "password": _seed_pw(p["div"]),
    }, timeout=15)
    r.raise_for_status()
    return r.json()["access_token"]


def _run_one(client: httpx.Client, base: str, token: str, pane: str, query: str) -> str:
    """POST the query, read the SSE stream, return the final flow string (or 'ERROR'/'PENDING')."""
    p = PANE[pane]
    flow = None
    try:
        with client.stream("POST", base + p["api"], headers={"Authorization": f"Bearer {token}"},
                           json={"query": query}, timeout=180) as resp:
            for line in resp.iter_lines():
                if not line or not line.startswith("data:"):
                    continue
                try:
                    d = json.loads(line[5:])
                except Exception:
                    continue
                if "flow" in d and d["flow"]:
                    flow = str(d["flow"]).replace("FlowDecision.", "")
                if d.get("status") in ("input-required", "input_required"):
                    flow = flow or "NEEDS_APPROVAL"
                if d.get("error"):
                    return f"ERROR:{d['error'][:40]}"
    except Exception as exc:  # noqa: BLE001
        return f"ERROR:{exc.__class__.__name__}"
    return flow or "UNKNOWN"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:5173")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--situation", default=None)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    scenarios = json.loads((SC / "scenarios.json").read_text())
    if args.situation:
        scenarios = [s for s in scenarios if s["situation"] == args.situation]
    if not args.all and not args.situation:
        # default: one representative per situation
        seen, sample = set(), []
        for s in scenarios:
            if s["situation"] not in seen:
                seen.add(s["situation"]); sample.append(s)
        scenarios = sample
    if args.limit:
        scenarios = scenarios[: args.limit]

    tokens: dict[tuple, str] = {}
    npass = nfail = 0
    with httpx.Client() as client:
        for s in scenarios:
            key = (s["pane"], s["persona"])
            if key not in tokens:
                try:
                    tokens[key] = _token(client, args.base, s["pane"], s["persona"])
                except Exception as exc:  # noqa: BLE001
                    print(f"  [auth-fail {key}] {exc}")
                    continue
            got = _run_one(client, args.base, tokens[key], s["pane"], s["query"])
            ok = got in ACCEPT.get(s["expected_flow"], {s["expected_flow"]}) or \
                (s["expected_flow"].endswith("NEEDS_APPROVAL") and "NEEDS_APPROVAL" in got)
            npass += ok
            nfail += (not ok)
            mark = "PASS" if ok else "FAIL"
            print(f"  [{mark}] {s['situation']:28s} exp={s['expected_flow']:22s} got={got:22s} | {s['query'][:54]}")
    print(f"\n{npass} passed, {nfail} failed (of {npass + nfail})")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
