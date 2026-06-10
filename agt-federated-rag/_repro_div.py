r"""Division-aware flow tester — each division has its OWN Keycloak (M0).

Usage (from agt-federated-rag/):
    ..\.venv\Scripts\python.exe _repro_div.py <agent_port> <keycloak_port> <user> "<query>"
e.g. ..\.venv\Scripts\python.exe _repro_div.py 8100 8102 alice "What is our data retention policy?"
"""
from __future__ import annotations

import json
import os
import sys

import httpx

agent_port = sys.argv[1] if len(sys.argv) > 1 else "8100"
kc_port = sys.argv[2] if len(sys.argv) > 2 else "8102"
user = sys.argv[3] if len(sys.argv) > 3 else "alice"
query = sys.argv[4] if len(sys.argv) > 4 else "What is our data retention policy?"
pw = os.environ.get("RAG_SEED_PASSWORD", "Rag-User-2026!")

tok = httpx.post(
    f"http://localhost:{kc_port}/realms/rag/protocol/openid-connect/token",
    data={"grant_type": "password", "client_id": "rag-ui", "username": user, "password": pw},
    timeout=15,
).json()["access_token"]
print(f"[token] {user} from kc:{kc_port} ({len(tok)} chars) -> agent :{agent_port}")
print(f"[query] {query}")

states: list[str] = []
answer = ""
with httpx.stream(
    "POST", f"http://localhost:{agent_port}/query",
    headers={"Authorization": f"Bearer {tok}", "Accept": "text/event-stream",
             "Content-Type": "application/json"},
    json={"query": query}, timeout=120,
) as r:
    if r.status_code != 200:
        print(f"[ERROR] HTTP {r.status_code}: {r.read().decode()[:300]}"); sys.exit(1)
    for line in r.iter_lines():
        if not line.startswith("data:"):
            continue
        try:
            d = json.loads(line[5:].strip())
        except Exception:
            continue
        if isinstance(d.get("status"), str):
            states.append(d["status"])
        if d.get("answer"):
            answer = d["answer"]
print(f"[states] {' -> '.join(states)}")
print(f"[answer] {answer[:320]}")
