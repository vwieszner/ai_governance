#!/usr/bin/env python
"""Start the multi-division browser chat and serve it at http://localhost:5173.

One command brings up everything the chat needs, reading the SINGLE source of truth
(`ui/divisions.config.json`):
  - Compose divisions (no `k8sNamespace`, e.g. alpha/beta): their host agent processes,
    started via scripts/clusters.ps1 if not already up.
  - Kubernetes divisions (`k8sNamespace` set, e.g. gamma/delta/epsilon): a `kubectl
    port-forward` for each one's agent + Keycloak so the Vite proxy can reach them.
  - the Vite UI itself.
Then it prints a per-division status table + the per-browser URLs. Ctrl+C tears down
everything this script started (port-forwards + Vite); host agents keep running
(`scripts/clusters.ps1 stop <ids>` to stop those).

    python scripts/present.py

Add a division to the line-up: add one entry to ui/divisions.config.json (id, label,
agentPort, keycloakPort [, k8sNamespace, k8sContext]) — both the UI and this launcher
pick it up. No code change.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "ui" / "divisions.config.json"
IS_WIN = os.name == "nt"
UI_PORT = 5173

_procs: list[subprocess.Popen] = []


def _up(port: int, path: str = "/health") -> bool:
    try:
        with urllib.request.urlopen(f"http://localhost:{port}{path}", timeout=3) as r:
            return 200 <= r.status < 500
    except Exception:
        return False


def _start_compose_agents(divs: list[dict]) -> None:
    compose = [d for d in divs if not d.get("k8sNamespace")]
    down = [d for d in compose if not _up(d["agentPort"])]
    if not down:
        if compose:
            print(f"  compose agents already up: {', '.join(d['id'] for d in compose)}")
        return
    ids = [d["id"] for d in down]
    print(f"  starting compose agents: {', '.join(ids)}")
    if IS_WIN:
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", str(ROOT / "scripts" / "clusters.ps1"), "start", *ids],
                       check=False)
    else:
        print(f"    (non-Windows host: start these agents yourself — RAG_ENV_FILE=.env.<id> "
              f"uvicorn api.main:app, ports {[d['agentPort'] for d in down]})")


def _start_k8s_port_forwards(divs: list[dict]) -> None:
    for d in divs:
        ns = d.get("k8sNamespace")
        if not ns:
            continue
        ctx = d.get("k8sContext", "kind-agt")
        if _up(d["agentPort"]):
            print(f"  {d['id']}: already reachable on :{d['agentPort']}")
            continue
        print(f"  port-forwarding {d['id']} ({ns}) -> :{d['agentPort']} / :{d['keycloakPort']}")
        for svc, local, remote in (("agent", d["agentPort"], 8000), ("keycloak", d["keycloakPort"], 8080)):
            _procs.append(subprocess.Popen(
                ["kubectl", "--context", ctx, "-n", ns, "port-forward", f"svc/{svc}", f"{local}:{remote}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))


def _start_ui() -> None:
    if _up(UI_PORT, "/"):
        print(f"  UI already serving on :{UI_PORT}")
        return
    npm = "npm.cmd" if IS_WIN else "npm"
    print("  starting Vite UI")
    _procs.append(subprocess.Popen([npm, "run", "start"], cwd=str(ROOT / "ui"),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))


def main() -> None:
    divs = json.loads(CONFIG.read_text(encoding="utf-8"))
    print("AGT — starting the multi-division browser chat\n")
    print("[1/3] compose division agents")
    _start_compose_agents(divs)
    print("[2/3] kubernetes division port-forwards")
    _start_k8s_port_forwards(divs)
    print("[3/3] web UI")
    _start_ui()

    # Wait for things to settle, then report what's actually reachable (no false claims).
    print("\nwaiting for divisions to come up ...")
    for _ in range(20):
        time.sleep(3)
        if _up(UI_PORT, "/") and all(_up(d["agentPort"]) for d in divs):
            break

    print("\n  division           agent      browser URL")
    print("  " + "-" * 64)
    for d in divs:
        ok = "UP  " if _up(d["agentPort"]) else "DOWN"
        print(f"  {d['label']:<26} {ok}   http://localhost:{UI_PORT}/?cluster={d['id']}")
    print("\n  picker:  http://localhost:%d/   (logins: infra/generated/<div>/secrets.json)" % UI_PORT)
    print("  open each division in its OWN browser/window to present the federation.")
    print("\n  Ctrl+C to stop (tears down port-forwards + the UI this script started).")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping ...")
    finally:
        for p in _procs:
            p.terminate()
        for p in _procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
