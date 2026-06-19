"""Browser UI for governed cross-department tool delegation (live on the kind cluster).

Run it, open http://localhost:8800, pick a department + tool + input, hit Run, and watch
whether the department ran its OWN tool (local) or securely BORROWED a peer's (delegated,
over the DID-signed /a2a/tool channel). This little server does the cluster plumbing
(kubectl port-forwards + Keycloak login) so the browser page stays simple.

    python examples/cross-agent-pii/browser_demo.py     # then open http://localhost:8800

Prereq: gamma/delta/epsilon up + federated on kind-agt (scripts/bootstrap_k8s.py).
"""
from __future__ import annotations

import http.client
import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CTX = "kind-agt"
UI_PORT = 8800
DIVS = {  # division -> (agent local port, keycloak local port, label)
    "gamma": (9200, 9202, "Security / Legal"),
    "delta": (9300, 9302, "Risk / Data-Gov"),
    "epsilon": (9400, 9402, "Finance"),
}
SERVES = {"gamma": ["tool.pii", "tool.compliance"], "delta": ["tool.risk", "tool.classify"],
          "epsilon": ["tool.fincheck"]}
EXAMPLES = {
    "tool.pii": {"text": "reach me at alice@example.com, card 4242424242424242, SSN 123-45-6789"},
    "tool.compliance": {"topic": "transparency obligations"},
    "tool.risk": {"description": "a recruitment screening AI system that ranks job candidates"},
    "tool.classify": {"text": "STRICTLY CONFIDENTIAL — Q4 board financials and card 4242424242424242"},
    "tool.fincheck": {"amount": 50000, "currency": "USD", "counterparty": "Volkov Holdings"},
}

_procs: list = []


def _retry(fn, n=6):
    last = None
    for _ in range(n):
        try:
            return fn()
        except (http.client.RemoteDisconnected, ConnectionError, urllib.error.URLError) as exc:
            last = exc
            time.sleep(1.5)
    raise last


def _start_port_forwards() -> None:
    for div, (ap, kp, _) in DIVS.items():
        ns = f"agt-div-{div}"
        for svc, local, remote in (("agent", ap, 8000), ("keycloak", kp, 8080)):
            _procs.append(subprocess.Popen(
                ["kubectl", "--context", CTX, "-n", ns, "port-forward", f"svc/{svc}", f"{local}:{remote}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(9)


def _token(div: str) -> str:
    _ap, kp, _ = DIVS[div]
    pw = json.loads((ROOT / "infra" / "generated" / div / "secrets.json").read_text())["seed_user_password"]
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "rag-ui",
                                   "username": "alice", "password": pw}).encode()
    url = f"http://localhost:{kp}/realms/rag/protocol/openid-connect/token"
    return _retry(lambda: json.loads(urllib.request.urlopen(url, data=data, timeout=15).read()))["access_token"]


def _solve(div: str, capability: str, arguments: dict) -> dict:
    ap, _kp, _ = DIVS[div]
    tok = _token(div)

    def call():
        req = urllib.request.Request(
            f"http://localhost:{ap}/solve",
            data=json.dumps({"capability": capability, "arguments": arguments}).encode(),
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    return _retry(call)


PAGE = """<!doctype html><html><head><meta charset=utf-8><title>AGT — cross-department tools</title>
<style>
 body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#1a1a2e;background:#f6f7fb}
 h1{font-size:21px} .sub{color:#666;margin-top:-8px}
 .card{background:#fff;border:1px solid #e3e6ef;border-radius:12px;padding:16px;margin:14px 0;box-shadow:0 1px 3px #0001}
 label{font-weight:600;font-size:13px;display:block;margin:10px 0 4px} select,textarea,input{width:100%;font:14px monospace;padding:8px;border:1px solid #cfd4e4;border-radius:8px;box-sizing:border-box}
 textarea{height:90px} button{margin-top:14px;background:#3b5bdb;color:#fff;border:0;border-radius:8px;padding:11px 20px;font-size:15px;font-weight:600;cursor:pointer}
 button:disabled{opacity:.5} .row{display:flex;gap:12px} .row>div{flex:1}
 .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:700}
 .local{background:#e7f5ec;color:#137333} .peer{background:#fff0e0;color:#b85c00}
 pre{background:#0f1020;color:#d6e0ff;padding:14px;border-radius:8px;overflow:auto;font-size:13px}
 .hint{color:#888;font-size:12px;margin-top:6px}
</style></head><body>
<h1>🏛️ AGT — governed cross-department tool delegation</h1>
<p class=sub>Pick a department and a tool. If the department owns the tool it runs it <b>locally</b>;
if not, it securely <b>delegates</b> to the peer that owns it — over a DID-signed channel, the peer re-authorizing you.</p>
<div class=card>
 <div class=row>
  <div><label>Department (who you log in as)</label><select id=div></select><div class=hint id=owns></div></div>
  <div><label>Tool / capability</label><select id=cap></select><div class=hint id=where></div></div>
 </div>
 <label>Input (JSON)</label><textarea id=args></textarea>
 <button id=run onclick=run()>Run →</button>
</div>
<div class=card id=out style=display:none>
 <div id=verdict></div><pre id=result></pre>
</div>
<script>
const DIVS=__DIVS__, SERVES=__SERVES__, EX=__EX__, CAPS=Object.keys(EX);
const d=document, $=id=>d.getElementById(id);
for(const k in DIVS){let o=d.createElement('option');o.value=k;o.text=k+' — '+DIVS[k][2];$('div').add(o)}
for(const c of CAPS){let o=d.createElement('option');o.value=c;o.text=c;$('cap').add(o)}
function refresh(){
 const dv=$('div').value, cap=$('cap').value;
 $('owns').textContent='serves locally: '+SERVES[dv].join(', ');
 const local=SERVES[dv].includes(cap);
 $('where').innerHTML=local?'<b style=color:#137333>runs LOCALLY here</b>':'<b style=color:#b85c00>will DELEGATE to the owner</b>';
 $('args').value=JSON.stringify(EX[cap],null,2);
}
$('div').onchange=refresh;$('cap').onchange=refresh;refresh();
async function run(){
 $('run').disabled=true;$('run').textContent='Running…';$('out').style.display='none';
 try{
  const body={division:$('div').value,capability:$('cap').value,arguments:JSON.parse($('args').value)};
  const r=await fetch('/api/solve',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json();
  if(j.error){$('verdict').innerHTML='<b style=color:#c00>error</b>';$('result').textContent=j.error}
  else{
   const local=j.source==='local';
   $('verdict').innerHTML='<b>'+body.division+'</b> asked for <b>'+body.capability+'</b> &nbsp; '+
    (local?'<span class="badge local">✓ ran LOCALLY (owns the tool)</span>'
          :'<span class="badge peer">⇄ DELEGATED to peer</span> <span class=hint>'+j.peer_did+'</span>');
   $('result').textContent=JSON.stringify(j.result,null,2);
  }
  $('out').style.display='block';
 }catch(e){$('verdict').textContent=''+e;$('out').style.display='block'}
 $('run').disabled=false;$('run').textContent='Run →';
}
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_response(404); self.end_headers(); return
        html = (PAGE.replace("__DIVS__", json.dumps(DIVS))
                    .replace("__SERVES__", json.dumps(SERVES))
                    .replace("__EX__", json.dumps(EXAMPLES))).encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self):
        if self.path != "/api/solve":
            self.send_response(404); self.end_headers(); return
        n = int(self.headers.get("content-length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        try:
            out = _solve(req["division"], req["capability"], req.get("arguments", {}))
        except Exception as exc:  # noqa: BLE001
            out = {"error": f"{type(exc).__name__}: {exc}"}
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    print("starting kubectl port-forwards to gamma/delta/epsilon …")
    _start_port_forwards()
    srv = ThreadingHTTPServer(("127.0.0.1", UI_PORT), Handler)
    print(f"\n  ->  open  http://localhost:{UI_PORT}  in your browser\n  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for p in _procs:
            p.terminate()


if __name__ == "__main__":
    main()
