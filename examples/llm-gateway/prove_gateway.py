"""Reproducible LIVE proof of the per-division LLM gateway (LiteLLM Proxy).

Drives the agent's REAL client factories — agent.nodes._get_llm / _get_intent_llm and
rag.embeddings.embed_dense, with their residency + SSRF guards — through the running
gateway and asserts the governed outcome of each scenario. App change = env only:
OPENAI_API_BASE=<gateway>/v1 and OPENAI_API_KEY=<the division's virtual key>.

    LITELLM_MASTER_KEY=... GATEWAY_DB_PASSWORD=... docker compose -f examples/llm-gateway/docker-compose.yml up -d
    LITELLM_MASTER_KEY=... GATEWAY_DB_PASSWORD=... .venv/Scripts/python.exe examples/llm-gateway/prove_gateway.py

Run it with the project venv (it imports the agent code). It toggles the demo stubs into
"outage" mode for the fallback scenarios and restores them at the end. GW_COMPOSE
overrides the compose invocation (default: this folder's docker-compose.yml).

What it proves:
  1. per-division virtual keys: a key is scoped to its models; others are refused
  2. residency=local division: the app's unchanged default model name is aliased onto
     the in-boundary model by the KEY, so prompts never reach the external upstream
  3. NIM's asymmetric-embedding fields (input_type, truncate) reach the upstream intact
  4. per-key rate limit (rpm) and budget (max_budget) are enforced
  5. external outage -> answered by the in-boundary fallback
  6. in-boundary outage -> FAILS for the local division; never falls back to external
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
AGENT_DIR = HERE.parents[1] / "agt-federated-rag"
GATEWAY = os.environ.get("GATEWAY_URL", "http://localhost:4000")
EXTERNAL_STUB = "http://localhost:4101"
COMPOSE = shlex.split(os.environ.get("GW_COMPOSE",
                                     f"docker compose -f {HERE / 'docker-compose.yml'}"))
MASTER = os.environ.get("LITELLM_MASTER_KEY", "")

EXT, LOCAL, EMBED = ("meta/llama-3.1-8b-instruct", "local/llama-3.1-8b-instruct",
                     "nvidia/nv-embedqa-e5-v5")

# Runs inside AGENT_DIR with the agent's settings taken from the environment.
_APP = """
import asyncio, json, sys
async def main(mode):
    try:
        if mode == "chat":
            from agent.nodes import _get_llm
            r = await (await _get_llm()).ainvoke("hi")
            out = {"content": r.content}
        elif mode == "intent":
            from agent.nodes import _get_intent_llm
            r = await (await _get_intent_llm()).ainvoke("hi")
            out = {"content": r.content}
        else:
            from rag.embeddings import embed_dense
            v = await embed_dense(["what is the refund policy?"], input_type="query")
            out = {"n": len(v), "dim": len(v[0])}
    except Exception as e:  # noqa: BLE001
        out = {"error": f"{type(e).__name__}: {e}"[:300]}
    print("RESULT " + json.dumps(out))
asyncio.run(main(sys.argv[1]))
"""


def _http(method: str, url: str, body: dict | None = None, key: str = "") -> tuple[int, dict]:
    req = urllib.request.Request(url, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {key}"} if key else {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def new_key(**spec) -> str:
    code, d = _http("POST", f"{GATEWAY}/key/generate", spec, MASTER)
    assert code == 200, f"key/generate failed: {code} {d}"
    return d["key"]


def app(mode: str, key: str, residency: str = "external") -> dict:
    env = {**os.environ, "RAG_ENV_FILE": "__none__",
           "OPENAI_API_BASE": f"{GATEWAY}/v1", "OPENAI_API_KEY": key,
           "RESIDENCY_MODE": residency, "EMBEDDING_PROVIDER": "api", "LLM_MAX_RETRIES": "0",
           # Settings fields that are REQUIRED at import but unused on this code path.
           "NEO4J_PASSWORD": "x", "OPENFGA_STORE_ID": "x", "OPENFGA_MODEL_ID": "x",
           "AGENT_CLIENT_ID": "x", "AGENT_CLIENT_SECRET": "x",
           "AGENT_SPONSOR_EMAIL": "proof@example.com", "APPROVAL_HMAC_SECRET": "0" * 64}
    p = subprocess.run([sys.executable, "-W", "ignore", "-c", _APP, mode], cwd=AGENT_DIR,
                       env=env, capture_output=True, text=True, timeout=300)
    line = next((x for x in p.stdout.splitlines() if x.startswith("RESULT ")), None)
    assert line, f"app run produced no result:\n{p.stdout[-800:]}\n{p.stderr[-1500:]}"
    return json.loads(line[7:])


def upstream_last() -> dict:
    return _http("GET", f"{EXTERNAL_STUB}/last")[1]


def outage(service: str, failing: bool) -> None:
    var = {"stub-external": "STUB_EXTERNAL_FAIL", "stub-local": "STUB_LOCAL_FAIL"}[service]
    subprocess.run([*COMPOSE, "up", "-d", service], env={**os.environ, var: "1" if failing else "0"},
                   check=True, capture_output=True)
    for _ in range(30):  # wait until the restarted stub answers again
        try:
            urllib.request.urlopen(f"http://localhost:{4101 if 'external' in service else 4102}/",
                                   timeout=2)
            return
        except OSError:
            time.sleep(0.5)


RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def main() -> int:
    if not MASTER:
        print("set LITELLM_MASTER_KEY (the gateway admin key)")
        return 2
    print(f"gateway {GATEWAY}: {_http('GET', f'{GATEWAY}/health/liveliness')}")
    outage("stub-external", False)   # start from a known-healthy state
    outage("stub-local", False)

    alpha = new_key(models=[EXT, LOCAL, EMBED], metadata={"division": "alpha"})
    sigma = new_key(models=[LOCAL], aliases={EXT: LOCAL},
                    metadata={"division": "sigma", "residency": "local"})
    limited = new_key(models=[EXT], rpm_limit=2, metadata={"division": "rate-limited"})
    print("issued per-division keys: alpha (external+local+embed), "
          "sigma (local only, residency=local), rate-limited (rpm=2)\n")

    r = app("chat", alpha)
    check("alpha chat via gateway", r.get("content") == "[external-nim] ok", str(r))
    r = app("intent", alpha)
    check("alpha intent LLM via gateway", r.get("content") == "[external-nim] ok", str(r))

    r = app("embed", alpha)
    got = upstream_last().get("body", {})
    check("alpha embed_dense via gateway", r.get("dim") == 1024, str(r))
    check("NIM input_type/truncate forwarded upstream",
          got.get("input_type") == "query" and got.get("truncate") == "END",
          f"upstream received input_type={got.get('input_type')!r} truncate={got.get('truncate')!r}")

    # Stamp a fresh marker into the external stub's /last, so "unchanged" below can only
    # mean that no request reached it (not that two requests happened to look alike).
    _http("POST", f"{EXTERNAL_STUB}/marker", {"marker": "before-sigma"})
    before = upstream_last()
    r = app("chat", sigma, residency="local")
    check("sigma (residency=local), unchanged app model -> in-boundary model",
          r.get("content") == "[local-vllm] ok", str(r))
    check("sigma prompt never reached the external upstream", upstream_last() == before,
          "external stub's last request unchanged")
    r = app("embed", sigma, residency="local")
    check("sigma refused the external embedding model",
          "error" in r and any(c in r["error"] for c in ("401", "403")),
          r.get("error", str(r))[:110])

    codes = [_http("POST", f"{GATEWAY}/v1/chat/completions",
                   {"model": EXT, "messages": [{"role": "user", "content": "hi"}]}, limited)[0]
             for _ in range(3)]
    check("per-key rate limit (rpm=2)", codes == [200, 200, 429], f"status codes {codes}")

    # Budget: enforcement is checked by setting the key's recorded spend to its cap (the
    # admin API), because spend only ACCRUES for models with a configured price — and these
    # self-hosted/OpenAI-compatible models have none (cost 0.0). See README.
    budgeted = new_key(models=[EXT], max_budget=1.0, metadata={"division": "budgeted"})
    msg = {"model": EXT, "messages": [{"role": "user", "content": "hi"}]}
    under = _http("POST", f"{GATEWAY}/v1/chat/completions", msg, budgeted)[0]
    _http("POST", f"{GATEWAY}/key/update", {"key": budgeted, "spend": 1.0}, MASTER)
    over, body = _http("POST", f"{GATEWAY}/v1/chat/completions", msg, budgeted)
    check("per-key budget: refused once spend reaches max_budget",
          under == 200 and over != 200 and "Budget has been exceeded" in json.dumps(body),
          f"under budget -> {under}, at budget -> {over}")

    try:
        outage("stub-external", True)
        r = app("chat", alpha)
        check("external outage -> in-boundary fallback answers",
              r.get("content") == "[local-vllm] ok", str(r))
    finally:
        outage("stub-external", False)

    try:
        outage("stub-local", True)
        _http("POST", f"{EXTERNAL_STUB}/marker", {"marker": "before-local-outage"})
        before = upstream_last()
        r = app("chat", sigma, residency="local")
        check("in-boundary outage -> sigma FAILS (no fallback to external)",
              "error" in r and upstream_last() == before,
              f"{r.get('error', r)!s:.90} | external stub untouched={upstream_last() == before}")
    finally:
        outage("stub-local", False)

    passed = sum(ok for _, ok, _ in RESULTS)
    print(f"\n{passed}/{len(RESULTS)} scenarios passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
