# Per-division LLM gateway (LiteLLM Proxy) — prototype

Puts a gateway between a division's agent and its model providers, for:
per-division **virtual keys** (model allowlist, rate limits, budgets), **fallback** when
the NVIDIA NIM free tier throttles or cold-starts, and a **key-enforced residency**
boundary. Standalone demo; the division stack (`infra/division-stack.template.yml`)
is not changed yet.

**App change: environment only.** The gateway's model groups use the exact model IDs
the agent already sends (`llm_model`, the intent model, `embedding_model`), so a
division only sets:

```
OPENAI_API_BASE=http://<gateway-host>:4000/v1
OPENAI_API_KEY=<that division's virtual key>
```

## Run the proof

```bash
export LITELLM_MASTER_KEY=sk-$(openssl rand -hex 16) GATEWAY_DB_PASSWORD=$(openssl rand -hex 16)
```
```bash
docker compose -f examples/llm-gateway/docker-compose.yml up -d
```
```bash
.venv/Scripts/python.exe examples/llm-gateway/prove_gateway.py
```

It drives the agent's **real** client factories (`agent.nodes._get_llm`,
`_get_intent_llm`, `rag.embeddings.embed_dense`, with their residency and SSRF guards)
through the gateway against two stub upstreams (`stub_upstream.py` standing in for NIM
and a local vLLM). Result in the dev sandbox (2026-11-03): **10/10**, covering
per-division keys, the residency alias, NIM `input_type`/`truncate` passthrough, an
rpm limit (200, 200, 429), external-outage fallback, and no local→external fallback.

For production, point `CHAT_PRIMARY_BASE` at `https://integrate.api.nvidia.com/v1` with
the real `NVIDIA_API_KEY`, and `LOCAL_LLM_BASE` at your self-hosted vLLM/NIM.

## Per-division keys

Create keys with the master key (admin only, never given to an agent):

```bash
curl -s localhost:4000/key/generate -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H 'Content-Type: application/json' -d '{"models":["meta/llama-3.1-8b-instruct","local/llama-3.1-8b-instruct","nvidia/nv-embedqa-e5-v5"],"rpm_limit":60,"max_budget":50,"metadata":{"division":"alpha"}}'
```

A **residency=local** division gets only the in-boundary model, plus an alias so the
app's unchanged default model name lands on it:

```bash
curl -s localhost:4000/key/generate -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H 'Content-Type: application/json' -d '{"models":["local/llama-3.1-8b-instruct"],"aliases":{"meta/llama-3.1-8b-instruct":"local/llama-3.1-8b-instruct"},"metadata":{"division":"sigma","residency":"local"}}'
```

## Rules (each one found by running this)

1. **Never configure a fallback from an in-boundary model to an external one.** A key's
   model allowlist does *not* constrain fallbacks. With `local → meta` added to
   `fallbacks`, the local-only division's prompt was answered by the external upstream.
   The last proof scenario catches exactly this.
2. **The agent's residency guard only sees the gateway URL.** `assert_inference_allowed`
   accepts any in-boundary gateway, wherever that gateway forwards. For a local division
   the boundary is enforced by its key (rule 1, plus the allowlist), not by the URL.
3. **Address the gateway by an in-boundary DNS name**, e.g. `litellm.<ns>.svc.cluster.local`
   on Kubernetes or a `.internal` alias in Compose:
   - a literal loopback IP (`http://127.0.0.1:4000`) is refused by the embedding SSRF guard;
   - a bare Compose service name (`http://litellm:4000`) counts as *external* in residency=local.
4. **Image pinned by digest; never `pip install litellm`.** The 2026 PyPI compromise
   (1.82.7/1.82.8) shipped through pip. The pinned Docker Hub index digest
   (`v1.106.6`) is byte-identical to the official `ghcr.io/berriai/litellm:v1.106.6`
   index. Admin UI disabled; port bound to loopback.

## Not covered yet

- AGT policy at the gateway: AGT's `AgentControlLiteLLMGuardrail` hook (in
  `agent-control-specification[litellm-proxy]`) would need a derived image. It targets
  the ACS policy model, so it belongs with the PolicyEvaluator → AgentControl migration.
- Budgets (`max_budget`) are configured as above but not asserted by the proof (spend is
  written asynchronously); rate limits are.
- cosign signature verification of the image (the digest was checked against GHCR instead).
- Real NIM traffic, and the division stack / Kubernetes wiring.
