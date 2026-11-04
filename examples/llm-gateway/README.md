# Per-division LLM gateway (LiteLLM Proxy) — prototype

Puts a gateway between a division's agent and its model providers, for:
per-division **virtual keys** (model allowlist, rate limits, budgets), **fallback** when
the NVIDIA NIM free tier throttles or cold-starts, and a **key-enforced residency**
boundary. This folder is the standalone proof; the same gateway is wired into the real
division deployments as an **opt-in** (see "Division deployments" below). The LiteLLM
config they all share lives at [`k8s/llm-gateway/litellm-config.yaml`](../../k8s/llm-gateway/litellm-config.yaml),
because kustomize can only read files under a component's root.

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
rpm limit (200, 200, 429), budget cut-off, external-outage fallback, and no
local→external fallback.

For production, point `CHAT_PRIMARY_BASE` at `https://integrate.api.nvidia.com/v1` with
the real `NVIDIA_API_KEY`, and `LOCAL_LLM_BASE` at your self-hosted vLLM/NIM.

## Per-division keys

Create keys with the master key (admin only, never given to an agent):

```bash
curl -s localhost:4000/key/generate -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H 'Content-Type: application/json' -d '{"models":["meta/llama-3.1-8b-instruct","local/llama-3.1-8b-instruct","nvidia/nv-embedqa-e5-v5"],"rpm_limit":60,"max_budget":50,"metadata":{"division":"alpha"}}'
```

A **residency=local** division gets only the in-boundary models (chat + embeddings), plus
aliases so the app's unchanged model names land on them:

```bash
curl -s localhost:4000/key/generate -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H 'Content-Type: application/json' -d '{"models":["local/llama-3.1-8b-instruct","local/nv-embedqa-e5-v5"],"aliases":{"meta/llama-3.1-8b-instruct":"local/llama-3.1-8b-instruct","nvidia/nv-embedqa-e5-v5":"local/nv-embedqa-e5-v5"},"metadata":{"division":"sigma","residency":"local"}}'
```

`local/nv-embedqa-e5-v5` forwards to `LOCAL_EMBED_BASE`: a self-hosted OpenAI-compatible
`/embeddings` endpoint (NIM / TEI / vLLM). It must return exactly `qdrant_dense_size`
(1024) dims. `rag.embeddings.embed_dense` raises on any other size, so it never writes a
mis-sized vector. Serve the same model (`nvidia/nv-embedqa-e5-v5`) that any existing
collection was ingested with, or re-ingest. NIM's `input_type` / `truncate` are forwarded.

## Rules (each one found by running this)

1. **Never configure a fallback from an in-boundary model to an external one.** A key's
   model allowlist does *not* constrain fallbacks. With `local → meta` added to
   `fallbacks`, the local-only division's prompt was answered by the external upstream.
   The last proof scenario catches exactly this. The same goes for embeddings:
   `local/nv-embedqa-e5-v5` has no fallback at all (pinned by `tests/test_onboarding.py`).
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

## Division deployments (opt-in)

**Compose.** Add `llm_gateway: true` to `infra/divisions/<id>.yml`. For a
residency=local division, also add `llm_gateway_local_base: http://<your vLLM/NIM>/v1`,
and, if it embeds through the API (`EMBEDDING_PROVIDER=api`, the k8s default),
`llm_gateway_local_embed_base: http://<your embeddings server>/v1`. Unset, both default to
a never-resolving `.invalid` host, so they fail closed.
Then run `scripts/onboard_division.py` as usual (`--dry-run` prints the plan).
Onboarding then:
- enables the `llm-gateway` profile of `infra/division-stack.template.yml`. That adds the
  gateway on `127.0.0.1:<port_base+7>`, with network alias `llm-gateway.internal`;
- gives the gateway its own `litellm` database and role in the division's existing Postgres;
- mints the master key into `infra/generated/<id>/secrets.json`;
- issues the agent's virtual key: residency `external` gets NIM + embeddings + the local
  model; anything else gets only the local chat and embedding models, with the app's model
  names aliased onto them. The key is reused on re-run, and revoked and re-issued if its
  allowlist changes (residency switch, or a pre-embeddings local key);
- writes `OPENAI_API_BASE=http://localhost:<port_base+7>/v1` and that key into the agent
  env;
- also writes `infra/generated/<id>/.env.<id>.agent` (gitignored, owner-only), which the
  `containerized` compose profile's agent and worker read. It has the same values, but
  reaches the infra by compose name (`qdrant:6333`, `openfga:8080`, `keycloak:8080` for
  JWKS, ...) and the gateway by `http://llm-gateway.internal:4000/v1`. `--dry-run` writes
  it too, with the persisted store/model ids.

**Kubernetes.** `python scripts/bootstrap_k8s.py --divisions <id> --llm-gateway` uses the
`k8s/llm-gateway` component. See k8s/README.md, "Optional: per-division LLM gateway".

Without the flag, nothing changes: no gateway services, and the agent talks to NIM directly.

## Not covered yet

- AGT policy at the gateway — **blocked upstream** (checked 2026-11-03). The hook
  exists in the published `agent-control-specification` 0.3.1b1, but:
  - it needs an ACS manifest + Rego bundle, and `agt migrate` (agt-policies 5.0.0) does
    not convert this repo's rule YAMLs (it only flags the `PolicyEvaluator` imports);
  - the v4→ACS bridge (`governance_to_acs_manifest`) needs AGT's stock Rego library,
    which no published wheel ships;
  - AGT `main` has moved to an ACS 0.4 manifest contract that rejects 0.3.x manifests.

  It belongs with the PolicyEvaluator → AgentControl migration, once ACS 0.4 is on PyPI.
  Never add it via `pip install agent-control-specification[litellm-proxy]`: that extra
  pulls `litellm` from PyPI. Install `--no-deps` into the pinned image.
- **Budgets need prices.** `max_budget` is enforced (a key at its cap gets
  422 "Budget has been exceeded"), but spend only *accrues* for models with a price.
  These self-hosted / OpenAI-compatible model groups have none, so measured spend
  stays 0.0 and a budget never trips by itself. Set `input_cost_per_token` /
  `output_cost_per_token` on each model in `k8s/llm-gateway/litellm-config.yaml` to your NIM contract
  or GPU cost; until then, rely on the rpm/tpm limits. The proof checks enforcement
  by setting a key's recorded spend to its cap.
- cosign signature verification of the image (the digest was checked against GHCR instead).
- Real NIM traffic. The division wiring was proven only against the stub upstreams.
- **Division wiring, what was proven (2026-11-03).** The gateway part of a rendered
  Compose division stack was brought up live (division Postgres, `litellm` DB init, gateway
  and stubs). Onboarding's key provisioning and rendered agent env then drove the agent's
  real `_get_llm`, `_get_intent_llm` and `embed_dense`, and the `llm-gateway.internal`
  alias was reached from a container on the division network. The k8s component was
  rendered with kustomize 5.4.3, and its pod settings were tried in plain Docker
  (init-db.sh as uid 70 on a read-only root filesystem; the gateway with all capabilities
  dropped).
- **Not proven yet:**
  - a full `onboard_division` run with the gateway enabled (needs every division image
    and an NVIDIA key);
  - a `bootstrap_k8s --llm-gateway` run on a cluster;
  - NetworkPolicy enforcement (needs an enforcing CNI);
  - a running containerized agent. Onboarding now generates `.env.<id>.agent`, and
    `docker compose config --profile containerized` resolves the agent against it. The
    profile's relative paths (env_file, build context, edge mounts) were also off by one
    directory, and are fixed. Not yet checked: the agent image actually serving there. Known
    gaps: the DID identity file is not mounted, and Keycloak tokens fetched in-network carry
    the `keycloak:8080` issuer.
- **In-boundary embeddings, what was proven (2026-11-04).** The gateway ran with the stub
  upstreams on sandbox ports. A residency=local key came from `onboard_division.gateway_key_spec`
  and was issued with `ensure_gateway_key`. The agent's real `embed_dense` then ran with
  `EMBEDDING_PROVIDER=api` and the unchanged `EMBEDDING_MODEL`. It returned 2×1024 vectors,
  answered by the **local** stub (`input_type=query`, `truncate=END` forwarded). The
  external stub received nothing. The key got 403 for `openai/nvidia/nv-embedqa-e5-v5` and
  for `text-embedding-3-small`, and the old chat-only local key got 403 for embeddings.
  With the local upstream serving 768 dims, `embed_dense` raised its dimension-mismatch
  error and there was no fallback. Not covered: a real self-hosted embeddings server.
- The gateway container trusts only its own CA store. On a TLS-intercepting host (Norton),
  its calls to NIM need the host CA bundle, like the k8s pods do.
