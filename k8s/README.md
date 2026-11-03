# Kubernetes deployment (kustomize) — per-division isolated stacks

This `k8s/` tree is a **production-shaped Kubernetes deployment of the current
per-division isolated stack** (PROJECT_STATUS.md decision D-3, NFR-2). It is the
Kubernetes expression of `infra/division-stack.template.yml` (the Docker Compose
source of truth): the same services, the **same pinned image versions**, the same
per-division physical isolation.

> **This complements — it does NOT replace — the Compose path.** Local dev and the
> demo still run on Compose via `scripts/onboard_division.py`. Kubernetes is for a
> real multi-node / multi-cloud deployment.
>
> **Multi-cluster (one cluster per division) — the production-shaped topology:** see
> **[`MULTICLUSTER.md`](MULTICLUSTER.md)** for deploying a division to ANY cluster
> (kind/EKS/GKE/AKS/on-prem), exposing the agent with a routable endpoint, and federating
> agents across clusters over routable URLs + DIDs. Local quickstart: `python
> scripts/multicluster.py up --divisions gamma,delta` (one kind cluster per division,
> federated + proven across clusters).

---

## Quick start (turnkey — one command)

`scripts/bootstrap_k8s.py` is the Kubernetes equivalent of the Compose `bootstrap`: for each
division it loads the image, applies the overlay, creates the Secret, waits for the data plane,
**provisions** (OpenFGA store/model + Keycloak realm/users/roles + **doc ingest** + DID — reusing
the exact tested `onboard_division.provision()` over short-lived port-forwards), completes the
Secret with the store/model ids, restarts agent+worker, and verifies `/health`.

```bash
# prereqs: a cluster context (e.g. `kind create cluster --name agt`), the agent image built
#          (docker build -t agt-federated-rag:alpha agt-federated-rag/), and ./.env with NVIDIA_API_KEY
python scripts/bootstrap_k8s.py --divisions gamma
python scripts/bootstrap_k8s.py --divisions alpha,beta --context kind-agt
```

When it finishes, the division is fully provisioned and serving. Reach it with a port-forward:

```bash
kubectl -n agt-div-gamma port-forward svc/agent 9200:8000      # then GET http://localhost:9200/health
kubectl -n agt-div-gamma port-forward svc/keycloak 9202:8080   # mint a user token to query (client_id rag-ui)
```

> Cross-platform, no hidden processes, no force-kills — it only runs `docker`/`kind`/`kubectl`/
> `python`. (A heuristic AV may still flag *any* unsigned script that drives `kubectl` + port-forwards;
> the source is ~130 readable lines.) The **manual** steps below are what this automates — read them
> to understand or customize the flow.

> **Embeddings = a SERVED API, not an in-pod model.** On Kubernetes the base ConfigMap
> sets `EMBEDDING_PROVIDER=api` (with `EMBEDDING_MODEL` + `EMBEDDING_API_BASE`), so the
> agent gets its **dense** vector from an OpenAI-compatible embeddings endpoint — no
> 1.3GB model download into the pod. **BM25 sparse** retrieval stays local in-pod, so
> hybrid search still works. The `EMBEDDING_API_KEY` lives in the Secret (same NVIDIA
> key as the LLM). For **data-residency** mode, self-host the embedding endpoint
> in-cluster (a NIM/TEI Service) and point `EMBEDDING_API_BASE` at it — exactly like
> self-hosting the LLM — so no embedding text leaves the cluster.
>
> Two model-specific notes for `nv-embedqa-e5-v5`, both already wired in the base:
> - **Relevance threshold:** its cosine scores run much lower than bge-large
>   (relevant chunks ~0.30, not ~0.55), so the base sets `QDRANT_SCORE_THRESHOLD=0.25`.
>   The bge-tuned default (~0.55) would filter every real hit. Raise it back if you
>   switch to bge-large / local mode.
> - **Long chunks:** the served embedder truncates over-length chunks via
>   `EMBEDDING_TRUNCATE` (default `END`) — `nv-embedqa` returns HTTP 400 on inputs
>   over its 512-token limit without it. The default works; no manifest change needed.

**Federation across k8s divisions** (cross-DID trust) is folded into `bootstrap_k8s.py --federate`:
after the divisions are up and their DIDs exist, it mounts each division's stable DID identity,
patches every division's ConfigMap with the peer trust map + unique issuer, applies the
cross-grants to each division's OpenFGA, and restarts the agents. Same-cluster, the peer URL is the
cross-namespace Service DNS (`agent.agt-div-<peer>.svc.cluster.local:8000`), which the
`allow-agent-federation` NetworkPolicy permits.

```bash
# bring up gamma + delta AND federate them in one command:
python scripts/bootstrap_k8s.py --divisions gamma,delta --federate --context kind-agt
```

**Governed cross-agent tool delegation** rides the same `--federate` step. Each division is a
**self-sufficient department**: its own data (per-division Qdrant + OpenFGA) AND its own distinct
governed tools, declared via `AGT_LOCAL_TOOLS` (from its manifest `local_tools`). The federate step
computes each division's `PEER_TOOL_MAP` (`{capability: provider_DID}`) for every capability it does
**not** serve but a trusted peer does — building an **N-way** tool mesh with **no discovery broker**.
On the cluster three departments collaborate: gamma (Security/Legal) serves `tool.pii,tool.compliance`,
delta (Risk/Data-Gov) serves `tool.risk,tool.classify`, and epsilon (Finance) serves `tool.fincheck` —
each delegates the capabilities it lacks to whichever peer owns them, both ways. The extensibility
walkthrough — **add a tool**, **add a RaaS retrieval connector**, **add a department** (epsilon is the
worked example) — with the exact `POST /solve` curls is in
[`examples/cross-agent-pii/README.md`](../examples/cross-agent-pii/README.md).

---

## What gets deployed (one division = one isolated stack)

Each division is a **physically isolated stack** — its own OpenFGA store, Qdrant,
Redis, Keycloak realm, Temporal, Postgres, and DID. In Compose that is a per-project
network + volumes; in Kubernetes it is a **dedicated Namespace + a default-deny
NetworkPolicy**.

| Component | Kind | Image (pinned, matches Compose) | Notes |
|---|---|---|---|
| postgres | StatefulSet + PVC | `postgres:16-alpine` | backs OpenFGA |
| openfga-migrate | Job (one-shot) | `openfga/openfga:v1.16.1` | schema migration, waits on postgres |
| openfga | Deployment | `openfga/openfga:v1.16.1` | per-chunk ReBAC store |
| keycloak | StatefulSet + PVC | `quay.io/keycloak/keycloak:26.6.2` | this division's realm host |
| temporal | StatefulSet + PVC | `temporalio/temporal:1.7.0` | durable approval workflows |
| qdrant | StatefulSet + PVC | `qdrant/qdrant:v1.16.0` | vector store |
| redis | StatefulSet + PVC | `redis:7-alpine` | durable task/outcome inbox (AOF on) |
| agent | Deployment + Service | `agt-federated-rag:<div>` | FastAPI `api.main` on :8000 |
| worker | Deployment | `agt-federated-rag:<div>` | Temporal worker `workflow.worker` |

All carry readiness/liveness probes and resource requests/limits.

---

## Layout

```
k8s/
  base/                     # ONE division's full stack as a kustomize base
    namespace.yaml          # the division Namespace (renamed per overlay)
    configmap.yaml          # non-secret config (agent-config)
    secret.yaml             # TEMPLATE secret (placeholders — see "Secret wiring")
    postgres.yaml openfga.yaml keycloak.yaml temporal.yaml qdrant.yaml redis.yaml
    agent.yaml worker.yaml
    networkpolicy.yaml      # default-deny + intra-namespace + agent-federation
    kustomization.yaml
  llm-gateway/              # OPT-IN component: per-division LiteLLM gateway (see below)
  overlays/
    alpha/  beta/  gamma/  delta/  epsilon/   # one overlay per division (mirrors infra/divisions/*.yml)
  README.md
```

---

## Per-division isolation (NFR-2)

Two mechanisms, together:

1. **Namespace** — every object for a division lands in its own Namespace
   (`agt-div-alpha`, `agt-div-beta`, `agt-div-gamma`). Service DNS (`qdrant`,
   `openfga`, `redis`, `temporal`, `keycloak`, `postgres`) resolves **within the
   namespace only**, so the agent always reaches *its own* stores.

2. **NetworkPolicy** (`base/networkpolicy.yaml`) — three policies enforce the boundary:
   - `default-deny-ingress` — denies **all** inbound to every pod.
   - `allow-intra-namespace` — re-allows same-namespace pod-to-pod (the stack wiring).
   - `allow-agent-federation` — re-allows **only the agent pod, only on :8000**, from
     pods in any namespace labeled `app.kubernetes.io/part-of: agt-federated-rag`
     (the cross-division peer call: `/a2a/query`, `/tasks/<id>/callback`). The data
     stores get **no** cross-namespace exception — so one division can never reach
     another's OpenFGA / Qdrant / Redis, even though federation between agents is
     allowed. The DID/Ed25519 signature + mTLS still authenticate the peer at the app
     layer; the policy just narrows who can open the socket.

> **CNI requirement:** NetworkPolicy is enforced only by a CNI that implements it
> (Calico, Cilium, etc.). On a CNI without enforcement the objects are accepted but
> **inert** — the operator must confirm enforcement (e.g. a probe pod in another
> namespace cannot reach `openfga:8080`).

---

## Adding a division = a new overlay (no base edits)

This mirrors the Compose onboarding ethos (a new division is a new
`infra/divisions/<id>.yml` manifest). To add division `delta`:

1. Copy `overlays/gamma/` to `overlays/delta/`.
2. In its `kustomization.yaml` set `namespace: agt-div-delta`, the Namespace patch
   name/label to `delta`, the ConfigMap patch values (`DIVISION_ID`, `CLUSTER_ID`,
   `TRUSTED_PEERS`, `AGENT_CLIENT_ID`, `TEMPORAL_TASK_QUEUE`, `OIDC_*`), and the
   `images:` tag to `delta`.

To assign **governed tools** to a division, add `AGT_LOCAL_TOOLS` (CSV of capabilities it
serves) to its ConfigMap patch — see `overlays/gamma` (serves `tool.pii,tool.compliance`)
and `overlays/delta` (serves none, carries a `PEER_TOOL_MAP` routing those capabilities to
gamma). Full walkthrough: [`examples/cross-agent-pii/README.md`](../examples/cross-agent-pii/README.md).

The `base/` is never edited.

---

## Build the image

The agent + worker share one image built from `agt-federated-rag/Dockerfile`:

```bash
# from repo root
docker build -t agt-federated-rag:alpha agt-federated-rag/
# push to the registry your cluster pulls from (or load into a local cluster):
#   docker push <registry>/agt-federated-rag:alpha   # then set the overlay's images: newName
#   kind  load docker-image agt-federated-rag:alpha --name <cluster>
#   minikube image load agt-federated-rag:alpha
```

The overlay's `images:` entry sets the tag (default `agt-federated-rag:<division>`).
For a remote registry, also set `newName` to the registry path (or pin a digest).

---

## Secret wiring

`base/secret.yaml` is a **template with placeholder values — never real secrets**.
In production the real per-division secrets are the ones
`scripts/onboard_division.py` mints into `infra/generated/<id>/` (each division has
its OWN; none shared — NFR-4). Generate the live Secret at deploy time **without
editing any file**, then it overrides the template:

```bash
# OpenFGA store/model ids come from infra/generated/alpha/state.json after the store
# is created; the rest from infra/generated/alpha/secrets.json.
kubectl -n agt-div-alpha create secret generic agent-secrets \
  --from-literal=OPENAI_API_KEY="$NVIDIA_API_KEY" \
  --from-literal=EMBEDDING_API_KEY="$NVIDIA_API_KEY" \
  --from-literal=POSTGRES_USER=openfga \
  --from-literal=POSTGRES_PASSWORD="$(jq -r .postgres_password infra/generated/alpha/secrets.json)" \
  --from-literal=OPENFGA_API_TOKEN="$(jq -r .openfga_api_token infra/generated/alpha/secrets.json)" \
  --from-literal=OPENFGA_STORE_ID="$(jq -r .store_id infra/generated/alpha/state.json)" \
  --from-literal=OPENFGA_MODEL_ID="$(jq -r .model_id infra/generated/alpha/state.json)" \
  --from-literal=KEYCLOAK_ADMIN=admin \
  --from-literal=KEYCLOAK_ADMIN_PASSWORD="$(jq -r .keycloak_admin_password infra/generated/alpha/secrets.json)" \
  --from-literal=AGENT_CLIENT_SECRET="$(jq -r .agent_client_secret infra/generated/alpha/secrets.json)" \
  --from-literal=APPROVAL_HMAC_SECRET="$(jq -r .approval_hmac_secret infra/generated/alpha/secrets.json)"
```

The agent's Ed25519 **DID private key** (`infra/generated/<id>/agent_identity_<id>.json`)
should likewise be mounted as a Secret volume in production so the DID is stable across
pod restarts (set `AGENT_IDENTITY_PATH` to the mount path). For real secret management,
back this with Sealed Secrets / External Secrets / Vault rather than `kubectl create`.

---

## Apply a division

```bash
# render (offline, no cluster needed) — inspect what will be applied:
kubectl kustomize k8s/overlays/alpha

# apply to the current cluster context:
kubectl apply -k k8s/overlays/alpha
```

Repeat for `beta`, `gamma`. Each lands in its own namespace; bring up the live Secret
(above) before — or immediately after — applying so pods can start.

---

## Validate (offline)

These run **without a cluster** and prove the manifests render and are structurally
valid kustomize output:

```bash
kubectl kustomize k8s/overlays/alpha    # renders 22 objects, no error (same for beta/gamma)
```

A full **schema** dry-run (`kubectl apply --dry-run=client -k ...`) needs a reachable
API server (it fetches the API server's OpenAPI), so it requires a cluster context.
With any cluster (even a throwaway `kind`/`minikube`):

```bash
kubectl apply -k k8s/overlays/alpha --dry-run=server   # server-side validation, applies nothing
```

---

## If your host does TLS interception

**Host-specific — skip this on a normal network, or when you self-host the embedder
in-cluster.** If the host running the cluster has a TLS-intercepting AV/proxy (e.g.
Norton's "Web/Mail Shield Root", a corporate MITM proxy, Zscaler), the **Linux pod
can't make external HTTPS calls**: the proxy re-signs every TLS connection with its
own root CA, which is in the *host's* trust store but **not** in the container's. This
breaks the served embedder (and the LLM), and likewise breaks any in-pod model
download — so it isn't fixed by switching `EMBEDDING_PROVIDER` to `local`. The fix is
to inject the host's intercepting CA into the pod's trust store:

```bash
# 1) Export the host's full root store to a single PEM bundle (this includes the
#    interceptor's root). On Windows, e.g. export "Trusted Root Certification
#    Authorities" to host-ca-bundle.crt (Base-64 PEM). On Linux/mac, copy your
#    system bundle (e.g. /etc/ssl/certs/ca-certificates.crt) and append the proxy CA.

# 2) Create a ConfigMap from it. Use `create`, NOT `apply` — `apply` records a
#    last-applied annotation capped at 256KB and a full root store overflows it.
kubectl -n agt-div-gamma create configmap ca-bundle \
  --from-file=cert.pem=host-ca-bundle.crt

# 3) Find where the pod's Python/OpenSSL looks for the CA bundle:
#    python -c "import ssl; print(ssl.get_default_verify_paths().cafile)"
#    -> /usr/lib/ssl/cert.pem   (on the distro this image uses)

# 4) Mount the ConfigMap key read-only OVER that file via a subPath, on the agent
#    (and worker) Deployment — a subPath replaces the single file, not the directory:
#      volumes:        - name: ca-bundle
#                        configMap: { name: ca-bundle }
#      volumeMounts:   - name: ca-bundle
#                        mountPath: /usr/lib/ssl/cert.pem
#                        subPath: cert.pem
#                        readOnly: true
```

This is **host-specific and not baked into the base manifests** — a clean deploy on a
normal network needs none of it. The cleanest avoidance is to **self-host the embedding
(and LLM) endpoint in-cluster**, so no pod makes an external HTTPS call in the first place.

---

## Optional: per-division LLM gateway (`k8s/llm-gateway/` component)

Puts a LiteLLM Proxy between the division's agent and its model providers (per-division
virtual key, residency enforced by that key's model allowlist + alias, NIM → in-boundary
fallback). Prototype, proof and rules: [`examples/llm-gateway/README.md`](../examples/llm-gateway/README.md).
Off by default; the overlays are unchanged.

```bash
python scripts/bootstrap_k8s.py --divisions gamma --llm-gateway
```

With `--llm-gateway` (or `llm_gateway: true` in `infra/divisions/<id>.yml`) the bootstrap:
1. applies a generated kustomization (`infra/generated/<id>/k8s/`, gitignored) = the
   overlay unchanged + the component + an `agent-config` patch setting `OPENAI_API_BASE` and
   `EMBEDDING_API_BASE` to `http://llm-gateway.agt-div-<id>.svc.cluster.local:4000/v1`;
2. creates `llm-gateway-secrets` (master key + DB password minted into
   `infra/generated/<id>/secrets.json`, plus the NVIDIA key);
3. port-forwards the gateway and issues the agent's virtual key with the same code as the
   Compose onboarding (`onboard_division.provision_gateway_key`): residency `external` →
   NIM chat + embeddings + the in-boundary model; anything else → only
   `local/llama-3.1-8b-instruct`, with the app's model names aliased onto it;
4. ingests through the gateway, and puts the virtual key (not the NVIDIA key) in
   `agent-secrets` as `OPENAI_API_KEY` / `EMBEDDING_API_KEY`.

The component adds `deploy/llm-gateway` (image pinned by digest) + `svc/llm-gateway:4000`,
the `llm-gateway-env` ConfigMap (upstreams) and a ConfigMap generated from the **same**
`litellm-config.yaml` and `init-db.sh` the Compose stack mounts. The gateway gets its own
`litellm` database and an unprivileged role inside the division's existing Postgres
(init container), not a second Postgres. NetworkPolicy: only `app: agent` may reach :4000;
the component also narrows the base `allow-intra-namespace` policy to exclude the gateway
pod, because policies are additive.

To use it from an overlay by hand: add `components: [../../llm-gateway]`, plus the
`agent-config` patch from step 1 with that overlay's namespace. The component runs before
the overlay's namespace transformer, so it cannot work out the FQDN itself. Then create
the Secret and the key (header of `k8s/llm-gateway/kustomization.yaml`). Use the FQDN, not a
bare `llm-gateway`: residency=local treats a single-label host as external.

Operator settings and caveats:
- Set `LOCAL_LLM_BASE` in `llm-gateway-env` to your in-cluster vLLM/NIM. The default
  `http://local-llm.invalid/v1` never resolves, so the in-boundary model fails closed. Never
  leave it empty: LiteLLM would then send the "local" model to the public OpenAI API.
- A residency=local division has no in-boundary **embedding** model in this config, so its
  key refuses API-mode embeddings. Add a `local/` embedding model group before enabling one.
- The gateway pod calls NIM over HTTPS, so on a TLS-intercepting host it needs the CA
  mount described above, the same as the agent.

---

## What still needs a live cluster (operator deploy step)

- **Applying** to a real cluster, and confirming the **CNI enforces NetworkPolicy**.
- **HA / production tuning of the stateful stores** — the bases run single-replica
  `start-dev`-style stores (matching Compose) for parity. Production wants: Postgres
  HA (or a managed DB) behind OpenFGA, Keycloak `start` (not `start-dev`) with an
  external DB + hostname config, a Temporal server backed by a real datastore, and a
  Qdrant cluster. These are deployment-environment choices, intentionally left to the
  operator.
- **Ingress / edge mTLS** — the Compose path has an nginx `edge` enforcing route-based
  mutual TLS on the peer routes (`/a2a/*`, `/tasks/*/callback`). The k8s equivalent is
  an Ingress/Gateway with mTLS on those routes; the agent still verifies the
  DID/Ed25519 signature regardless. Wire to your cluster's ingress controller.
- **StorageClass / PVC sizing** — the PVCs use the cluster default StorageClass;
  size and class are environment-specific.
