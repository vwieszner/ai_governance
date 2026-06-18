# Kubernetes deployment (kustomize) — per-division isolated stacks

This `k8s/` tree is a **production-shaped Kubernetes deployment of the current
per-division isolated stack** (PROJECT_STATUS.md decision D-3, NFR-2). It is the
Kubernetes expression of `infra/division-stack.template.yml` (the Docker Compose
source of truth): the same services, the **same pinned image versions**, the same
per-division physical isolation.

> **This complements — it does NOT replace — the Compose path.** Local dev and the
> demo still run on Compose via `scripts/onboard_division.py`. Kubernetes is for a
> real multi-node / multi-cloud deployment. Nothing here touches `infra/`, `scripts/`,
> or the application code.

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
  overlays/
    alpha/  beta/  gamma/   # one overlay per division (mirrors infra/divisions/*.yml)
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
