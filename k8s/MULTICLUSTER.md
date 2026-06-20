# Deploy anywhere + federate across clusters

This is the template's **production-shaped topology**: each division is its **own Kubernetes
cluster** (its own control plane, its own physically-isolated stack), and divisions federate
over **routable network URLs + DIDs** — the multi-node / multi-cloud deployment the template
targets. It is the same governance + federation you already have; only the *deployment boundary*
moves from "namespace on one cluster" to "a whole cluster per division."

> **Why a cluster per division and not namespaces on one cluster?**
> The federation primitives — each division has its own Ed25519 DID, signs every inter-agent
> message, forwards the user's identity as **signed claims (never a token)**, shares **no** trust
> store, and **re-authorizes the user against its own OpenFGA** — exist precisely because
> divisions do **not** share a control plane. Separate departments / subsidiaries / jurisdictions
> are separate security and compliance boundaries; in the real world they are separate clusters
> (often separate clouds/accounts/regions). One cluster with namespaces is the **dev rig** (cheap,
> one host, proves the logic); separate clusters is the **product**. See `README.md`
> ("physically-isolated stack… no shared point") and this directory's `README.md`
> ("Kubernetes is for a real multi-node / multi-cloud deployment").

The agent already addresses peers by **URL + DID** (`agent_url` + `public_jwk` in the peer trust
map). Moving to multi-cluster therefore changes **deployment + networking only** — the
agent/federation code is unchanged. The single-cluster path uses the in-cluster Service DNS
(`agent.agt-div-<peer>.svc.cluster.local:8000`); multi-cluster uses each agent's **externally
routable** address instead.

---

## 1. Local quickstart — N clusters on one host (kind)

`scripts/multicluster.py` stands up the real multi-cluster model locally: **one kind cluster per
division**, federated over routable URLs + DIDs. It orchestrates the existing, tested
`scripts/bootstrap_k8s.py` (build → per-division bring-up → cross-cluster federate) — it does not
reimplement provisioning or federation.

```bash
# create one kind cluster per division, deploy each division into its own cluster, federate across them
python scripts/multicluster.py up     --divisions gamma,delta

# show each cluster + its routable agent URL
python scripts/multicluster.py status  --divisions gamma,delta

# keep the cross-cluster relay up (the host is the L4 router between clusters — see below)
python scripts/multicluster.py relay   --divisions gamma,delta     # leave running in a terminal

# PROVE it: an agent in one cluster delegates a tool it lacks to the peer that owns it — across clusters
python scripts/multicluster.py prove   --divisions gamma,delta

# tear the clusters down
python scripts/multicluster.py down    --divisions gamma,delta
```

**Verified live** (gamma + delta, each in its own kind cluster `agt-gamma` / `agt-delta`,
federated over routable URLs + DIDs). `prove` calls a capability each division does **not**
serve, so it must delegate to the peer that owns it — in the other cluster:

```
gamma (cluster agt-gamma)  --tool.risk-->  delta (cluster agt-delta)   status=completed  source=peer
delta (cluster agt-delta)  --tool.pii -->  gamma (cluster agt-gamma)   status=completed  source=peer
```
`source=peer` means it was **not** run locally; the receiving agent's log confirms it:
`solve_with_tools_delegated capability=tool.pii peer_did=did:mesh:c5839…(gamma) status=completed`
— the delegated user is re-authorized against the receiver's own OpenFGA before the tool runs.

Mapping: division `d` → kind cluster `agt-<d>` (context `kind-agt-<d>`), namespace `agt-div-<d>`.
`gamma` (Security/Legal) serves `tool.pii,tool.compliance`; `delta` (Risk/Data-Gov) serves
`tool.risk,tool.classify` — so each must **delegate the other's tools across the cluster
boundary**, both ways.

**How the local clusters reach each other — the host is the L4 router.** Separate kind clusters
are network-isolated: their pod/Service networks do **not** traverse the Docker bridge (kindnet's
iptables service routing is inert across clusters — a NodePort/ClusterIP from another cluster's
pod does not connect; observable on Docker Desktop, where only same-cluster pod-to-pod, real node
sockets, and pod→host work). Two paths **do** work reliably: every pod can reach the **host**
(`host.docker.internal`), and the host can reach every cluster (`kubectl port-forward`). So
`multicluster.py relay` runs one host port-forward per division agent — bound on `0.0.0.0` at a
stable host port (`port_base + 30000`) — and each division's peer trust map points at
`http://host.docker.internal:<relay-port>`. The host plays the role a cloud LoadBalancer plays in
production. Keep `relay` running while you use the mesh (it auto-restarts the flaky forwards). In
a real multi-cloud deploy this URL is the agent's LoadBalancer/Ingress hostname instead —
identical wiring, no relay needed (§3.3).

---

## 2. What "federate across clusters" actually wires

For each division `d` in its own cluster, `bootstrap_k8s.federate_multicluster` (reusing the same
`DivisionFacts` / `compute_peer_tool_map` / `_apply_cross_grants` helpers as the single-cluster
path) sets, **in d's own kube-context**:

| Config | Value | Purpose |
|---|---|---|
| `PEER_TRUST_MAP` | `{peer_DID: {issuer, public_jwk, agent_url, division_id}}` for every peer | The data-path trust anchor. A signer is accepted **only** if its DID is a key here; the asserted user's issuer is bound **per-DID** (a peer can only assert its *own* users). `agent_url` is the peer's **routable** address. |
| `agent-identity` Secret | the division's stable Ed25519 DID key, mounted at `/identity` | So the running agent's DID matches the trust map (not a pod-ephemeral key). |
| `TRUSTED_ISSUERS` | union of peers' Keycloak issuers | Accept a verifiable user assertion minted by any peer, then re-authorize locally. |
| `AGT_LOCAL_TOOLS` | the capabilities this division serves | What it runs locally vs. delegates. |
| `PEER_TOOL_MAP` | `{capability: provider_peer_DID}` for every capability it lacks | Broker-less tool routing — resolved against `PEER_TRUST_MAP` at call time. |
| cross-grants | applied to **this** division's OpenFGA | Pre-authorize named external (peer-division) users on specific docs (FR-3.7). |

The cross-cluster call itself is unchanged from same-cluster federation: kill-switch → Ed25519
verify + replay guard → trust gate → recipient-bound assertion (`aud` = the receiver's DID, short
TTL) → **default-deny policy on the delegated user** → governed execution → **DID-signed** reply
the caller verifies. Nothing crosses the cluster boundary except that one signed call.

---

## 3. Deploy a division to ANY cluster (EKS / GKE / AKS / on-prem)

The local kind path and a real cloud cluster differ only in (a) where the image comes from and
(b) how the agent gets a routable address. The per-division stack, provisioning, and federation
are identical.

### 3.1 Build + publish the image to a registry your cluster can pull

```bash
docker build -t <registry>/agt-federated-rag:<div> agt-federated-rag/
docker push     <registry>/agt-federated-rag:<div>
# point the overlay at it (instead of a local image):
#   k8s/overlays/<div>/kustomization.yaml -> images: [{name: agt-federated-rag, newName: <registry>/agt-federated-rag, newTag: <div>}]
```

(For kind/minikube you load the image instead of pushing — `kind load docker-image …`. That's
what `bootstrap_k8s.py` does locally.)

### 3.2 Apply the division + its secrets, provision it

```bash
kubectl --context <cloud-ctx> apply -k k8s/overlays/<div>          # the full isolated stack
# create the live agent-secrets Secret (see k8s/README.md "Secret wiring"), then provision:
#   OpenFGA store/model + Keycloak realm/users/roles + doc ingest + DID
```

On a normal cloud cluster (no TLS-intercepting proxy) the in-pod served embedder reaches your
embeddings endpoint directly — none of the host-CA steps in `k8s/README.md` are needed. For
data-residency, self-host the embedding + LLM endpoints in-cluster and point `EMBEDDING_API_BASE`
/ `OPENAI_API_BASE` at them, so no inference text leaves the cluster.

### 3.3 Give the agent a routable address (the one new requirement)

A peer in another cluster must be able to open a TCP connection to this agent. Pick whichever
fits your environment — they all just produce a URL you put in the peer trust map:

| Exposure | How | Peer `agent_url` |
|---|---|---|
| **LoadBalancer** (cloud) | `kubectl expose deploy/agent --type=LoadBalancer --name agent-ext --port 8000` (or a Service manifest) | `https://<lb-hostname>:8000` |
| **Ingress / Gateway** (recommended for prod) | an Ingress/Gateway routing `/a2a/*` + `/tasks/*/callback` to `agent:8000`, with **mTLS** on those routes | `https://agent.<div>.<your-domain>` |
| **NodePort** (kind / bare-metal) | the `agent-ext` NodePort Service `multicluster.py` creates | `http://<node-ip>:30800` |

For production, terminate **mutual TLS** on the peer routes (the Compose path's nginx edge is the
reference; on k8s use your Ingress/Gateway's mTLS). The agent still verifies the DID/Ed25519
signature regardless of the transport, so mTLS is defense-in-depth on top of the app-layer trust.

### 3.4 Connect it into the federation

Two divisions in two clusters federate by exchanging four facts each and writing them into the
**other** side's config. With the script (local kind) this is automatic; manually (any clusters):

For each pair (A, B), give A this about B (and vice-versa):
1. **B's DID** (`infra/generated/B/did.json` → `did`)
2. **B's public JWK** (`infra/generated/B/did.json` → `jwk`)
3. **B's Keycloak issuer** (`http://…/realms/rag` — or your real IdP issuer URL)
4. **B's routable agent URL** (from §3.3)

Then on **A's** cluster:
```bash
# add B to A's PEER_TRUST_MAP + TRUSTED_ISSUERS + (if A lacks a capability B serves) PEER_TOOL_MAP
kubectl --context <A-ctx> -n agt-div-A patch configmap agent-config --type=merge -p '{"data":{
  "PEER_TRUST_MAP": "{\"<B-DID>\":{\"issuer\":\"<B-issuer>\",\"public_jwk\":<B-jwk>,\"agent_url\":\"<B-url>\",\"division_id\":\"B\"}}",
  "TRUSTED_ISSUERS": "<B-issuer>",
  "PEER_TOOL_MAP": "{\"tool.risk\":\"<B-DID>\"}"
}}'
# apply A's cross-grants to A's own OpenFGA (pre-authorize named B-users on A's docs), then:
kubectl --context <A-ctx> -n agt-div-A rollout restart deploy/agent deploy/worker
```

`bootstrap_k8s.federate_multicluster({"A": "<A-ctx>", "B": "<B-ctx>"})` does exactly this for any
set of contexts — point it at your real cloud contexts instead of the local kind ones and it
wires the same trust map with your routable URLs.

---

## 4. Networking & security across the cluster boundary

- **Routability.** Each agent needs an address reachable from its peers' pods (§3.3). Cross-cluster
  egress from a pod is normal outbound traffic; only the *peer agent* endpoints need to be
  reachable, nothing else in the stack is ever exposed.
- **NetworkPolicy on an enforcing CNI (Calico/Cilium).** The base `allow-agent-federation` policy
  admits peers by **namespace label**, which only matches *in-cluster* peers. For cross-cluster
  peers the traffic arrives from outside, so add an `ipBlock` for the peer clusters' node/LB
  egress CIDRs to that policy (only :8000 on the agent pod), or front the agent with an
  Ingress/Gateway whose ingress you allow. On kindnet (local) NetworkPolicy is inert, so the local
  quickstart needs none of this.
- **Trust is app-layer, not network.** Even with a wide-open network, a peer call is rejected
  unless: the Ed25519 signature verifies against a DID **in the trust map**, the replay guard
  passes, the user assertion is recipient-bound (`aud` = this DID) and unexpired, and the
  delegated user passes **this** division's default-deny policy + OpenFGA. A compromised network
  path cannot bypass any of that.
- **No shared anything.** No shared database, no shared OpenFGA, no shared secrets, no shared DID.
  Lose one cluster and the others keep serving (resilience / NFR-2) — there is no shared point.

---

## 5. Production checklist (beyond the local quickstart)

- **HA stateful stores** — the bases run single-replica `start-dev`-style stores for parity with
  Compose. Production wants Postgres HA (or managed) behind OpenFGA, Keycloak `start` with an
  external DB + hostname config, a real Temporal datastore, and a Qdrant cluster.
- **Real DNS + TLS** — give each agent a stable hostname (§3.3) and terminate mTLS on the peer
  routes; put the routable hostnames (not node IPs) in the trust map.
- **Secrets backend** — back the per-division Secrets with Sealed Secrets / External Secrets /
  Vault rather than `kubectl create secret` (see `k8s/README.md`).
- **Audit anchoring + CRL** — set `AUDIT_ANCHOR_URL` (remote append-only sink) and the mTLS
  `TLS_CRL_FILE` so the tamper-evidence and revocation gates are live (they warn at startup if not).
- **DID key custody** — mount each division's `agent_identity_<div>.json` from a managed secret so
  the DID is stable across pod restarts (`AGENT_IDENTITY_PATH`).

---

## 6. Host-specific: TLS-interception (Norton/Zscaler/corporate MITM)

The **deterministic governed tools** (`/solve` → `tool.pii/compliance/risk/classify/fincheck`)
are pure rule-based logic — they make **no external calls**, so cross-cluster tool delegation
works with no special networking. The **`/query` RAG path** needs the pod to reach the
embeddings + LLM endpoints; on a host whose AV/proxy intercepts TLS, mount the host CA bundle into
the agent pod (see `k8s/README.md` → "If your host does TLS interception") or self-host the
endpoints in-cluster. This is host-specific and not baked into the manifests.
