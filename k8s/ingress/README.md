# Agent edge — Ingress + route-based mTLS (production replacement for the host-relay)

The local multi-cluster setup uses the **host as an L4 relay** (`scripts/multicluster.py relay`)
because separate kind clusters don't route to each other. In a real multi-cloud deployment you
replace that with a proper edge per division — this overlay is that edge, the k8s equivalent of
the Compose nginx edge.

Two planes, split across two Ingresses (nginx mTLS annotations are per-Ingress):

| Plane | Host | Routes | Auth |
|---|---|---|---|
| **Peer** | `peer.<div>.<domain>` | `/a2a/*`, `/tasks/*/callback` | **client-cert mTLS** + (app-layer) DID/Ed25519 signature |
| **User** | `agent.<div>.<domain>` | `/query`, `/solve`, `/inbox`, `/admin/*` | server TLS + user JWT |

The **peer hostname is what goes in the federation trust map** (`agent_url` =
`https://peer.<div>.<domain>`) — identical wiring to the local relay, just a routable URL instead
of `host.docker.internal:<port>`. `bootstrap_k8s.federate_multicluster` accepts any routable URL,
so point it at these hostnames for a real cross-cloud federation.

## Prerequisites & deploy

```bash
# 1) ingress-nginx + cert-manager in the cluster
helm install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace
helm install cert-manager jetstack/cert-manager -n cert-manager --create-namespace --set crds.enabled=true

# 2) a ClusterIssuer named `agt-issuer` (ACME for public hosts, or an internal CA), and a
#    `peer-ca` Secret (ca.crt) in each division namespace holding the CA that signs peer client
#    certs (the per-division CA from scripts/issue_division_certs.py).

# 3) set DIV/DOMAIN + namespace, then:
kubectl apply -k k8s/ingress      # into agt-div-<div>
```

The agent **still verifies the DID/Ed25519 signature** on every peer call regardless of mTLS, so
the edge is defense-in-depth on the transport, not the trust root. Wire `TLS_CRL_FILE` / the
ClusterIssuer's CRL/OCSP for certificate revocation (the open OCSP item).

> Placeholders (`DIV`, `DOMAIN`, `agt-div-DIV`) are literal — replace per division (kustomize
> `replacements`, `sed`, or a small overlay patch). Kept as a template so the overlay carries no
> environment-specific hostnames.
