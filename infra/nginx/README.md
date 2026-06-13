# Production edge — route-based mTLS per division

The recommended production deployment puts an **nginx edge** in front of each division's
agent. One TLS ingress carries both trust planes, separated by route:

| Plane | Routes | Auth |
|---|---|---|
| **User** | `/query`, `/approvals/*`, `/tasks/<id>/result`, UI, `/health`, `/metrics` | TLS + the user's **JWT** (no client cert — browser-friendly) |
| **Peer** | `/a2a/*`, `/tasks/<id>/callback` | **Mutual TLS** — a client cert issued by the **federation CA** is required; no/invalid cert is rejected at the edge |

This is what a single uvicorn port cannot do (it can't apply different client-cert policy
per route). Config: `division-edge.conf.template` (`ssl_verify_client optional` + a
per-peer-route `$ssl_client_verify = SUCCESS` check). Defence-in-depth: the agent **also**
verifies the DID/Ed25519 signature on every peer call, so mTLS is an added transport layer,
not the only control.

## Why nginx (vs. a service mesh)

A reverse proxy is portable (plain Docker Compose *and* Kubernetes), explicit/auditable, and
is the edge you'd run in production anyway (TLS termination, rate limiting, WAF hook). A
service mesh (Istio/Linkerd) is the K8s-native alternative; the design is swappable — a
mesh-native customer drops nginx and the agent's DID layer stays the identity source of
truth, with **zero agent code change**.

## Enable it

```powershell
# 1. Issue the federation CA + per-division certs (CN/SAN = division id, SAN incl. localhost)
.venv\Scripts\python.exe scripts\issue_division_certs.py alpha beta

# 2. Bring up the division with the containerized profile (agent + worker + edge)
docker compose -p agt-div-alpha --env-file infra\generated\alpha\div-alpha.env `
  -f infra\division-stack.template.yml --profile containerized up -d

# 3. Point federation at the peer EDGE (https) instead of the agent (http)
#    set PEER_AGENT_URL=https://<peer-host>:<DIV_EDGE_PORT> ; the agent presents its
#    client cert automatically once TLS_CERT_FILE/TLS_KEY_FILE/TLS_CA_FILE are set
#    (peer_tls_context activates on cert presence — independent of require_mtls).
```

## Proven (live)

Against an nginx edge fronting a division agent:
- user plane `/health` **without** a client cert → **200** (browser path works);
- peer `/a2a/query` with **no** client cert → **rejected at the edge** (never reaches the agent);
- peer `/a2a/query` with a **rogue-CA** client cert → **rejected at the edge**;
- peer `/a2a/query` with a **valid federation** client cert → **passes the edge to the agent**
  (which then enforces the DID signature).
- The cert chain is independently verified (`beta` signed by the federation CA) and the
  in-process TLS handshake tests pass (`tests/test_transport.py`).

## Host caveat: TLS-intercepting AV / corporate proxy

On a host running TLS interception (e.g. **Norton Web/Mail Shield**, or a corporate MITM
proxy), the server cert is **re-signed on the wire** with the AV's own root, so a client
pinning the federation CA sees that root instead and server verification fails locally
("unable to get local issuer"). This is a host artifact, not a config/design issue — the
client-cert mTLS gate above still works through it, and on a clean production host (or with
the AV root excluded for these ports) federation-CA server-pinning verifies normally.
