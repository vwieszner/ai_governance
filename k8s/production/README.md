# Production hardening: autoscaling, disruption budgets, and HA stores

A composable kustomize **component**. Layer it into a division overlay:

```yaml
# k8s/overlays/<div>/kustomization.yaml
components:
  - ../../production
```

It adds, for the **stateless** tiers:
- **HPA** (`hpa.yaml`) — agent 2→10, worker 2→6, CPU-target 70% (needs metrics-server).
- **PDB** (`pdb.yaml`) — `maxUnavailable: 1` so a node drain / rolling upgrade never takes the
  whole tier down.

These are safe because the agent and worker hold **no local state**: the replay-nonce store and
rate limiter are Redis-backed (see the defect fixes), so N replicas behind the Service share one
consistent view. The base runs them single-replica for parity with Compose; this component makes
them HA.

## Stateful stores — HA is a substitution, not a replica bump

**Do not** naively set `replicas > 1` on the base StatefulSets (postgres, openfga, keycloak,
temporal, qdrant, redis) — they run single-instance `start-dev`/standalone modes and would
corrupt or split-brain. Production HA is a per-store substitution, left to the operator:

| Store | Production HA path |
|---|---|
| **Postgres** (OpenFGA + Keycloak + Temporal datastore) | a managed DB (RDS/Cloud SQL) or an operator (CloudNativePG/Zalando) with replication + failover |
| **OpenFGA** | already stateless — scale its Deployment + point it at HA Postgres |
| **Keycloak** | run `start` (not `start-dev`) with an external HA DB + clustered cache (Infinispan), 2+ replicas |
| **Temporal** | the Temporal server/services backed by a real datastore (Cassandra/HA Postgres) |
| **Qdrant** | Qdrant cluster mode (sharding + replication) |
| **Redis** | managed Redis or Redis Sentinel/Cluster — the durable approval/outcome inbox + nonce/rate state live here |

Once a store runs HA (≥2 replicas), add a PDB for it too (the same pattern in `pdb.yaml`).

## Verify

```bash
kubectl apply -k k8s/overlays/<div>           # with the component referenced
kubectl -n agt-div-<div> get hpa,pdb
```
Render offline: `kubectl kustomize k8s/overlays/<div>`.
