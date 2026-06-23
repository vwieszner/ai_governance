# Observability on Kubernetes

Deploys Prometheus into a `monitoring` namespace and **auto-discovers every division agent** by
its `prometheus.io/scrape` annotation (set in `k8s/base/agent.yaml`) — no static target list (the
Compose `infra/observability/prometheus.yml` hard-codes `localhost` ports, which don't exist in
k8s). The governance alert rules (`AuthFailureSpike`, `AuthorizationBypassAttempt`,
`AuditWriteError`, `KeyRotationFailing`, `DivisionAgentDown`) are loaded so they fire in-cluster.

```bash
# build is not needed (uses the upstream prom/prometheus image); on a local kind cluster load it:
docker pull prom/prometheus:v2.54.1
kind load docker-image prom/prometheus:v2.54.1 --name <cluster>

kubectl apply -k k8s/observability
kubectl -n monitoring port-forward svc/prometheus 9591:9090   # http://localhost:9591
```

**Verified live** on the `agt` kind cluster: Prometheus discovered all 5 division agents
(alpha…epsilon) and scraped `/metrics` — `up{job="agt-divisions"}` = 1 for every division, each
carrying its `division` label.

Notes:
- The `monitoring` namespace carries the `app.kubernetes.io/part-of: agt-federated-rag` label so
  the agents' `allow-agent-federation` NetworkPolicy admits Prometheus to `:8000/metrics` on an
  enforcing CNI (inert on kindnet).
- `alert.rules.yml` here mirrors `infra/observability/alert.rules.yml` (kustomize can't read files
  above the overlay root) — keep the two in sync.
- Production: add Grafana (the dashboard in `infra/observability/grafana-dashboard.json`),
  Alertmanager for routing, and persistent storage for the TSDB (the overlay uses `emptyDir`).
- Gate `/metrics` with `METRICS_TOKEN` in production and add the bearer to the scrape config.
