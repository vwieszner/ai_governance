# Multi-department governance mesh — a template you extend with tools, connectors, and departments

This is the **template at the heart of the project**: a set of **self-sufficient
departments** that each own their **data** *and* their **tools**, and that **collaborate
both ways** under governance — DID-signed transport, recipient-bound user assertions,
default-deny policy, per-chunk OpenFGA authorization, and the §4.2 no-credential boundary.

It is built to be **extended**. Three extension points, each a config edit (no
orchestration code): **add a tool**, **add a retrieval connector**, **add a department**.

---

## The model: every department is self-sufficient, collaboration is two-way

A department (a "division") is a **physically isolated stack** — its **own** Qdrant +
OpenFGA + Keycloak realm + Temporal + Redis + DID — and it owns a **distinct** set of
governed tools. When it needs a capability it does not own, it **delegates** the governed
tool call to the department that does, over the DID-signed `/a2a/tool` channel. Delegation
is **bidirectional**: each department both serves tools to peers and consumes peers' tools.

The three departments wired on the `kind-agt` cluster — each owns a **distinct** tool and
delegates the ones it lacks, so the routing is a full **N-way mesh**:

| Department | Role | Owns (data) | Serves (`AGT_LOCAL_TOOLS`) | Delegates out (`PEER_TOOL_MAP`) |
|---|---|---|---|---|
| **gamma** | Security / Legal | its own Qdrant + OpenFGA | `tool.pii`, `tool.compliance` | `tool.risk`/`tool.classify`→delta, `tool.fincheck`→epsilon |
| **delta** | Risk / Data-Gov | its own Qdrant + OpenFGA | `tool.risk`, `tool.classify` | `tool.pii`/`tool.compliance`→gamma, `tool.fincheck`→epsilon |
| **epsilon** | Finance | its own Qdrant + OpenFGA | `tool.fincheck` | `tool.pii`/`tool.compliance`→gamma, `tool.risk`/`tool.classify`→delta |

So **delta uses gamma's PII screen**, **gamma uses delta's risk classifier**, and **both use
epsilon's financial check** — real N-way collaboration, each call under the callee's
governance, each department keeping its own data. Adding a department extends the mesh
automatically (see extension point 3).

The governed tools (all real, deterministic, dependency-light — in
`agt-federated-rag/tools/local_tools.py`):

| Capability | What it does | Arguments |
|---|---|---|
| `tool.pii` | PII/DLP screen: detect + redact email, phone, SSN, Luhn-valid card, IBAN, IPv4 (raw value never leaves) | `{"text": str}` |
| `tool.compliance` | EU AI Act / GDPR obligation lookup by topic | `{"topic": str}` |
| `tool.risk` | EU AI Act risk-tier classifier (unacceptable/high/limited/minimal) + obligations | `{"description": str}` |
| `tool.classify` | Data classification / sensitivity labelling + handling guidance | `{"text": str}` |
| `tool.fincheck` | Finance / AML transaction screen: sanctions watchlist + disclosure threshold + risk tier (Finance department) | `{"amount": number, "currency": str, "counterparty": str}` |

### The three wiring knobs

1. **`AGT_LOCAL_TOOLS`** — CSV of the capabilities a department **serves** locally (full
   ids like `tool.pii` or short names like `pii`). Unset → serves **all** tools (back-compat).
2. **`PEER_TOOL_MAP`** — JSON `{capability: provider_DID}`. For a capability a department
   does **not** serve, this names **which trusted peer DID** serves it.
3. **`PEER_TRUST_MAP`** — the data-path trust anchor (wired by federation). `PEER_TOOL_MAP`
   only names a DID; the peer's **`agent_url` + division always come from `PEER_TRUST_MAP`**
   keyed on that DID. So a route can only point at an **already-trusted** partner — a DID not
   in the trust anchor resolves to nothing, never a fabricated peer. (Control plane = "which
   capability → which DID"; data plane = "where that DID lives and whether we'll talk to it".)

Because routing is **configured** (not broker-discovered), the same wiring runs on
Kubernetes (overlay ConfigMaps) and Compose (per-division `.env`), with **no extra broker
service**. The `allow-agent-federation` NetworkPolicy already permits the agent→agent call
on `:8000` across namespaces.

---

## Run it on Kubernetes (kind/minikube)

Prereqs: a cluster context (`kind create cluster --name agt`), the agent image built +
loaded, and `./.env` with `NVIDIA_API_KEY`. From the repo root:

```bash
# Bring up ALL THREE departments AND wire the whole cross-department tool mesh in one shot.
# After the DIDs exist, --federate patches each department's ConfigMap with PEER_TRUST_MAP
# + an auto-derived PEER_TOOL_MAP (every capability a department lacks -> the peer DID that
# serves it) + AGT_LOCAL_TOOLS from the manifests, then restarts the agents.
python scripts/bootstrap_k8s.py --divisions gamma,delta,epsilon --federate --context kind-agt
```

Confirm the N-way mesh landed (each department serves its own tools, routes the rest):

```bash
kubectl -n agt-div-gamma   get configmap agent-config -o jsonpath='{.data.AGT_LOCAL_TOOLS}'  # tool.pii,tool.compliance
kubectl -n agt-div-gamma   get configmap agent-config -o jsonpath='{.data.PEER_TOOL_MAP}'    # {"tool.risk":"<delta>","tool.classify":"<delta>","tool.fincheck":"<epsilon>"}
kubectl -n agt-div-delta   get configmap agent-config -o jsonpath='{.data.AGT_LOCAL_TOOLS}'  # tool.risk,tool.classify
kubectl -n agt-div-delta   get configmap agent-config -o jsonpath='{.data.PEER_TOOL_MAP}'    # {"tool.pii":"<gamma>","tool.compliance":"<gamma>","tool.fincheck":"<epsilon>"}
kubectl -n agt-div-epsilon get configmap agent-config -o jsonpath='{.data.AGT_LOCAL_TOOLS}'  # tool.fincheck
kubectl -n agt-div-epsilon get configmap agent-config -o jsonpath='{.data.PEER_TOOL_MAP}'    # {"tool.pii":"<gamma>","tool.compliance":"<gamma>","tool.risk":"<delta>","tool.classify":"<delta>"}
```

### Drive `POST /solve` — any direction

`/solve` is the **user trigger** for the governed tool path. It needs a Bearer JWT (same
validation as `/query`); mint one from the **calling** department's Keycloak.

```bash
# helper: mint a user token from a department's realm (direct access grant, public rag-ui client)
mint_token() {  # $1 = division id, $2 = keycloak local port
  local pw; pw=$(jq -r .seed_user_password "infra/generated/$1/secrets.json")
  curl -s "http://localhost:$2/realms/rag/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=rag-ui -d username=alice -d "password=$pw" | jq -r .access_token
}

# A) delta delegates PII screening UP to gamma -------------------------------------------
kubectl -n agt-div-delta port-forward svc/agent    9300:8000 &
kubectl -n agt-div-delta port-forward svc/keycloak 9302:8080 &
DELTA_TOKEN=$(mint_token delta 9302)
curl -s http://localhost:9300/solve -H "Authorization: Bearer $DELTA_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"capability":"tool.pii","arguments":{"text":"Email john@acme.com; SSN 123-45-6789."}}' | jq
#   -> {"status":"completed","source":"peer","capability":"tool.pii","peer_did":"did:mesh:<gamma>","result":{...redacted...}}

# B) gamma delegates RISK classification ACROSS to delta ---------------------------------
kubectl -n agt-div-gamma port-forward svc/agent    9200:8000 &
kubectl -n agt-div-gamma port-forward svc/keycloak 9202:8080 &
GAMMA_TOKEN=$(mint_token gamma 9202)
curl -s http://localhost:9200/solve -H "Authorization: Bearer $GAMMA_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"capability":"tool.risk","arguments":{"description":"Real-time CV screening for hiring decisions."}}' | jq
#   -> {"status":"completed","source":"peer","capability":"tool.risk","peer_did":"did:mesh:<delta>","result":{"tier":"high",...}}

# C) delta delegates a FINANCE/AML check to epsilon (the third department) ----------------
curl -s http://localhost:9300/solve -H "Authorization: Bearer $DELTA_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"capability":"tool.fincheck","arguments":{"amount":50000,"currency":"USD","counterparty":"Acme Holdings"}}' | jq
#   -> {"status":"completed","source":"peer","capability":"tool.fincheck","peer_did":"did:mesh:<epsilon>","result":{"disclosure_required":true,"risk":"medium",...}}
# (epsilon serves tool.fincheck LOCALLY; the same call against epsilon's own agent returns source:"local".)
```

`source:"peer"` + `peer_did` proves the cross-department delegation; a tool the department
**owns** instead returns `source:"local"`. The raw PII value never appears in any result or
log — only a last-4 mask + redacted text, and that invariant holds across the delegation.

**Routed form** (no explicit capability — the deterministic router maps free text):

```bash
curl -s http://localhost:9300/solve -H "Authorization: Bearer $DELTA_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"problem":"Screen this for PII before logging: bob@acme.com, card 4111 1111 1111 1111."}' | jq
```

> **Note:** the end-to-end `/solve` calls require an agent image that includes the `/solve`
> endpoint + the broker-less routing. If a running pod's `/openapi.json` shows only
> `/a2a/query`, rebuild the image (`docker build -t agt-federated-rag:<div> agt-federated-rag/`,
> `kind load docker-image agt-federated-rag:<div> --name agt`) and roll the agent. The
> ConfigMap wiring above is independent and verifiable without a rebuild.

---

## Extension point 1 — ADD A TOOL

Make a new governed capability and assign it. ~15 lines, then config.

1. **Register the tool** in `agt-federated-rag/tools/local_tools.py` — a deterministic,
   dependency-light function plus a `TOOLS` entry advertising **one** capability:

   ```python
   def translate(arguments: dict) -> dict:
       text = arguments.get("text")
       if not isinstance(text, str):
           raise ValueError("'text' must be a string")
       ...  # pure compute; no network, no filesystem
       return {"translated": ...}

   TOOLS = {
       "pii-scan":          {"capability": "tool.pii",        "scan":     pii_scan},
       "compliance-lookup": {"capability": "tool.compliance", "lookup":   compliance_lookup},
       "risk-score":        {"capability": "tool.risk",       "assess":   risk_assess},
       "data-classify":     {"capability": "tool.classify",   "classify": classify},
       "translate":         {"capability": "tool.translate",  "run":      translate},   # <-- new
   }
   ```

   It now runs through all three governance gates automatically (policy default-deny →
   gateway → no-credential boundary), and a department that serves it auto-advertises it.

2. **Assign it to a department** — add the capability to that department's served set:
   - Manifest (Compose parity): `infra/divisions/<dept>.yml` → `local_tools: [tool.translate, ...]`
   - k8s overlay: `k8s/overlays/<dept>/kustomization.yaml` ConfigMap patch →
     `AGT_LOCAL_TOOLS: tool.translate,...`

3. **Let other departments use it** — add `<dept>` to each consumer's `trusted_peers` and
   re-run **`bootstrap_k8s.py --federate`** (k8s) / **`scripts/federate_divisions.py`**
   (Compose). Federation **auto-computes** each consumer's `PEER_TOOL_MAP` — for every
   capability it lacks but a trusted peer serves, it routes to that peer's DID
   (`federate_divisions.compute_peer_tool_map`). Or set it explicitly in the consumer
   overlay: `PEER_TOOL_MAP: '{"tool.translate":"<provider_DID>"}'` (DID is in
   `infra/generated/<provider>/did.json`).

No orchestration code changes. `/solve` runs it locally if the department serves it,
otherwise resolves `PEER_TOOL_MAP` → a trusted DID → `PEER_TRUST_MAP` and delegates.

---

## Extension point 2 — ADD A RETRIEVAL CONNECTOR (retrieval-as-a-service)

A department keeps its own Qdrant, but can **fan out** retrieval to an **external** RaaS
backend so its answers also draw on an outside corpus — **still per-chunk authorized by its
own OpenFGA**. This already exists (`config.RaasEndpoint` + `rag/retriever.py`
`build_retrievers`); you add a connector with a JSON env entry — **no code**.

Set `RAAS_ENDPOINTS` (a JSON array; each entry is a `RaasEndpoint`):

```jsonc
// RAAS_ENDPOINTS — one or more external retrieval-as-a-service backends.
[
  { "name": "corp-wiki", "url": "https://raas.corp.internal", "api_key": "<bearer>", "top_k": 10 }
]
```

- **k8s:** add it to the department's overlay ConfigMap patch (it is a plain env string):
  ```yaml
  - op: add
    path: /data/RAAS_ENDPOINTS
    value: '[{"name":"corp-wiki","url":"https://raas.corp.internal","top_k":10}]'
  ```
  (Put the `api_key` in the Secret instead of the ConfigMap if it is sensitive.)
- **Compose:** add `RAAS_ENDPOINTS=[...]` to the department's `.env.<dept>`.

> Env var name: pydantic-settings maps the `raas_endpoints` field to `RAAS_ENDPOINTS` (no
> prefix). (The docstring in `config.py` shows a `RAG_`-prefixed example, but the loader has
> no `env_prefix` — `RAAS_ENDPOINTS` is the name k8s/Compose env actually reads.)

How it behaves (from `rag/retriever.py`):
- The endpoint is fused into the department's hybrid retrieval (Qdrant + BM25) via
  Reciprocal Rank Fusion. The adapter `POST`s to `<url>/retrieve`.
- It is treated as an **untrusted** backend: a chunk surfaced **only** by the RaaS is
  **re-sourced from a trusted store before being served**, and **every** returned
  `chunk_id` is still authorized against the department's OpenFGA — so an external service
  can never widen access or inject unauthorized content. The service must return **stable
  `chunk_id`s** that key this department's OpenFGA tuples.
- SSRF-guarded: a RaaS host in cloud-metadata / loopback / link-local space is refused. In
  `residency_mode: local` an external RaaS URL is refused outright (data stays in-cluster).

This is the "connector" axis: a department can add retrieval reach without giving up
per-chunk governance.

---

## Extension point 3 — ADD A DEPARTMENT (with its own DB)

A new department = a new manifest + overlay (copy an existing one). It gets its **own**
Qdrant / OpenFGA / Keycloak / Temporal / Redis / DID and its **own** data — the isolation
boundary is a dedicated Namespace + default-deny NetworkPolicy. **Worked example: the Finance
department `epsilon`** (added exactly this way — `infra/divisions/epsilon.yml` +
`k8s/overlays/epsilon/`).

1. **Manifest** — `infra/divisions/epsilon.yml` (copied from `delta.yml`):
   ```yaml
   division_id: epsilon
   display_name: Division Epsilon (Finance)
   port_base: 9400                 # clean band above delta's 9300 (see onboard_division._reserved_ports)
   trusted_peers: [gamma, delta]   # the departments it collaborates with, both ways
   docs_dir: tests/docs/cluster-b
   residency_mode: external
   seed_viewer: q4_financial_results
   local_tools: [tool.fincheck]    # the DISTINCT tool this department owns
   ```

2. **Make peers trust it both ways** — add `epsilon` to the existing departments'
   `trusted_peers` so federation wires the routes in both directions:
   `gamma.yml → [alpha, beta, delta, epsilon]`, `delta.yml → [gamma, epsilon]`.

3. **k8s overlay** — copy `k8s/overlays/delta/` to `k8s/overlays/epsilon/`: set
   `namespace: agt-div-epsilon`, the Namespace patch name/label, the ConfigMap values
   (`DIVISION_ID`/`CLUSTER_ID` = epsilon, `TRUSTED_PEERS: gamma,delta`,
   `AGENT_CLIENT_ID: agent-epsilon`, `AGENT_NAME`, `TEMPORAL_TASK_QUEUE: approval-epsilon`,
   `OIDC_*`, `AGT_LOCAL_TOOLS: tool.fincheck`), the `images:` `newTag: epsilon`, and leave
   `PEER_TOOL_MAP: ""` for federation to fill.

4. **Bring it up + federate** — it ingests its own docs into its own Qdrant, mints its own
   DID, and joins the tool mesh:
   ```bash
   # bring up just epsilon, then re-federate the whole mesh so existing departments learn its DID:
   python scripts/bootstrap_k8s.py --divisions gamma,delta,epsilon --federate --context kind-agt
   ```
   Federation derives each department's `PEER_TOOL_MAP` from the manifests' `local_tools` +
   the federated DIDs — so adding epsilon **automatically** gives gamma + delta a
   `tool.fincheck → epsilon` route, and gives epsilon routes to gamma's pii/compliance and
   delta's risk/classify, with **no hand-editing** of any routing table. (Verify offline first
   with `federate_divisions.compute_peer_tool_map` across the three manifests — it yields the
   full N-way table.)

The `base/` is never edited; a department is added entirely by config (NFR-8). The Compose
path is identical: `scripts/onboard_division.py infra/divisions/epsilon.yml` then
`scripts/federate_divisions.py`.

---

## Where each piece lives

| Concern | File |
|---|---|
| The governed tools (in-process, 3-gate) | `agt-federated-rag/tools/local_tools.py` |
| `/solve` user trigger + governed delegation | `agt-federated-rag/api/main.py`, `agt-federated-rag/agent/nodes.py` (`solve_with_tools`) |
| Capability → peer DID routing (broker-less) | `agt-federated-rag/mesh/discovery.py`, `config.py` (`peer_tool_map`) |
| Retrieval-as-a-service connector | `agt-federated-rag/config.py` (`RaasEndpoint`, `RAAS_ENDPOINTS`), `agt-federated-rag/rag/retriever.py` (`build_retrievers`) |
| k8s defaults | `k8s/base/configmap.yaml` (`AGT_LOCAL_TOOLS`, `PEER_TOOL_MAP`) |
| Per-department assignment + routing (k8s) | `k8s/overlays/{gamma,delta,epsilon,...}/kustomization.yaml` |
| Department manifest (data + tools + peers) | `infra/divisions/{gamma,delta,epsilon,...}.yml` (`docs_dir`, `local_tools`, `trusted_peers`) |
| Env generation + auto-routing (Compose parity) | `scripts/onboard_division.py` (`AGT_LOCAL_TOOLS`), `scripts/federate_divisions.py` (`compute_peer_tool_map` → `PEER_TOOL_MAP`) |
| Deploy-time k8s mesh wiring | `scripts/bootstrap_k8s.py` (`--federate` patches each ConfigMap) |
