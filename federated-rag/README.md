# Federated Cross-Cluster RAG

Two Kubernetes clusters, each running a LangGraph agent with hybrid Qdrant RAG (dense + sparse with RRF) and a scaffolded Neo4j graph-retrieval seam, communicating via the A2A v1.0 protocol with OpenFGA per-chunk authorization and Temporal approval workflows.

> **Retrieval status:** the demo runs **Qdrant-only** hybrid retrieval. The Neo4j path is wired
> in and RRF-fused, but the documented bring-up uses `--no-neo4j` so it is not exercised; even when
> populated it does vector + keyword lookup of chunks (`HybridRetriever`), **not** graph traversal
> or entity-neighbourhood expansion. See the root `README.md` GraphRAG note for details.

## Architecture

```
User → Agent A (LangGraph)
         ├── Qdrant (BGE-M3 dense + BM25 sparse, RRF fusion)
         ├── Neo4j  (graph-retrieval seam via neo4j-graphrag; scaffolded, not exercised by the demo)
         ├── OpenFGA (per-chunk ReBAC: viewer / editor / owner / pending_approval)
         ├── Temporal (approval workflow + Slack notification)
         └── A2A client ──→ Agent B (same stack, other cluster)
                                └── OpenFGA-B → Temporal-B (if approval needed)
```

## 4 Authorization Flows

| Flow | Condition | Outcome |
|------|-----------|---------|
| **A** | Data local, user has viewer access | Answer returned immediately |
| **B** | Data local, access pending approval | Temporal workflow started, approver notified |
| **C** | Data on peer cluster, user approved there | A2A call → answer streamed back |
| **D** | Data on peer cluster, approval needed | Peer starts Temporal workflow, user notified on both ends |

## Quick Start

### 1. Install dependencies
```bash
cd federated-rag
pip install -e "."
python -m spacy download en_core_web_lg
```

### 2. Configure
```bash
cp .env.example .env
# Edit .env with your NVIDIA NIM key, Qdrant/Neo4j/OpenFGA/Temporal endpoints
```

### 3. Ingest documents
```bash
python -m rag.ingest --path ./your-docs/
```

### 4. Set up OpenFGA
```bash
# Port-forward OpenFGA
kubectl port-forward svc/openfga 8080:8080 -n federated-rag

# Create store + auth model, copy output to .env
python scripts/setup-openfga.py
```

### 5. Start the Temporal worker
```bash
python -m workflow.worker
```

### 6. Start the agent API
```bash
python -m api.main
# or: uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### 7. Test a query
```bash
curl -X POST http://localhost:8000/tasks/send \
  -H "Authorization: Bearer YOUR_USER_JWT" \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -d '{
    "message": {
      "role": "user",
      "parts": [{"type": "text", "text": "What is our data retention policy?"}]
    }
  }'
```

## Kubernetes Deployment

### Per cluster:
```bash
# Create namespace
kubectl create namespace federated-rag

# Install Qdrant
helm repo add qdrant https://qdrant.github.io/qdrant-helm
helm install qdrant qdrant/qdrant -n federated-rag -f k8s/cluster-a/qdrant-values.yaml

# Install Neo4j
helm repo add neo4j https://helm.neo4j.com/neo4j
helm install neo4j neo4j/neo4j -n federated-rag -f k8s/cluster-a/neo4j-values.yaml

# Install OpenFGA
helm repo add openfga https://openfga.github.io/helm-charts
helm install openfga openfga/openfga -n federated-rag -f k8s/cluster-a/openfga-values.yaml

# Install Temporal
helm repo add temporal https://charts.temporal.io
helm install temporal temporal/temporal -n federated-rag -f k8s/cluster-a/temporal-values.yaml

# Deploy the agent
kubectl apply -f k8s/cluster-a/agent-deployment.yaml
```

## Project Structure

```
federated-rag/
├── agent/              LangGraph agent (state, nodes, graph)
├── rag/                Qdrant hybrid retrieval + scaffolded Neo4j graph-retrieval seam + RRF fusion + ingest
├── a2a/                A2A v1.0 protocol (models, client)
├── auth/               OpenFGA client + RFC 8693 token exchange
├── workflow/           Temporal approval workflow + activities + worker
├── api/                FastAPI server (A2A endpoints + approval UI)
├── k8s/                Helm values for cluster-a and cluster-b
├── scripts/            OpenFGA bootstrap
├── config.py           Centralised settings (pydantic-settings)
└── pyproject.toml
```

## Key Dependencies

| Component | Library |
|-----------|---------|
| Agent framework | LangGraph 0.2+ |
| LLM | NVIDIA NIM (OpenAI-compatible) |
| Vector store | Qdrant 1.11+ with BGE-M3 + BM25 |
| Graph RAG | neo4j-graphrag 1.2+ |
| Authorization | OpenFGA SDK 0.6+ |
| Token exchange | RFC 8693 via authlib |
| Approval workflow | Temporalio 1.7+ |
| API server | FastAPI 0.115+ with SSE |
