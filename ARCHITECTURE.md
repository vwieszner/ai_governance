# Federated, Cross-Cluster, Agent-to-Agent RAG on Kubernetes — Reference Architecture and Open-Source Stack (May 2026)

## TL;DR
- **Use A2A v1.0 (Linux Foundation) for inter-agent communication, MCP for agent-to-tool calls, and pair them with SPIFFE/SPIRE workload identity + OAuth 2.0 Token Exchange (RFC 8693) for on-behalf-of authentication** — this is the only protocol stack that is now an enterprise de facto standard (150+ orgs, IBM ACP merged in August 2025, AP2 ships as a formal A2A extension).
- **For the federated RAG storage layer, run Qdrant for hybrid (BGE-M3 dense + BM25 sparse with RRF fusion via Qdrant's Query API) plus Neo4j with the official `neo4j-graphrag` Python package as the GraphRAG backbone**, and use **OpenFGA (CNCF Incubating as of 28 Oct 2025) for per-chunk ReBAC ACLs with Temporal driving the "needs approval" human-in-the-loop workflow**.
- **For Kubernetes federation, use Cilium Cluster Mesh for L3/L4 cross-cluster networking plus Istio multi-primary for L7 mTLS and policy**, expose only signed A2A AgentCards at `/.well-known/agent-card.json` between clusters, and put KServe (CNCF Incubating since Nov 2025) + vLLM behind the agents for model serving.

## Key Findings

1. **A2A has effectively absorbed the agent-communication market.** Google contributed A2A to the Linux Foundation on 23 June 2025; IBM's ACP merged into A2A in August 2025 (with Kate Blair joining the A2A TSC); Cisco's AGNTCY joined the Linux Foundation in July 2025 and now uses A2A AgentCards in its directory. There is no competing standard for cross-vendor agent communication as of April 2026.
2. **MCP and A2A are layered, not competing.** MCP is the vertical agent-to-tool protocol (Anthropic, also LF-governed); A2A is the horizontal agent-to-agent protocol. Both are required.
3. **GraphRAG choice is now a real trade-off.** Writer's RobustQA benchmark (December 2024) reported GraphRAG scoring 86.31% versus competing RAG methods in the 33–76% range; but the May 2025 unbiased-evaluation paper *"How Significant Are the Real Performance Gains? An Unbiased Evaluation Framework for GraphRAG"* (Jiang et al., arXiv 2506.06331) showed that "LightRAG originally outperforms NaiveRAG with a win rate of 72% vs. 28% but NaiveRAG slightly outperforms LightRAG after eliminating the biases" — so the headline gains shrink when position/length/trial biases are stripped. The LightRAG paper itself (Guo et al., arXiv 2410.05779, EMNLP 2025) quantifies GraphRAG at ~610,000 tokens per retrieval vs. ~100 tokens for LightRAG's dual-level retrieval — a ~6,000× cost gap.
4. **Qdrant has had first-class hybrid (dense+sparse) since v1.10** with server-side RRF/DBSF fusion in its Query API and built-in BM25 via `Qdrant/bm25` and FastEmbed.
5. **For per-user, per-chunk authorization, OpenFGA or SpiceDB are the right answers.** OpenFGA moved to the CNCF Incubating maturity level on 28 October 2025 (CNCF announcement 11 Nov 2025). SpiceDB has the stronger consistency story (ZedTokens) and was confirmed by AuthZed at KubeCon NA 2025 as powering OpenAI's ChatGPT Enterprise connectors "handling tens of billions of fine-grained permissions". Oso's open-source library has been **deprecated** in favor of Oso Cloud — do not start new work on the OSS Oso library.
6. **For agent-acts-on-behalf-of-user, the now-canonical pattern is SPIFFE/SPIRE for workload identity + OAuth 2.0 Token Exchange (RFC 8693) carrying explicit `sub` (user) and `act` (agent) claims**, per Coalition for Secure AI and IBM/Stacklok ToolHive published guidance. Never pass user OAuth tokens through to downstream services unchanged.
7. **The OWASP GenAI Security Project released its Top 10 for Agentic Applications on 10 December 2025** — it is now the operational baseline for agentic risk and is referenced by Microsoft, NVIDIA, and AWS. Use it in concert with CSA MAESTRO's 7-layer threat model (published 6 Feb 2025) and MITRE ATLAS.
8. **The EU AI Act high-risk obligations become enforceable on 2 August 2026** — building NIST AI RMF + ISO/IEC 42001 + EU AI Act mapping in once via a unified register is the right approach.
9. **Temporal is the cleanest open-source choice for the "needs approval" path**, because durable signals survive cluster failures and naturally bridge to LangGraph agent runtimes.
10. **KServe became a CNCF Incubating project in November 2025**, with `LLMInferenceService` + `llm-d` integration providing the strongest Kubernetes-native LLM serving today (validated at Tesla production scale).

---

## Details

### 1. Open-Source AI Governance Frameworks

| Framework | Role | Status (May 2026) | Recommendation |
|---|---|---|---|
| **NIST AI RMF 1.0 + Generative AI Profile (AI 600-1, July 2024)** | Voluntary risk methodology: Govern/Map/Measure/Manage; 12 GenAI risk categories (confabulation, info integrity, etc.) | Active; Cyber AI Profile IR 8596 draft Dec 2025 | **Adopt as the risk methodology layer.** |
| **OWASP Top 10 for LLM Applications (2025)** | LLM01 prompt injection through LLM10 unbounded consumption | Active baseline | **Use as control-level taxonomy for the RAG layer.** |
| **OWASP Top 10 for Agentic Applications (10 Dec 2025)** | ASI01 Agent Goal Hijack, ASI03 Identity & Privilege Abuse, ASI09 Human-Agent Trust Exploit, ASI10 Rogue Agents, etc. | Released | **Use on top of LLM Top 10 for the agent layer.** |
| **ISO/IEC 42001:2023** | First international AI management system standard | Certifiable via accredited bodies (ISO/IEC 42006:2025) | **Use as the auditable AIMS shell.** |
| **MITRE ATLAS** | Adversarial TTPs against AI; 14 new AI-specific techniques added in 2025 | Active | **Use for red-team and detection mapping.** |
| **EU AI Act** | Risk-based law; GPAI obligations live 2 Aug 2025, high-risk live 2 Aug 2026 | Enforceable | **Mandatory if any EU exposure.** Penalties up to €35M / 7% global turnover. |
| **CSA MAESTRO (Feb 2025)** | 7-layer threat model for agentic AI (Foundation Models, Data, Agent Frameworks, Deployment, Evaluation, Ecosystem, Agent Operations) | Active; CSA tool on GitHub | **Use as the explicit threat-modeling framework — STRIDE/PASTA fail on agentic systems.** |

**Open-source toolkits — what to combine:**
- **AI Verify (IMDA Singapore)** + **Microsoft Responsible AI Toolbox** for bias/explainability evaluation.
- **IBM AI Fairness 360** + **Holistic AI open source** for bias metrics on training data.
- **NVIDIA Garak** + **Microsoft PyRIT** + **DeepTeam** + **Promptfoo** for red-team/adversarial testing in CI.
- **Credo AI Lens (OSS parts)** for model documentation.
- Mend.io's published mappings illustrate how a single evidence pipeline can output to EU AI Act, NIST SSDF, ISO 42001, and OWASP LLM Top 10 simultaneously.

**Recommended governance stack:** ISO 42001 management shell → NIST AI RMF for risk methodology → OWASP LLM + Agentic Top 10 + CSA MAESTRO + MITRE ATLAS as control taxonomies → **Microsoft Agent Governance Toolkit** for runtime policy enforcement and OWASP Agentic Top 10 evidence collection → Garak/PyRIT/Promptfoo in CI → AI Verify / RAI Toolbox for periodic audits.

### 2. Open-Source Agent Governance

**Observability — pick one stack:**
- **Langfuse** (Apache 2.0, ClickHouse-backed, broad OTel + framework support, generous self-host) — recommended primary backbone.
- **Arize Phoenix** (open-source, OpenInference instrumentation built in, OTel-native, 9,746 stars / "9k+" on arize.com as of May 2026; backed by Arize AI's $70M Feb 2025 Series C). Stronger for RAG eval workflows out of the box.
- **OpenLLMetry/Traceloop** if you already run Prometheus/Grafana/Tempo and want pure OTel semantic conventions (whose GenAI conventions are now adopted by the OTel project).
- **Helicone** as a proxy if you only need cost/latency tracking.

**Pick:** Langfuse for production, Phoenix in dev/notebooks, instrument with OpenTelemetry GenAI conventions so traces are portable.

**Guardrails — layered approach:**
- **Input rail:** NVIDIA NeMo Guardrails (Colang DSL, ~50–150 ms on optimized infra, Nemotron Safety Guard models on HF).
- **Output validation:** Guardrails AI Hub (50+ validators, Pydantic-based).
- **Content classification:** Llama Guard / Prompt Guard for prompt-injection classification; **IBM Granite Guardian** for enterprise content safety; **Invariant Labs** for tool-call policy enforcement.
- **PII:** Microsoft Presidio (custom recognizers + NER + regex + checksum) — apply both on ingest (to vector DB) and on output.
- **Secrets:** LLM Guard scanners; Vigil for prompt-leak detection. Note **Rebuff was archived in May 2025** — do not adopt it.

**Runtime policy enforcement (new — April 2026):** **Microsoft Agent Governance Toolkit** (MIT, [github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)) is the first toolkit to explicitly address all 10 OWASP Agentic Top 10 risks with deterministic, sub-millisecond (<0.1ms p99) policy enforcement. It is a seven-package system available in Python, TypeScript, Rust, Go, and .NET:

- **Agent OS** — stateless policy kernel; intercepts every tool call before execution; supports YAML rules, OPA Rego, and Cedar policy languages.
- **Agent Mesh** — DID-based cryptographic identity (Ed25519), the Inter-Agent Trust Protocol (IATP) for secure agent-to-agent comms, and dynamic trust scoring (0–1000 scale with five behavioral tiers and trust decay).
- **Agent Runtime** — CPU-ring-inspired execution sandboxing, saga orchestration for multi-step transactions, and an emergency kill switch.
- **Agent SRE** — SLOs, error budgets, circuit breakers, chaos engineering, and progressive delivery for agent reliability.
- **Agent Compliance** — automated governance grading with EU AI Act, HIPAA, SOC2, and full OWASP Agentic Top 10 evidence collection.
- **Agent Marketplace** — plugin lifecycle management with Ed25519 signing, trust-tiered capability gating, and supply-chain security.
- **Agent Lightning** — RL training governance with policy-enforced runners and reward shaping.

Framework integrations are shipped for LangGraph, LangChain, CrewAI, Google ADK, Microsoft Agent Framework, OpenAI Agents SDK, Haystack, and PydanticAI — governance hooks into native extension points (callbacks, decorators, middleware) without rewriting agent code. Microsoft intends to donate the project to a foundation (AAIF/LF) for cross-industry stewardship. Install: `pip install agent-governance-toolkit[full]`.

**OWASP Agentic Top 10 → toolkit mapping:** goal hijacking → semantic intent classifier (Agent OS); tool misuse → capability sandboxing + MCP security gateway; identity abuse → DID identity + behavioral trust scoring (Agent Mesh); supply chain → Ed25519 plugin signing (Agent Marketplace); code execution → execution rings (Agent Runtime); memory poisoning → Cross-Model Verification Kernel with majority voting; insecure comms → IATP encryption (Agent Mesh); cascading failures → circuit breakers + SLO enforcement (Agent SRE); human-agent trust exploitation → approval workflows with quorum logic; rogue agents → ring isolation + trust decay + kill switch.

**Evaluation:** DeepEval, Ragas, TruLens for RAG-specific metrics (context relevance, groundedness, answer relevance); Promptfoo for CI-style A/B; Inspect AI for agent eval suites.

**Identity/lifecycle:** SPIFFE/SPIRE for workload identity (see §7) plus per-agent OAuth client registration (RFC 7591) — this becomes the agent identity backbone.

### 3. A2A / Inter-Agent Protocols — Comparison and Recommendation

| Protocol | Owner / Governance | Transport | Status (May 2026) | Use For |
|---|---|---|---|---|
| **A2A** | Linux Foundation (since 23 June 2025) | HTTP + JSON-RPC 2.0 + SSE; gRPC added in v0.3; **signed AgentCards** + AP2 extension in v1.0 | **De facto standard**, 150+ orgs, 22k+ GitHub stars, SDKs in Python/JS/Java/Go/.NET | **Cross-cluster agent comms (primary choice)** |
| **MCP** | Linux Foundation (Anthropic) | JSON-RPC 2.0 | Adopted natively in Claude, Copilot, Cursor, Azure AI Foundry, Bedrock AgentCore | **Agent-to-tool/data — complementary to A2A** |
| **IBM ACP** | Was BeeAI / LF | REST | **Merged into A2A August 2025** (BeeAI migration guide published) | **Do not adopt — migrate to A2A** |
| **Cisco AGNTCY** | LF (July 2025) | gRPC pub/sub via SLIM (with MLS / RFC 9420 group encryption) | Active; 65+ supporters; Agent Directory supports A2A AgentCards and MCP descriptions | **Use SLIM as L4 transport if you need pub/sub or MLS group encryption; otherwise A2A over HTTP suffices** |
| **ANP** | Decentralized DID-based | HTTP+DID | Niche | Skip |
| **LOKA** | CMU academic (arXiv 2504.10915) | DID/VC-based | **Research proposal only**, no production deployment | Skip for production |
| **LMOS (Eclipse)** | Eclipse Foundation | Transport-agnostic; Agent Definition Language added 28 Oct 2025 | Active; in production at Deutsche Telekom | Niche |
| **AITP (NEAR)** | NEAR AI | Cross-trust-boundary structured messages including payments | Pre-1.0 RFC | Skip unless crypto-payments use case |
| **Coral Protocol** | Coral Protocol team (arXiv 2505.00749) | MCP-based + payments | Active OSS, pre-1.0 | Skip |
| **Agora Protocol** | Oxford/Eigent academic (arXiv 2410.11905) | "Meta-protocol" — natural language → LLM routines → structured | Research | Skip |
| **AP2** | Google + Coinbase + 60+ partners, 16 Sep 2025 | **Formal A2A extension** (AgentCard `extensions` field, URI `github.com/google-agentic-commerce/ap2/tree/v0.1`) | Active | Add if you need agent-mediated payments |

**Concrete recommendation for the two-cluster federated case:**
- Each cluster's agent exposes an **A2A AgentCard at `/.well-known/agent-card.json`**, signed (A2A v1.0).
- Cross-cluster A2A traffic flows over **mTLS** between Istio gateways, with **SPIFFE SVIDs** identifying the agent workloads.
- **MCP** is used inside each cluster for the agent to talk to its local Qdrant, Neo4j, OPA/OpenFGA, approval workflow, etc.
- AGNTCY's **SLIM** (gRPC + MLS pub/sub, per IETF draft `draft-mpsb-agntcy-slim`) is optional and only worth introducing if you anticipate many-to-many agent fanout beyond two clusters.

### 4. Agent Frameworks — Comparison

| Framework | A2A native | MCP native | K8s-friendly | Best at |
|---|---|---|---|---|
| **LangGraph** (LangChain) | Adapters (community) | Yes via LangChain MCP | Excellent (LangGraph Platform) | Production graph orchestration, checkpointing, human-in-the-loop |
| **Google ADK** | **Native v0.3+** | Native | Excellent (GKE deployment guide published) | A2A multi-agent on GCP/Gemini |
| **BeeAI Framework** (IBM, LF) | **Native via A2AServer/A2AAgent** | Native | Good | Cross-framework A2A interop |
| **Microsoft Agent Framework (AutoGen+SK merged, v1.0 GA April 2026)** | Adapters | Native | Excellent on Azure | .NET / Azure shops |
| **CrewAI** | Added A2A support | Yes | Good | Rapid prototyping, role-based crews |
| **OpenAI Agents SDK** | No native | Native | Minimal | OpenAI-only |
| **Pydantic AI** | Native | Native | Good | Type-safe agents with Logfire OTel |
| **AutoGen (legacy)** | No | No | OK | **Maintenance mode — do not adopt for new work** |
| **LlamaIndex Workflows** | Adapters | Yes | Good | Mixing RAG + agent steps |
| **Semantic Kernel** | Merged into MS Agent Framework | Yes | Good | .NET |
| **Haystack Agents** | Community | Yes | Good | RAG-centric pipelines |
| **DSPy** | No | No | OK | Programmatic prompt optimization, not a runtime |

**Recommendation:** **LangGraph as the orchestration backbone in each cluster, exposed via the BeeAI A2AServer adapter** (or, equivalently, the official Google ADK A2A adapter if you're on Gemini/GCP). LangGraph's checkpointing is what lets the approval-pending state survive crashes and reboots; the BeeAI/ADK A2A wrapper gives you AgentCard discovery for free.

### 5. GraphRAG — Comparison and Recommendation

| Project | Strengths | Weaknesses | Inc. updates | Graph DB | K8s | Pair with Qdrant |
|---|---|---|---|---|---|---|
| **Microsoft GraphRAG** | Hierarchical communities, best global queries (86.31% on Writer's RobustQA per Neo4j's GraphRAG Manifesto blog) | **Very expensive indexing** — ~610,000 tokens per retrieval per LightRAG paper (arXiv 2410.05779) | Limited | LanceDB/Parquet by default | OK | Yes via custom retriever |
| **LightRAG (HKU)** | ~6,000× cheaper tokens (~100 vs ~610,000), strong legal-RAG accuracy, simple ops, modular backends (Neo4j, PG/AGE, FAISS, Milvus, Redis) | Less faithful on complex relational queries; gains shrink in unbiased eval (Jiang et al., arXiv 2506.06331) | **Strong incremental updates** | Pluggable | Good | Native |
| **HippoRAG 2** | Best multi-hop recall (~88–91% Evidence Recall L2/L3), compact prompts (~1k tokens) | Newer ecosystem | Yes | Neo4j-style | Good | Yes |
| **Neo4j `neo4j-graphrag` Python package** | Official, first-party; SimpleKGPipeline; multi-retriever (vector, hybrid, text2cypher, graph traversal) | Tied to Neo4j | Yes | Neo4j 5.23+ with APOC | Excellent (Neo4j Helm) | Yes (use Qdrant for vectors, Neo4j for graph) |
| **Neo4j LLM Knowledge Graph Builder** | UI app, multi-LLM, multi-source ingest | More of a tool than library | Yes | Neo4j | Docker Compose | Indirect |
| **nano-graphrag** | Tiny, hackable | Less features | Yes | Pluggable | Good | Easy |
| **Cognee** | Memory-graph for agents | Newer | Yes | Multiple | Good | Yes |
| **LangChain `LLMGraphTransformer`** | Easiest to drop in | Just a transformer, not a system | N/A | Any | Good | Yes |
| **AWS GraphRAG-Toolkit** | AWS-native | AWS-coupled | Yes | Neptune | OK | Possible |
| **Memgraph / FalkorDB / TigerGraph / ArangoDB GraphRAG** | Vendor stacks | Vendor coupling | Varies | Their DB | Varies | Varies |
| **KAG / GFM-RAG / ItRAG** | Strong on knowledge-heavy tasks | Younger / research | Varies | Varies | Varies | Varies |

**Recommendation:** Use **Neo4j (community/AuraDB) + the `neo4j-graphrag` Python package** as the GraphRAG backbone, with **Qdrant as the parallel vector+sparse store**. Neo4j is the most Kubernetes-friendly graph DB (official Helm chart, AuraDB option for managed), the official package supports hybrid + Text2Cypher + graph traversal retrievers, and you can layer LightRAG-style dual-level retrieval on top of Neo4j storage. The architecture pattern: **ingest text → LLM-extract entities/relations → write triples to Neo4j AND embeddings (BGE-M3 dense + BM25 sparse) to Qdrant → at query time, fan out to both retrievers in parallel → fuse with RRF and feed top-k chunks + 1–2 hop subgraph into the answer prompt**.

If indexing cost is the dominant constraint and global summarization is not critical, swap Microsoft GraphRAG for LightRAG (also Neo4j-backed) to save the ~6,000× token cost during ingestion.

### 6. Hybrid Search Stack with Qdrant

**Qdrant Query API (since v1.10)** supports server-side hybrid retrieval and RRF / DBSF fusion in a single call:

```python
client.query_points(
    collection_name="kb",
    prefetch=[
        models.Prefetch(query=models.Document(text=q, model="BAAI/bge-m3"), using="dense", limit=20),
        models.Prefetch(query=models.Document(text=q, model="Qdrant/bm25"), using="sparse", limit=20),
    ],
    query=models.FusionQuery(fusion=models.Fusion.RRF),
    limit=10,
)
```

**Embeddings — recommended:**
- **BGE-M3** is the canonical hybrid model: ~568M params, 100+ languages, 8192-context, simultaneously emits dense + sparse (lexical weights) + ColBERT multi-vectors — matches Qdrant's hybrid API one-to-one.
- Alternatives: Jina v3 (multilingual, task LoRA), Nomic Embed v2 (MoE, Apache-2), Snowflake Arctic-Embed v2 (Apache-2, Pareto-optimal). For pure English quality, Qwen3-Embedding-8B + SPLADE/BM25 is the leading combo but heavier.

**Sparse:** `Qdrant/bm25` (built-in, IDF computed server-side) or `prithivida/Splade_PP_en_v1` for SPLADE.

**Rerankers (top-k → top-n):**
- **`bge-reranker-v2-m3`** (568M, multilingual, Apache-2) — production default; beats Jina-reranker-v2 and mxbai-rerank-large-v1 on most BEIR tasks per NVIDIA's published comparison (arXiv 2409.07691).
- **`mxbai-rerank-v2-large-1.5B`** (Apache-2, Qwen-2.5-based, 100+ languages, 32k context, claimed BEIR 57.49) — best open-source quality if you can pay the latency.
- **Jina reranker v2/v3** — strong but v3 is CC-BY-NC, not safe for commercial.
- **ColBERT / ColPali** — late-interaction; ColPali for visual-document RAG.

**Fusion strategy — combining Qdrant hybrid with GraphRAG output:** run dense+sparse on Qdrant → fuse with RRF → pull entities mentioned in top-k chunks and expand 1–2 hops in Neo4j → append the resulting subgraph (as compact triples or community summaries) to the LLM context. For global/summarization queries, run a separate community-summary retriever (à la GraphRAG) and concatenate.

### 7. Authorization & Approval — the Critical Layer for the User's Use Case

**Per-chunk / per-document ACLs (ReBAC):** Use **OpenFGA** (CNCF Incubating since 28 Oct 2025, Apache 2.0, by Okta/Auth0) **or SpiceDB** (AuthZed). Both are Zanzibar-inspired; pick:
- **OpenFGA** if you want the broadest SDK ecosystem and an easy Auth0 path.
- **SpiceDB** if you need ZedToken strict consistency — AuthZed confirmed at KubeCon NA 2025 that SpiceDB powers OpenAI's ChatGPT Enterprise connectors at "tens of billions of fine-grained permissions".

Model chunks as objects, users/groups as subjects; relations like `viewer`, `editor`, `pending_approval`. For row-level / per-chunk ACLs, write a tuple per chunk-user grant; for scale, derive from group/role membership via type-level relations.

**Policy / ABAC layer:** **OPA** (Rego) at admission/gateway level for cluster policies; **Cedar** if you want a policy DSL with formal analysis (used in AWS Verified Permissions). **Casbin** is fine for simple RBAC. **Topaz (Aserto)** is OPA + ReBAC if you want a single sidecar.

**Identity layer:** **Keycloak** for human SSO/OIDC; **Ory stack (Kratos + Hydra + Keto + Oathkeeper)** if you want each layer separately and modular.

**Workload identity:** **SPIFFE / SPIRE** (CNCF Graduated) — every agent pod gets an X.509 SVID via the Workload API; SPIRE Server is HA-deployed with PostgreSQL and an HSM/KMS-protected CA.

**Agent-acts-on-behalf-of-user (THE critical pattern):**
1. User authenticates to the user-facing entry agent via OIDC (Keycloak).
2. Entry agent gets a user JWT.
3. Before calling MCP tools or another A2A agent, the agent **exchanges the user token (RFC 8693)** at the authorization server, presenting its **SPIFFE SVID** for client authentication and the user JWT as the `subject_token`. The exchanged token carries `sub = user` and `act = agent_spiffe_id` and is **scoped to exactly the target audience and operation**.
4. The downstream MCP server / A2A agent validates the SVID + token, authorizes on `sub` (the user), but logs and rate-limits on `act` (the agent).

Never forward the raw user token. Per CoSAI guidance: "do not pass through OAuth tokens provided by the user". Stacklok ToolHive's RFC 8693 implementation (toolhive issue #5194) and Riptides' SPIFFE-backed OAuth Dynamic Client Registration are reference implementations.

**Approval workflow:** **Temporal** is the right choice. Temporal Signals are durable: when an authorization check returns `NEEDS_APPROVAL`, the agent starts (or signals) a Temporal workflow that:
1. Writes a pending decision row tied to the request ID.
2. Sends a notification to the approver (Slack/email/webhook activity).
3. Awaits a signal `approval_decision` with a timeout (e.g., 24h).
4. On approval, writes an OpenFGA tuple granting the user the relation on the chunk (auditable), then resumes and replays the original RAG query.
5. On rejection or timeout, returns the reasoning to the original user.

Alternatives: Argo Workflows for K8s-pod-per-step batch flows (less suited to long human waits with signals); n8n for low-code (Community Edition cannot scale); Camunda for BPMN-heavy enterprises.

### 8. Security & Safety Layer

- **Prompt injection / jailbreak:** NeMo Guardrails (Colang) for input rails; LLM Guard scanners; Llama Guard / Prompt Guard for classifier-style detection; Vigil for prompt-leak; **Rebuff is archived — skip**. Lakera Guard's open alternatives are essentially LLM Guard + NeMo Guardrails (Lakera was acquired by Check Point in Sept 2025).
- **PII detection/redaction:** **Microsoft Presidio** — apply (a) at ingest before chunks reach Qdrant/Neo4j and (b) on RAG output. Use the "Anonymize → LLM → De-anonymize" pattern with reversible token mapping for cases where the user is authorized to see the PII.
- **Secrets detection:** LLM Guard's `Secrets` scanner; TruffleHog/Gitleaks for stored prompts.
- **Sandboxing tool calls:** **E2B** or **Daytona** for code-execution sandboxes; **gVisor** or **Kata Containers** for syscall-level isolation of MCP servers handling code/shell tools.
- **DLP for RAG outputs:** Presidio + custom Guardrails AI validators.
- **Adversarial robustness:** **NVIDIA Garak** (broadest probes), **Microsoft PyRIT** (orchestrated attacks), **DeepTeam** (OWASP-LLM-framework-aware), **Promptfoo** for CI.
- **Supply chain:** **Sigstore + cosign** for image signing; **model signing** via Sigstore's model-signing project; verify **Hugging Face safetensors** with `transformers`' integrity checks; SLSA provenance for fine-tunes.
- **Network security between clusters:** **Istio multi-primary with SPIFFE trust domain federation** is the production-grade choice for mTLS + L7 policy; **Cilium Cluster Mesh** for L3/L4 cross-cluster service connectivity (overlapping pod CIDRs handled, native eBPF). Submariner is a viable alternative but has known incompatibilities with Cilium (per discussions on the Cilium GitHub project). **Karmada** if you also need cross-cluster orchestration of K8s objects.

### 9. Kubernetes-Native Deployment & Federation

- **Model serving:** **KServe** (CNCF Incubating since Nov 2025) with `LLMInferenceService` + **llm-d** for cache-aware routing/disaggregated prefill-decode; serves vLLM, TGI, Ollama as runtimes. KServe's Inference Gateway Extension is used at Tesla scale (Red Hat / Tesla joint engineering, llm-d.ai blog).
- **Vector DB:** **Qdrant** with its official Helm chart, 3-node minimum for HA.
- **Graph DB:** **Neo4j** with the official Helm chart, or AuraDB managed.
- **Agent runtime:** **KubeRay / Ray Serve** if you need Python-based fan-out; otherwise simple Deployments suffice for LangGraph apps.
- **Multi-cluster networking:** **Cilium Cluster Mesh** as CNI + L3/L4 cross-cluster service mesh; **Istio multi-primary** on top for L7 mTLS, SPIFFE-based AuthorizationPolicy, traffic mirroring. Cross-cluster service discovery via Cilium's global services (`io.cilium/global-service: "true"`) or Istio's ServiceEntry pattern. **Karmada** for declarative cross-cluster K8s API.
- **Cross-cluster A2A exposure:** put the A2A endpoint behind an Istio gateway; restrict mTLS to peer-cluster SPIFFE IDs; AgentCard is publicly fetchable but signed (A2A v1.0 Signed AgentCards).
- **GitOps:** **ArgoCD** (or Flux). Use ApplicationSets for multi-cluster fan-out of the agent + RAG stack.
- **Observability:** **Prometheus + Grafana + Loki + Tempo** for infrastructure; **Langfuse** (or Phoenix) for LLM/agent traces; export OpenTelemetry GenAI spans from both into the same backend if you want correlated debugging.

### 10. End-to-End Reference Architecture

**Per cluster (Cluster A and Cluster B identical):**

```
┌─────────────────────────────────────────────────────────────────────┐
│                          User-facing UI                              │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ OIDC (Keycloak)
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ A2A Agent (LangGraph, exposed via BeeAI A2AServer or ADK A2A)        │
│  - AgentCard at /.well-known/agent-card.json (signed)                │
│  - SPIFFE SVID, OAuth client (RFC 7591 dynamic)                      │
│  - NeMo Guardrails (input rail) → Presidio → policy check            │
└─────┬───────────────────────┬────────────────────────┬───────────────┘
      │ MCP                   │ A2A (cross-cluster)    │
      ▼                       ▼                        ▼
┌──────────┐         ┌────────────────────┐    ┌──────────────────┐
│  Qdrant  │         │  Other-cluster A2A │    │ OpenFGA / SpiceDB │
│ (dense+  │         │     Agent          │    │ (per-chunk ACLs)  │
│  BM25)   │         └────────────────────┘    └──────────────────┘
└──────────┘                                          │
┌──────────┐                                          ▼
│  Neo4j   │                                  ┌────────────────────┐
│ (GraphRAG│                                  │ Temporal           │
│ via      │                                  │ (approval workflow)│
│ neo4j-   │                                  └────────────────────┘
│ graphrag)│                                          │
└──────────┘                                          ▼
                                              ┌─────────────────┐
                                              │ Notifier        │
                                              │ (Slack/email)   │
                                              └─────────────────┘
KServe + vLLM (model serving), all on Istio + Cilium ClusterMesh,
Langfuse + OTel collecting traces.
```

**Cross-cluster wiring:** Both clusters join the same SPIFFE trust-domain federation. Cluster A's egress to Cluster B's A2A endpoint goes via Istio east-west gateway over mTLS; the peer SPIFFE ID is allow-listed in an AuthorizationPolicy. AgentCards are fetched once and cached; signature verification happens on the consumer side.

**Approval routing:** OpenFGA on Cluster B is the source of truth for who owns/approves chunk X. When agent B receives an A2A `tasks/send` from agent A and OpenFGA returns `NEEDS_APPROVAL`, agent B starts a Temporal workflow on Cluster B, looks up the approver via OpenFGA (`owner` relation), notifies them, and immediately returns an A2A task status of `input-required` (or a custom `pending-approval` state via A2A v0.3+ extension). Agent A in turn returns to its user "Your request is pending approval by Alice; we'll notify you when decided." When the approver responds, Temporal sends an `approval_decision` signal, the workflow writes an OpenFGA tuple granting the user access, and emits an A2A task update — agent A streams the result back to the original user via SSE.

#### Sequence diagrams (text)

**Flow A — Local + authorized:**
1. User → Agent A: "What is X?"
2. Agent A → Keycloak: validate user JWT
3. Agent A → OpenFGA: `check(user, viewer, chunk:X)` → ALLOWED
4. Agent A → Qdrant (hybrid) + Neo4j (subgraph) → top-k chunks + triples
5. Agent A → LLM (vLLM via KServe) → answer
6. Agent A → User (SSE), Langfuse logs trace.

**Flow B — Local but needs approval:**
1–3. As above; OpenFGA returns NEEDS_APPROVAL.
4. Agent A starts Temporal workflow, returns "pending approval" to user.
5. Temporal activity notifies approver on Slack with deep link.
6. Approver decides → Temporal signal received.
7. If approved: Temporal writes OpenFGA tuple, signals back into Agent A's session (or user receives a notification + link to retry).

**Flow C — Remote + authorized:**
1. User → Agent A: "What is Y?" (data only on Cluster B)
2. Agent A consults its local data registry (or AgentCard skill list), routes to Agent B.
3. Agent A → Token endpoint (RFC 8693): exchange user JWT + Agent A SVID → delegated token (`sub=user, act=agentA, aud=agentB`).
4. Agent A → Agent B over A2A (Istio east-west, mTLS, SPIFFE-validated): `tasks/send` with delegated token in `Authorization` header.
5. Agent B → Keycloak: validate token, extract `sub` and `act`.
6. Agent B → OpenFGA-B: check(user, viewer, chunk:Y) → ALLOWED.
7. Agent B → its local Qdrant + Neo4j → result.
8. Agent B → Agent A → User (streamed via SSE through both hops).

**Flow D — Remote + needs approval (the critical flow):**
1–5. As Flow C.
6. OpenFGA-B returns NEEDS_APPROVAL.
7. Agent B starts Temporal workflow on Cluster B; resolves approver from OpenFGA-B (`owner`).
8. Agent B returns A2A task state `input-required` with reason `pending-approval` and approver name to Agent A.
9. Agent A returns to user: "Pending approval by Bob on cluster B."
10. Temporal-B sends notification (Slack/email/in-app) to Bob with approve/deny URL pointing at Cluster B's approval UI.
11. Bob authenticates to Cluster B (Keycloak) → approves → Temporal-B signal.
12. Temporal-B writes OpenFGA-B tuple → calls back to Agent B → Agent B emits an A2A `task/update` event (via push notification webhook to Agent A registered at task creation).
13. Agent A receives webhook, re-runs the original task (now authorized), streams answer to the original user.

**Governance/Observability/Security overlays:**
- All agent calls are wrapped with NeMo Guardrails (input) and Guardrails AI validators (output).
- Presidio masks PII on ingest into Qdrant/Neo4j; for authorized retrieval, the user-binding controls whether the de-anonymizer is invoked.
- Every span flows through OTel GenAI semantic conventions to Langfuse; Temporal workflow history is the system-of-record for approval audit.
- Garak/PyRIT run nightly against both clusters' agents in a CI namespace.
- ISO 42001 evidence (model cards, risk register, conformity docs) is generated from Langfuse + OpenFGA tuple history + Temporal workflow history.
- Sigstore signs model artifacts and container images; only signed images can run (admission via Kyverno or Connaisseur).
- CSA MAESTRO threat model is reviewed quarterly; OWASP Top 10 for LLM + Agentic mapped to control tests.

---

## Recommendations

**Phase 1 (Weeks 0–6) — Foundations:**
1. Stand up Keycloak + SPIFFE/SPIRE on both clusters with a federated trust domain.
2. Install Cilium Cluster Mesh + Istio multi-primary; verify east-west gateway between clusters works under mTLS.
3. Deploy Qdrant + Neo4j on both clusters via Helm; back up to S3-compatible storage.
4. Deploy KServe + vLLM with a chosen open model (e.g., Llama 3.3 70B Instruct or Mistral Large) and BGE-M3 + `Qdrant/bm25` for embeddings.
5. Deploy OpenFGA on both clusters, seed initial schema for `User`, `Group`, `Chunk`, with relations `viewer`, `editor`, `owner`, `pending_approval`.

**Phase 2 (Weeks 6–12) — Agent layer:**
6. Build the LangGraph agent in each cluster; wrap with BeeAI's `A2AServer` adapter.
7. Implement the RFC 8693 token-exchange middleware (reference: Stacklok ToolHive issue #5194).
8. Add the GraphRAG ingestion pipeline (`neo4j-graphrag` SimpleKGPipeline) and the hybrid Qdrant pipeline; index a pilot corpus.
9. Implement the cross-cluster A2A call from Agent A to Agent B; verify token has `act` claim.
10. Add Langfuse, NeMo Guardrails, Guardrails AI, Presidio.

**Phase 3 (Weeks 12–18) — Approval workflow:**
11. Deploy Temporal on both clusters (separate namespaces; not federated — each cluster's approvals stay local).
12. Wire the `NEEDS_APPROVAL` path: Agent → Temporal start → notification → signal → OpenFGA tuple write → A2A push notification webhook → resume.
13. Add A2A `pushNotificationConfig` so Agent A receives the eventual result asynchronously.

**Phase 4 (Weeks 18–24) — Governance & hardening:**
14. Run Garak + PyRIT + Promptfoo in nightly CI against both agents.
15. Map controls to OWASP LLM/Agentic + NIST AI RMF + ISO 42001 + EU AI Act (use the unified register pattern).
16. Add Sigstore signing in the CI pipeline and Kyverno verification at admission.
17. Threat-model via CSA MAESTRO; document and remediate.

**Benchmarks/thresholds that would change the recommendation:**
- If ingestion cost is the dominant constraint → swap Microsoft GraphRAG for LightRAG (still on Neo4j) — saves ~6,000× tokens per the LightRAG paper.
- If your queries are 90%+ keyword/fact lookup → drop GraphRAG entirely and use Qdrant hybrid alone with bge-reranker-v2-m3.
- If you reach >5 clusters → add Cisco AGNTCY SLIM (gRPC pub/sub) as the L4 agent message bus instead of point-to-point A2A.
- If you must support strict revocation latency in OpenFGA, migrate to **SpiceDB** (ZedTokens give per-request consistency choice).
- If you have heavy .NET/Azure exposure → swap LangGraph for Microsoft Agent Framework (v1.0 GA April 2026).
- If you need agent-mediated payments → adopt AP2 (A2A extension) and add the `act` chain through the AP2 Intent/Cart/Payment mandates.

## Caveats

- **A2A v1.0 was finalized only in early 2026**; some SDKs still lag on Signed AgentCards. Validate signature support in the SDK version you adopt.
- **OpenFGA is CNCF Incubating, not Graduated** (Incubating since 28 October 2025) — its API is stable but tooling around it is still maturing; SpiceDB is more battle-tested at very high scale (OpenAI ChatGPT Enterprise).
- **Microsoft GraphRAG's headline accuracy gains are real on the right benchmark (Writer's RobustQA at 86.31%) but the unbiased evaluation framework by Jiang et al. (arXiv 2506.06331, May 2025) showed that "LightRAG originally outperforms NaiveRAG with a win rate of 72% vs. 28% but NaiveRAG slightly outperforms LightRAG after eliminating the biases"** — meaning much of the reported GraphRAG/LightRAG advantage stems from evaluation artifacts (position, length, trial bias). Always evaluate on your own corpus with bias-mitigated protocols.
- **LangGraph A2A support is via community/adapter code**, not first-party. Long-term, ADK (Google) and BeeAI (IBM/LF) have the deepest A2A integration; consider a hybrid runtime.
- **Oso's open-source library is deprecated** (osohq.com explicit deprecation notice; GitHub README labeled "Deprecated"). Do not adopt it for new work — choose OpenFGA or SpiceDB.
- **Rebuff is archived (May 2025).** **AutoGen is in maintenance mode** after the merger into Microsoft Agent Framework.
- **EU AI Act compliance dates:** GPAI obligations are live since 2 Aug 2025; high-risk obligations enforce 2 Aug 2026. Build the conformity evidence pipeline now.
- **Cross-cluster Cilium Cluster Mesh + Istio multi-primary is a known-tricky combination** (ClusterIP resolution edge cases documented in upstream Istio issue #52402); pilot carefully.
- Several published "comparisons" of agent frameworks and rerankers in 2025/2026 trade-press blogs include future-tense or speculative claims; verify every benchmark against primary sources (MTEB leaderboard, BEIR, vendor papers) before final selection. The MTEB v2 (2026) scores are not directly comparable to MTEB v1.