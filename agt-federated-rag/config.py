"""Central configuration — loaded once at startup from environment / .env file."""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import AnyHttpUrl, BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# RAG_ENV_FILE selects which env file to load, so the SAME codebase runs as two
# federated AGT clusters (cluster-a -> .env, cluster-b -> .env.cluster-b).
_ENV_FILE = os.environ.get("RAG_ENV_FILE", ".env")


class RaasEndpoint(BaseModel):
    """One external retrieval-as-a-service backend (Pattern A: it FINDS chunks; the
    agent still authorizes each returned chunk_id against OpenFGA downstream).

    The service MUST return stable ``chunk_id``s that key this division's OpenFGA
    tuples, and MUST NOT be relied on to filter per-user (that stays in check_auth).
    Configured as JSON in the ``RAAS_ENDPOINTS`` env var (the Settings loader has no
    env_prefix, so the field name IS the env var — not ``RAG_RAAS_ENDPOINTS``), e.g.
    ``RAAS_ENDPOINTS='[{"name":"acme","url":"https://raas.internal","top_k":10}]'``.
    """
    name: str                       # label used in fusion / logs (keep unique)
    url: str                        # base URL; the adapter POSTs to <url>/retrieve
    api_key: str = ""               # optional bearer token
    top_k: int = 10                 # default result count requested


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_ENV_FILE, env_file_encoding="utf-8", extra="ignore")

    # ── Cluster / division identity ───────────────────────────────────────────
    cluster_id: str = "cluster-a"
    # M0 (multi-division tenancy): the division this agent belongs to. Each
    # division is a physically-isolated stack (own OpenFGA store, Qdrant, Redis,
    # Keycloak realm, Temporal). division_id is threaded into token-claim audit,
    # OpenFGA audit records, and the cross-division A2A envelope (source_division)
    # so every action is attributable to a division and isolation is provable.
    # Defaults to cluster_id when unset (back-compat with single-cluster .env).
    division_id: str = ""
    # Comma-separated set of peer division ids this division federates with /
    # trusts (used by later milestones for multi-peer discovery + trusted-issuer
    # validation). Empty = no configured peers.
    trusted_peers: str = ""
    # M2: trusted peer-division OIDC issuer URLs (CSV). A cross-division user
    # assertion (the user's home-Keycloak token, forwarded in the DID-signed peer
    # envelope) is accepted only if its `iss` is in this set, and its signature is
    # verified against that issuer's JWKS (derived as <issuer>/protocol/openid-connect/certs).
    # This is the verifiable-cross-division-identity trust anchor (the spike showed
    # cross-realm token-exchange audience is unsupported, so the receiver validates
    # the home assertion directly against the home issuer).
    trusted_issuers: str = ""
    agent_name: str = "AGT RAG Agent"
    agent_url: AnyHttpUrl = Field(default="http://localhost:8000")  # type: ignore[assignment]
    # M8: directory for the tamper-evident hash-chained audit log. Each process writes
    # <division>_<role>.jsonl (agent + worker are separate processes). Per-division so
    # one division's audit trail is isolated from another's (NFR-2).
    audit_log_dir: str = "audit_logs"

    # ── Data residency / inference egress (M6, NFR-1) ─────────────────────────
    # "external" = LLM/embeddings may egress to a hosted endpoint (e.g. NVIDIA).
    # "local"    = inference must stay within the division boundary (no external
    # egress); a self-hosted backend is required. Threaded now so M6 can enforce.
    residency_mode: str = "external"

    # ── Transport security (M7, NFR-3) ────────────────────────────────────────
    # When true, the agent SERVES mTLS (client cert REQUIRED) and presents its own
    # division client cert on outbound peer calls. Default false → the bundled
    # localhost demo stays HTTP. Production sets require_mtls=true with the cert paths
    # below (issued from the federation CA by scripts/issue_division_certs.py, written
    # to infra/generated/<id>/certs/). The certless-peer rejection is proven by the
    # transport/mtls handshake tests.
    require_mtls: bool = False
    # PEM paths for this division's cert chain + key and the federation CA bundle.
    # Empty → mTLS cannot be served even if require_mtls is set (fail loud at startup).
    tls_cert_file: str = ""
    tls_key_file: str = ""
    tls_ca_file: str = ""

    # ── Peer cluster ──────────────────────────────────────────────────────────
    peer_agent_url: AnyHttpUrl | None = None  # type: ignore[assignment]
    peer_agent_did: str = ""          # DID of the peer agent (AgentMesh identity)
    # SECURITY (signer-specific issuer binding): the Keycloak issuer that the peer
    # agent (peer_agent_did) is authorised to vouch for. A cross-division user
    # assertion is accepted ONLY if its `iss` equals this AND the envelope is
    # DID-signed by peer_agent_did. Binding the issuer to the specific signer (not
    # to the trusted-issuer SET) is what stops a compromised trusted peer from
    # asserting ANOTHER division's user. Set by scripts/federate_divisions.py.
    # (Legacy single-peer fields; M3 generalises them to peer_trust_map below.)
    peer_agent_issuer: str = ""
    # M3 multi-peer: JSON {peer_did: {issuer, public_jwk, agent_url, division_id}} — the
    # data-path trust anchor (see the `peer_trust` property). Set by federate_divisions.py.
    # Empty → a 1-entry map is synthesised from PEER_AGENT_* (back-compat, one code path).
    peer_trust_map: str = ""

    # ── LLM ───────────────────────────────────────────────────────────────────
    openai_api_base: str = "https://integrate.api.nvidia.com/v1"
    openai_api_key: str = Field(default=...)  # REQUIRED
    # llama-3.1-8b is the default: on NVIDIA NIM's free tier the 70b/3.2-3b models are
    # frequently throttled to 50-90s+ (or time out) while 3.1-8b answers reliably in
    # ~1-2s. A self-hosted/paid endpoint (M6) can move back to a larger model.
    llm_model: str = "meta/llama-3.1-8b-instruct"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 2048
    # NVIDIA NIM (the default endpoint) cold-starts: the FIRST request after idle can
    # hang 60-120s while the model loads, then warm requests are ~2-3s. The timeout must
    # exceed a cold load so a (warming) first attempt + a fast retry can complete rather
    # than the retry-storm timing out at exactly the wrong moment. Production with a
    # reliable/self-hosted endpoint (M6) can safely lower this.
    llm_timeout_seconds: float = 120.0
    llm_max_retries: int = 2
    llm_context_token_budget: int = 6000
    max_query_length: int = 4096

    # ── Retrieval backends (pluggable, multi-retriever) ───────────────────────
    # Which retrievers fan out per query; results are RRF-fused (rag/fusion.py) and
    # then EACH returned chunk_id is authorized per-user against OpenFGA in
    # check_auth — so adding retrievers never widens access. Built-ins: "qdrant",
    # "neo4j" (inert seam). External services are added via raas_endpoints below.
    # Default preserves the historical qdrant + neo4j-seam fan-out.
    retriever_backends: list[str] = ["qdrant", "neo4j"]
    # Zero or more external retrieval-as-a-service backends (each becomes a fused
    # retriever). See RaasEndpoint. Refused in residency_mode=local if the URL is
    # an external (out-of-boundary) endpoint.
    raas_endpoints: list[RaasEndpoint] = Field(default_factory=list)
    raas_timeout_seconds: float = 10.0
    # Per-retriever wall-clock bound in the retrieve_local fan-out. A retriever whose
    # backend is slow/unreachable (e.g. the Neo4j graph seam when no Neo4j is deployed)
    # degrades to [] after this, so retrieval falls back to the other backends (Qdrant)
    # WITHOUT eating the request's latency budget or failing the query. Keep it well under
    # the SRE latency budget so a dead optional backend never breaches it.
    retriever_timeout_seconds: float = 3.0

    # ── Embeddings (pluggable DENSE backend) ──────────────────────────────────
    # The DENSE embedding can run LOCAL (FastEmbed ONNX, default) or be served by an
    # OpenAI-compatible /embeddings API (e.g. NVIDIA NIM nvidia/nv-embedqa-e5-v5). The
    # 1.3GB local bge-large model must download into the pod, which fails on k8s; the
    # api provider sidesteps that by calling a served endpoint. The SPARSE BM25 vector
    # stays LOCAL in both modes (it's tiny). See rag/embeddings.py.
    embedding_provider: str = "local"   # "local" | "api"
    # API-mode endpoint + key. Empty → fall back to openai_api_base / openai_api_key
    # (the LLM endpoint) via effective_embedding_base / effective_embedding_key, so a
    # single NVIDIA NIM deployment can serve both chat and embeddings with one config.
    embedding_api_base: str = ""
    embedding_api_key: str = ""
    # Served embedding model id — used ONLY in api mode. Must emit qdrant_dense_size dims.
    embedding_model: str = "nvidia/nv-embedqa-e5-v5"
    # NVIDIA nv-embedqa is ASYMMETRIC: it REQUIRES an `input_type` ("query" | "passage")
    # and rejects a request without it (400 "'input_type' parameter is required for
    # asymmetric models"). When True (the default — the default model is asymmetric), the
    # api backend sends input_type; chunks embed as "passage", queries as "query" (using the
    # wrong type degrades retrieval). Set False for symmetric OpenAI-compatible models
    # (e.g. text-embedding-3) which don't accept input_type — then it's omitted from the body.
    embedding_asymmetric: bool = True
    # NVIDIA nv-embedqa caps input at 512 tokens and 400s on longer chunks unless told how
    # to truncate. "END" keeps the head (sent only in asymmetric/api mode). Set "" to omit
    # (symmetric OpenAI models reject the field); "NONE"/"START"/"END" per the NIM API.
    embedding_truncate: str = "END"

    # ── Qdrant ────────────────────────────────────────────────────────────────
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = Field(default="")   # optional for local instances
    qdrant_collection: str = "knowledge_base"
    # fastembed 0.8 dropped BAAI/bge-m3; bge-large-en-v1.5 is 1024-dim.
    qdrant_dense_model: str = "BAAI/bge-large-en-v1.5"
    qdrant_sparse_model: str = "Qdrant/bm25"
    qdrant_dense_size: int = 1024
    qdrant_top_k: int = 20
    qdrant_final_k: int = 10
    # Minimum dense cosine similarity for a chunk to count as relevant. Off-topic
    # chunks are dropped before authorization so they never block an answer.
    qdrant_score_threshold: float = 0.55

    # ── Reranking (optional precision stage after RRF fusion) ──────────────────
    # none → no rerank (RRF order stands); api → NIM-style /ranking endpoint; local → FastEmbed
    # cross-encoder. A reranker only REORDERS already-retrieved candidates (never widens access).
    reranker_provider: str = "none"            # "none" | "api" | "local"
    reranker_model: str = "nvidia/nv-rerankqa-mistral-4b-v3"
    reranker_api_base: str = ""                # empty → embedding_api_base / openai_api_base
    reranker_api_key: str = ""                 # empty → embedding_api_key / openai_api_key
    rerank_candidate_k: int = 20               # fused candidates fed to the reranker before top_k

    # ── Answer grounding / citations ──────────────────────────────────────────
    # require_citations: instruct the LLM to cite its sources as [Source: <name>] per claim.
    # citation_enforcement: "log" audits any citation to a source NOT in the authorized context
    # (a fabricated/hallucinated citation); "strict" also appends a transparency caveat to the
    # answer. Deterministic + auditable (no LLM judge) — a real groundedness judge is separate.
    require_citations: bool = True
    citation_enforcement: str = "log"          # "log" | "strict"

    # ── Specialized sub-agents (governed multi-agent reasoning) ────────────────
    # When enabled, generate_answer composes the answer with a team of specialist sub-agents
    # (planner -> researcher -> synthesizer -> critic) instead of one LLM call. They operate
    # ONLY on the already-authorized context (no new retrieval -> no access widening), each
    # passes the default-deny policy + is audited, and the answer still flows through output
    # DLP. Off by default (one LLM call); enabling adds LLM calls but improves complex answers.
    specialist_agents_enabled: bool = False
    max_specialist_aspects: int = 3            # cap the planner's decomposition (bounds cost)

    # ── Neo4j ─────────────────────────────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = Field(default=...)  # REQUIRED
    # reserved/unused — graph-hop expansion not implemented (the AGT retriever is a
    # plain VectorRetriever with no traversal; see rag/neo4j_retriever.py docstring).
    neo4j_graph_hops: int = 2
    neo4j_top_k: int = 5

    # ── OpenFGA (per-chunk ReBAC — data-level authorization) ─────────────────
    openfga_api_url: str = "http://localhost:8080"
    openfga_store_id: str = Field(default=...)   # REQUIRED
    openfga_model_id: str = Field(default=...)   # REQUIRED
    # Preshared key the OpenFGA server requires on every call (preshared auth).
    openfga_api_token: str = Field(default="")

    # ── Temporal ──────────────────────────────────────────────────────────────
    temporal_address: str = "localhost:7233"
    temporal_namespace: str = "default"
    temporal_task_queue: str = "approval-queue"
    approval_timeout_seconds: int = 86400
    # FR-7.1 access lifecycle: TTL (seconds) applied to a grant created by an APPROVAL.
    # 0 = permanent (legacy behaviour); >0 = the approved viewer grant expires after this
    # window via the OpenFGA `non_expired` conditional tuple, so the requester must
    # re-ask (and re-enter approval) once it lapses. Default 0 to preserve behaviour.
    approval_grant_ttl_seconds: int = 0

    # ── OIDC / JWT — user authentication (Keycloak) ───────────────────────────
    # AGT handles agent-to-agent identity via DIDs.
    # Keycloak handles *user* login; we still validate user JWTs here.
    oidc_issuer: str = "https://keycloak.internal/realms/rag"
    oidc_jwks_uri: str = "https://keycloak.internal/realms/rag/protocol/openid-connect/certs"
    allowed_jwt_algorithms: str = "RS256,ES256"
    agent_client_id: str = Field(default=...)    # REQUIRED — Keycloak client ID for this agent
    agent_client_secret: str = Field(default=...) # REQUIRED

    # ── Identity claim mapping (template: works against ANY OIDC IdP) ──────────
    # The authorization SUBJECT claim. Default "email" (Keycloak). Entra ID often
    # uses "preferred_username"/"upn"; Okta uses "email". The principal becomes
    # "<claim-value>|<issuer-namespace>" so per-IdP token shapes work with no code change.
    principal_claim: str = "email"
    # Whether to require the email_verified flag. Email-specific; some IdPs (Entra)
    # omit it. Default true (the hardened Keycloak posture). Set false when the chosen
    # principal_claim is not an email or the IdP does not emit email_verified.
    require_verified_principal: bool = True
    # Token claim carrying the user's group/role memberships (a list, or a single
    # string). Maps IdP groups (AD/Entra/Okta) to OpenFGA `group#member` usersets so a
    # user gets a group's baseline document access with NO per-user tuple — and loses it
    # the moment the IdP drops them from the group (membership is sourced live from the
    # token as a contextual tuple, never persisted). Empty value/claim = no group grants.
    groups_claim: str = "groups"
    # Optional ALLOWLIST of group names this division recognises (CSV). When set, any group
    # in the token NOT on this list is dropped before it can grant access — defence against
    # a misconfigured IdP mapper or a user-influenced group claim escalating privilege.
    # Empty = accept every group the (trusted) IdP asserts (back-compat).
    recognized_groups: str = ""

    # ── AgentMesh (Microsoft Agent Governance Toolkit — agent identity) ───────
    # Each agent has a DID (Decentralized Identifier) with Ed25519 credentials,
    # created via agentmesh.AgentIdentity.create() on first run.
    # agent_sponsor_email is the human sponsor bound to the DID — the toolkit
    # requires every agent identity to name a human sponsor.
    agent_sponsor_email: str = Field(default=...)  # REQUIRED — human sponsor email
    agent_mesh_registry_url: str = "http://localhost:9000"  # AgentMesh registry
    agent_trust_threshold: float = 0.6        # minimum trust score (0.0–1.0) to accept peer messages
    # Path to the persisted identity JWKS (private key). Mount as a Kubernetes
    # Secret volume so the DID is stable across restarts / pod replacements.
    # If empty, an ephemeral identity is created each start (dev only).
    agent_identity_path: str = ""
    # Peer's public-key JWK (JSON string) — used by verify_signed_message() to
    # verify the Ed25519 signature on inbound peer callbacks. Obtain it from the
    # peer's GET /identity endpoint at setup time (alongside PEER_AGENT_DID).
    peer_agent_public_jwk: str = ""

    # ── MCP tool servers (Phase-1 item 11) ───────────────────────────────────
    # JSON list of allowed MCP servers, e.g.
    #   [{"name":"jira","url":"https://mcp.corp/jira","allowed_auth_methods":["oauth2"],
    #     "require_tls":true,"auth_mode":"oauth_obo"}]
    #   (valid allowed_auth_methods: oauth2, bearer, api_key, mtls, none)
    # Empty = no MCP servers (the default). The toolkit's McpAuthPolicy gateway enforces
    # the per-server allowlist + required auth method; the policy engine's default-deny
    # blocks any mcp.call to a server/tool not explicitly allowed. The user's RAW token is
    # NEVER relayed (M2 lesson) — per-server auth_mode selects token-exchange or a
    # service credential with agent-side ReBAC mediation.
    mcp_servers: str = ""

    # ── Cross-agent tool delegation (/a2a/tool) ──────────────────────────────
    # When an agent faces a sub-problem needing a TOOL capability it lacks, it can
    # discover a peer advertising that capability and securely delegate the TOOL CALL
    # over the DID-signed /a2a/tool channel (the peer runs ITS governed tool and returns
    # a DID-signed result). This mirrors the /a2a/query envelope exactly (signature →
    # trust → recipient-bound assertion → policy → governed execution → signed reply).
    #   * tool_delegation_enabled — master switch for the orchestrator's delegate branch.
    #     When False, solve_with_tools never reaches across the mesh: a missing-local
    #     capability degrades gracefully instead of delegating. The /a2a/tool RECEIVE
    #     endpoint is governed independently (signature + policy) and is not gated by this.
    #   * max_tool_delegations — hard cap on cross-agent tool hops per solve_with_tools
    #     call (runaway / delegation-loop guard, ASI-07/ASI-08 spirit). Each delegated tool
    #     call counts once; exceeding the cap degrades gracefully (no further delegation).
    tool_delegation_enabled: bool = True
    max_tool_delegations: int = 3

    # peer_tool_map — CONFIGURED (broker-less) capability → peer-DID ROUTING TABLE. A JSON
    # object mapping EACH tool capability to the DID of the trusted peer that serves it; a
    # division serves some capabilities LOCALLY (AGT_LOCAL_TOOLS) and routes the OTHERS to
    # peers — and DIFFERENT capabilities can route to DIFFERENT peers, e.g.
    #   PEER_TOOL_MAP={"tool.compliance":"did:mesh:division-b","tool.risk":"did:mesh:division-c"}
    # This lets a template Kubernetes deployment do cross-agent tool delegation with NO extra
    # discovery-broker service: when no broker is configured (or it is unreachable / returns
    # nothing), find_peer_for_capability looks the SPECIFIC capability up here to learn WHICH
    # trusted peer serves it. SECURITY — this map only names the peer DID; the peer's agent_url
    # and division ALWAYS come from the operator-curated `peer_trust` anchor keyed on that DID,
    # so an entry can only route to an already-trusted partner (a DID not in peer_trust resolves
    # to nothing — never a fabricated peer). Empty (default) → configured routing is off and
    # delegation relies on the discovery broker alone.
    peer_tool_map: str = ""

    # ── AGT Policy Engine (Agent OS) ─────────────────────────────────────────
    # Path to YAML policy directory (loaded at startup). The default is anchored to
    # this file, not the CWD, so an installed wheel (or any launch dir) finds the
    # shipped policies instead of loading zero rules and denying every action.
    policy_dir: str = str(Path(__file__).resolve().parent / "agent" / "policies")
    # Whether to run in audit-only mode (log violations but don't block).
    policy_audit_only: bool = False
    # Mosaic-effect guard (agent/context_guard.py): YAML rules over the COMBINATION of
    # authorized chunks, evaluated after check_auth's per-chunk authz and before
    # llm.generate. Default anchored like policy_dir; a relative override resolves to the
    # package root. Missing/invalid file → fail-closed (answer withheld). Empty string
    # disables the guard explicitly.
    context_aggregation_policy: str = str(
        Path(__file__).resolve().parent / "agent" / "policies" / "aggregation"
        / "context-aggregation.yaml")

    # ── Graph-level kill-switch (AgentMesh govern_action gate) ───────────────
    # Operator emergency off-switch. When true, the graph-level govern_action
    # gate in agent.graph.run_query DENIES every invocation (raises PermissionError
    # before any node runs / before the graph is compiled), disabling this agent's
    # /query and /a2a/query paths entirely. The denial currently surfaces as an SSE
    # error event (/query, stream is already HTTP 200) / a signed status="failed"
    # (/a2a/query) — not a 403 — unless the endpoints also check this flag before
    # streaming. Default false = normal
    # operation. This is a DEPLOY-TIME lever: settings is read once at startup, so
    # changing AGENT_KILL_SWITCH_ENGAGED requires an agent RESTART to take effect.
    # It is NOT an automatic trust-based trip (see mesh/agent_identity.py
    # _GRAPH_GOVERNANCE_POLICY) and does NOT replace the fail-closed data-path
    # controls (per-node _enforce default-deny + OpenFGA per-chunk ReBAC).
    agent_kill_switch_engaged: bool = False

    # ── AGT Agent SRE ─────────────────────────────────────────────────────────
    sre_enabled: bool = True
    sre_slo_latency_p99_ms: float = 5000.0    # 5-second p99 latency SLO
    sre_error_budget_percent: float = 0.1      # 0.1% error budget

    # ── Approval deep-link HMAC ───────────────────────────────────────────────
    approval_hmac_secret: str = Field(default=...)  # REQUIRED — random 32-byte hex

    # ── Redis task store ──────────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"
    task_ttl_seconds: int = 86400

    # ── Artifact (object/blob) storage ────────────────────────────────────────
    # Durable sink for finished outputs (exported evidence packs, reports, uploads). Keys are
    # namespaced by division_id so a shared bucket stays tenant-isolated. See artifact_store.py.
    artifact_backend: str = "local"            # "local" | "s3"
    artifact_local_dir: str = "./artifacts"    # local backend root
    artifact_s3_bucket: str = ""               # required for the s3 backend
    artifact_s3_endpoint: str = ""             # set for MinIO / non-AWS S3; empty = AWS
    artifact_s3_region: str = "us-east-1"
    artifact_s3_access_key: str = ""           # empty → boto3 default credential chain (env/IAM)
    artifact_s3_secret_key: str = ""

    # ── Notifications ─────────────────────────────────────────────────────────
    slack_bot_token: str | None = None
    slack_approval_channel: str = "#approvals"
    approval_ui_base_url: str = "http://localhost:8000"
    # Generic outbound webhook for parked approvals (ops/SIEM/automation). Fires IN ADDITION
    # to slack/email. The payload is DATA-MINIMIZED on purpose — request id, approver, the
    # signed deep-link, timestamp — and deliberately carries NO query text or chunk ids, so an
    # external endpoint never receives the sensitive content the approval is gating.
    notify_webhook_url: str = ""

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    max_request_body_bytes: int = 1_048_576
    # Finding #7: per-subject (JWT sub) fixed-window rate limit for the
    # expensive /query endpoint (retrieval fan-out + LLM call per request).
    rate_limit_per_minute: int = 60
    # Per-PEER (sender DID) fixed-window limit on the DID-signed federation endpoints
    # (/a2a/query, /a2a/tool). Bounds a compromised-but-trusted peer from driving unbounded
    # LLM/tool cost through federation (a per-user limit is evadable — a peer can rotate
    # user_ids). More generous than the per-user limit since one peer fronts many users.
    peer_rate_limit_per_minute: int = 600

    # /metrics scrape protection. When set, GET /metrics requires this bearer token (so the
    # governance event counters aren't world-readable recon). Empty = open (dev default);
    # production sets METRICS_TOKEN and scrapes with `Authorization: Bearer <token>`.
    metrics_token: str = ""

    # ── BFF browser session (production auth: no token in the browser) ─────────
    # The browser holds only this opaque HttpOnly cookie; tokens live server-side in Redis.
    bff_cookie_name: str = "__Host-agtsession"
    bff_cookie_secure: bool = True            # required for __Host- prefix; browsers allow it on localhost
    bff_session_ttl_seconds: int = 28800      # 8h absolute session lifetime
    bff_client_id: str = "rag-ui"             # public client + server-side PKCE
    # The browser-facing origin the BFF redirect_uri is built from (must be a registered
    # rag-ui redirect URI). Dev: the Vite origin; prod: the division's edge origin.
    bff_public_base_url: str = "http://localhost:5173"
    bff_post_login_redirect: str = "/"        # where to send the browser after login

    # CORS — comma-separated list of allowed origins (str, not list[str], so that
    # operators can set the env var as a plain comma-separated string without
    # needing JSON escaping, matching the convention used by other list settings).
    # Dev default: Vite's local dev server.  In production set CORS_ORIGINS to
    # the actual UI origin, e.g. "https://rag.example.com".
    cors_origins: str = "http://localhost:5173"

    @property
    def effective_embedding_base(self) -> str:
        """API-mode embedding base URL — embedding_api_base, or openai_api_base when unset
        (so one NVIDIA NIM endpoint serves both chat + embeddings with no extra config)."""
        return (self.embedding_api_base or self.openai_api_base).rstrip("/")

    @property
    def effective_embedding_key(self) -> str:
        """API-mode embedding bearer key — embedding_api_key, or openai_api_key when unset."""
        return self.embedding_api_key or self.openai_api_key

    @property
    def cors_origins_list(self) -> list[str]:
        return [s.strip() for s in self.cors_origins.split(",") if s.strip()]

    @property
    def allowed_jwt_algorithms_list(self) -> list[str]:
        return [s.strip() for s in self.allowed_jwt_algorithms.split(",") if s.strip()]

    @property
    def trusted_peers_list(self) -> list[str]:
        return [s.strip() for s in self.trusted_peers.split(",") if s.strip()]

    @property
    def recognized_groups_set(self) -> set[str]:
        """Allowlisted group names (empty set = accept all the IdP asserts)."""
        return {s.strip() for s in self.recognized_groups.split(",") if s.strip()}

    @property
    def peer_trust(self) -> dict:
        """M3 multi-peer DATA-PATH trust anchor: ``{peer_did: {issuer, public_jwk,
        agent_url, division_id}}``. This — NOT the open discovery registry — is what a
        division trusts for cross-division calls: verify_signed_message accepts a signer
        only if its DID is a key here, and assertion_principal binds the asserted issuer
        to THIS entry's issuer (per-DID, so a peer can only assert its OWN users).

        ONE code path: if PEER_TRUST_MAP is unset, fall back to a 1-entry map synthesised
        from the legacy single PEER_AGENT_* config (back-compat), so callers never branch."""
        import json
        raw = self.peer_trust_map.strip()
        if raw:
            try:
                m = json.loads(raw)
                return m if isinstance(m, dict) else {}
            except Exception:
                return {}
        if self.peer_agent_did:
            return {self.peer_agent_did: {
                "issuer": self.peer_agent_issuer,
                "public_jwk": self.peer_agent_public_jwk,
                "agent_url": str(self.peer_agent_url or ""),
                "division_id": "",
            }}
        return {}

    @property
    def peer_tool_map_dict(self) -> dict:
        """Parsed PEER_TOOL_MAP: ``{tool_capability: peer_did}`` for broker-less, CONFIGURED
        capability routing. A malformed value parses to ``{}`` (configured routing off) so a
        bad env var degrades gracefully rather than crashing — the broker path still applies.
        The peer_did here is only a SELECTOR; the peer's url/division come from `peer_trust`."""
        import json
        raw = self.peer_tool_map.strip()
        if not raw:
            return {}
        try:
            m = json.loads(raw)
            return m if isinstance(m, dict) else {}
        except Exception:
            return {}

    @property
    def trusted_issuers_list(self) -> list[str]:
        return [s.strip() for s in self.trusted_issuers.split(",") if s.strip()]

    @model_validator(mode="after")
    def resolve_secret_refs(self) -> "Settings":
        # Phase-1 item 14: resolve any setting whose value is a `vault:path#field` reference
        # via the configured secrets backend. No-op for the default env-file deployment
        # (no values are refs), so this is free and safe. Fails loud if a ref can't resolve.
        try:
            from secrets_backend import is_ref, resolve_secret, get_backend
        except Exception:
            return self
        refs = {n: v for n, v in self.__dict__.items() if isinstance(v, str) and is_ref(v)}
        if not refs:
            return self
        be = get_backend()
        for name, value in refs.items():
            object.__setattr__(self, name, resolve_secret(value, be))
        return self

    @model_validator(mode="after")
    def default_division_id(self) -> "Settings":
        # Back-compat: a single-cluster .env that sets only CLUSTER_ID still gets a
        # division_id (so tenancy threading never sees an empty division).
        if not self.division_id:
            object.__setattr__(self, "division_id", self.cluster_id)
        return self

    @model_validator(mode="after")
    def embedder_aware_score_threshold(self) -> "Settings":
        # The cosine scale differs by embedder: bge-large (local) scores relevant chunks
        # ~0.55, while the served asymmetric nv-embedqa-e5-v5 (api) scores them ~0.30. If api
        # mode is on and the operator did NOT explicitly set a threshold, lower the default to
        # a model-appropriate 0.25 — otherwise the bge-tuned 0.55 default silently drops every
        # real hit and answers come back empty. An explicit QDRANT_SCORE_THRESHOLD is honored.
        if (self.embedding_provider == "api"
                and "qdrant_score_threshold" not in self.model_fields_set):
            object.__setattr__(self, "qdrant_score_threshold", 0.25)
        return self

    @model_validator(mode="after")
    def warn_peer_missing_did(self) -> "Settings":
        if self.peer_agent_url and not self.peer_agent_did:
            import warnings
            warnings.warn(
                "peer_agent_url is set but peer_agent_did is empty — "
                "AgentMesh cannot verify the peer agent's identity. "
                "Set PEER_AGENT_DID to the peer's registered DID.",
                stacklevel=2,
            )
        if self.peer_agent_url and not self.peer_agent_public_jwk:
            import warnings
            warnings.warn(
                "peer_agent_url is set but peer_agent_public_jwk is empty — "
                "inbound peer callbacks cannot be signature-verified and will "
                "ALL be rejected. Set PEER_AGENT_PUBLIC_JWK to the peer's public "
                "key JWK (from the peer's GET /identity endpoint).",
                stacklevel=2,
            )
        return self


settings = Settings()
