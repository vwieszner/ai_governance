"""Central configuration — loaded once at startup from environment / .env file."""
from __future__ import annotations

from pydantic import AnyHttpUrl, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Cluster identity ──────────────────────────────────────────────────────
    cluster_id: str = "cluster-a"
    agent_name: str = "AGT RAG Agent"
    agent_url: AnyHttpUrl = Field(default="http://localhost:8000")  # type: ignore[assignment]

    # ── Peer cluster ──────────────────────────────────────────────────────────
    peer_agent_url: AnyHttpUrl | None = None  # type: ignore[assignment]
    peer_agent_did: str = ""          # DID of the peer agent (AgentMesh identity)

    # ── LLM ───────────────────────────────────────────────────────────────────
    openai_api_base: str = "https://integrate.api.nvidia.com/v1"
    openai_api_key: str = Field(default=...)  # REQUIRED
    llm_model: str = "nvidia/llama-3.1-nemotron-70b-instruct"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 2048
    # Generous timeout + retries for the slow NVIDIA cold-connect (see federated-rag).
    llm_timeout_seconds: float = 60.0
    llm_max_retries: int = 2
    llm_context_token_budget: int = 6000
    max_query_length: int = 4096

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

    # ── Neo4j ─────────────────────────────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = Field(default=...)  # REQUIRED
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

    # ── OIDC / JWT — user authentication (Keycloak) ───────────────────────────
    # AGT handles agent-to-agent identity via DIDs.
    # Keycloak handles *user* login; we still validate user JWTs here.
    oidc_issuer: str = "https://keycloak.internal/realms/rag"
    oidc_jwks_uri: str = "https://keycloak.internal/realms/rag/protocol/openid-connect/certs"
    allowed_jwt_algorithms: str = "RS256,ES256"
    agent_client_id: str = Field(default=...)    # REQUIRED — Keycloak client ID for this agent
    agent_client_secret: str = Field(default=...) # REQUIRED

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

    # ── AGT Policy Engine (Agent OS) ─────────────────────────────────────────
    # Path to YAML policy directory (loaded at startup).
    policy_dir: str = "agent/policies"
    # Whether to run in audit-only mode (log violations but don't block).
    policy_audit_only: bool = False

    # ── AGT Agent SRE ─────────────────────────────────────────────────────────
    sre_enabled: bool = True
    sre_slo_latency_p99_ms: float = 5000.0    # 5-second p99 latency SLO
    sre_error_budget_percent: float = 0.1      # 0.1% error budget

    # ── Approval deep-link HMAC ───────────────────────────────────────────────
    approval_hmac_secret: str = Field(default=...)  # REQUIRED — random 32-byte hex

    # ── Redis task store ──────────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"
    task_ttl_seconds: int = 86400

    # ── Notifications ─────────────────────────────────────────────────────────
    slack_bot_token: str | None = None
    slack_approval_channel: str = "#approvals"
    approval_ui_base_url: str = "http://localhost:8000"

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    max_request_body_bytes: int = 1_048_576
    # Finding #7: per-subject (JWT sub) fixed-window rate limit for the
    # expensive /query endpoint (retrieval fan-out + LLM call per request).
    rate_limit_per_minute: int = 60

    # CORS — comma-separated list of allowed origins (str, not list[str], so that
    # operators can set the env var as a plain comma-separated string without
    # needing JSON escaping, matching the convention used by other list settings).
    # Dev default: Vite's local dev server.  In production set CORS_ORIGINS to
    # the actual UI origin, e.g. "https://rag.example.com".
    cors_origins: str = "http://localhost:5173"

    @property
    def cors_origins_list(self) -> list[str]:
        return [s.strip() for s in self.cors_origins.split(",") if s.strip()]

    @property
    def allowed_jwt_algorithms_list(self) -> list[str]:
        return [s.strip() for s in self.allowed_jwt_algorithms.split(",") if s.strip()]

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
