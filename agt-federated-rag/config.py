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
    llm_context_token_budget: int = 6000
    max_query_length: int = 4096

    # ── Qdrant ────────────────────────────────────────────────────────────────
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = Field(default="")   # optional for local instances
    qdrant_collection: str = "knowledge_base"
    qdrant_dense_model: str = "BAAI/bge-m3"
    qdrant_sparse_model: str = "Qdrant/bm25"
    qdrant_dense_size: int = 1024
    qdrant_top_k: int = 20
    qdrant_final_k: int = 10

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

    # ── AgentMesh (AGT agent identity) ────────────────────────────────────────
    # Each agent has a DID (Decentralized Identifier) with Ed25519 credentials.
    # The DID is created on first run and persisted; subsequent runs load it.
    agent_did_seed: str = Field(default=...)  # REQUIRED — 32-byte hex seed for DID key
    agent_mesh_registry_url: str = "http://localhost:9000"  # local mesh registry
    agent_trust_threshold: float = 0.6        # minimum trust score (0.0–1.0) to accept peer messages

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
        return self


settings = Settings()
