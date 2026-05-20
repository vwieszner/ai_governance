"""Central configuration — loaded once at startup from environment / .env file."""
from __future__ import annotations  # PY-12: enables plain class name in return annotations

from pydantic import AnyHttpUrl, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# N3-4: _REQUIRED_SECRETS was a dead constant — never read at runtime.
# Enforcement is handled by Field(default=...) on each secret field, which
# causes Pydantic to raise ValidationError at startup if the env var is unset.


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Cluster identity
    cluster_id: str = "cluster-a"
    agent_name: str = "RAG Agent"
    agent_url: AnyHttpUrl = Field(default="http://localhost:8000")  # type: ignore[assignment]

    # Peer cluster
    peer_agent_url: AnyHttpUrl | None = None  # type: ignore[assignment]
    peer_agent_card_url: AnyHttpUrl | None = None  # type: ignore[assignment]
    # FIX Q-4: if peer_agent_url is set and this is empty, callback auth is disabled.
    # Must be set in production whenever peer_agent_url is configured.
    # Comma-separated list of allowed peer agent OAuth client IDs for callback auth.
    peer_agent_client_ids: str = ""

    # LLM — NVIDIA NIM (OpenAI-compatible)
    openai_api_base: str = "https://integrate.api.nvidia.com/v1"
    openai_api_key: str = Field(default=...)  # REQUIRED — set OPENAI_API_KEY in .env
    llm_model: str = "nvidia/llama-3.1-nemotron-70b-instruct"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 2048
    llm_context_token_budget: int = 6000     # max tokens of context fed to LLM (M-4)
    max_query_length: int = 4096             # max chars for user query input

    # Qdrant
    qdrant_url: str = "http://localhost:6333"
    # NIT-4: empty string is the correct sentinel — qdrant_retriever does `or None`
    # to convert it to None for unauthenticated local Qdrant instances.
    # Field(default=...) would force every developer to set the env var even when
    # running against a local container with no API key configured.
    qdrant_api_key: str = Field(default="")   # optional — set for managed Qdrant Cloud
    qdrant_collection: str = "knowledge_base"
    qdrant_dense_model: str = "BAAI/bge-m3"   # 1024-dim
    qdrant_sparse_model: str = "Qdrant/bm25"
    qdrant_dense_size: int = 1024              # must match model output dim
    qdrant_top_k: int = 20
    qdrant_final_k: int = 10

    # Neo4j / GraphRAG
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = Field(default=...)  # REQUIRED — set NEO4J_PASSWORD in .env
    neo4j_graph_hops: int = 2
    neo4j_top_k: int = 5

    # OpenFGA
    openfga_api_url: str = "http://localhost:8080"
    openfga_store_id: str = Field(default=...)   # REQUIRED — run scripts/setup-openfga.py
    openfga_model_id: str = Field(default=...)   # REQUIRED

    # Temporal
    temporal_address: str = "localhost:7233"
    temporal_namespace: str = "default"
    temporal_task_queue: str = "approval-queue"
    approval_timeout_seconds: int = 86400        # 24 h

    # OIDC / JWT
    oidc_issuer: str = "https://keycloak.internal/realms/rag"
    oidc_jwks_uri: str = "https://keycloak.internal/realms/rag/protocol/openid-connect/certs"
    oidc_token_endpoint: str = "https://keycloak.internal/realms/rag/protocol/openid-connect/token"
    agent_client_id: str = Field(default=...)    # REQUIRED
    agent_client_secret: str = Field(default=...) # REQUIRED
    # FIX S-5: lock to your IdP's actual algorithm. If Keycloak is RS256-only,
    # change to "RS256" to prevent ES256-keyed token forgery.
    allowed_jwt_algorithms: str = "RS256,ES256"  # comma-separated

    # Approval endpoint — HMAC signing key for approve/deny deep-links (C-2)
    approval_hmac_secret: str = Field(default=...)  # REQUIRED — random 32-byte hex

    # Redis — task store (replaces in-memory dict)
    redis_url: str = "redis://redis:6379/0"
    task_ttl_seconds: int = 86400               # 24 h — tasks expire from Redis

    # Notifications
    # GQ-8: str | None = None is cleaner than str = "" — callers can `if settings.slack_bot_token`
    # without ambiguity between "not configured" and "configured but empty".
    slack_bot_token: str | None = None
    slack_approval_channel: str = "#approvals"
    approval_ui_base_url: str = "http://localhost:8000"

    # Observability
    langfuse_secret_key: str = ""
    langfuse_public_key: str = ""
    langfuse_host: str = "https://cloud.langfuse.com"
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_service_name: str = "federated-rag-agent"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    max_request_body_bytes: int = 1_048_576     # 1 MB (M-3 / S-1)

    @property
    def peer_agent_client_ids_list(self) -> list[str]:
        return [s.strip() for s in self.peer_agent_client_ids.split(",") if s.strip()]

    @property
    def allowed_jwt_algorithms_list(self) -> list[str]:
        return [s.strip() for s in self.allowed_jwt_algorithms.split(",") if s.strip()]

    @model_validator(mode="after")
    def warn_peer_client_ids(self) -> Settings:  # PY-12: no forward ref needed; add `from __future__ import annotations` instead
        """Warn at startup if a peer URL is configured but no peer client IDs are set."""
        if self.peer_agent_url and not self.peer_agent_client_ids_list:
            import warnings
            warnings.warn(
                "peer_agent_url is set but peer_agent_client_ids is empty — "
                "the /tasks/{id}/callback endpoint will reject ALL peer callbacks. "
                "Set PEER_AGENT_CLIENT_IDS to the peer's OAuth client_id.",
                stacklevel=2,
            )
        return self


settings = Settings()
