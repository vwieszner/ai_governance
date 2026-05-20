"""Central configuration — loaded once at startup from environment / .env file."""
from __future__ import annotations

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Cluster identity
    cluster_id: str = "cluster-a"
    agent_name: str = "RAG Agent"
    agent_url: AnyHttpUrl = Field(default="http://localhost:8000")  # type: ignore[assignment]

    # Peer cluster
    peer_agent_url: AnyHttpUrl | None = None  # type: ignore[assignment]
    peer_agent_card_url: AnyHttpUrl | None = None  # type: ignore[assignment]

    # LLM — NVIDIA NIM (OpenAI-compatible)
    openai_api_base: str = "https://integrate.api.nvidia.com/v1"
    openai_api_key: str = "nvapi-change-me"
    llm_model: str = "nvidia/llama-3.1-nemotron-70b-instruct"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 2048

    # Qdrant
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = ""
    qdrant_collection: str = "knowledge_base"
    qdrant_dense_model: str = "BAAI/bge-m3"        # FastEmbed dense
    qdrant_sparse_model: str = "Qdrant/bm25"        # FastEmbed sparse
    qdrant_top_k: int = 20                           # per retriever before fusion
    qdrant_final_k: int = 10                         # after RRF fusion

    # Neo4j / GraphRAG
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"
    neo4j_graph_hops: int = 2                        # subgraph expansion depth
    neo4j_top_k: int = 5                             # entities/subgraph nodes

    # OpenFGA
    openfga_api_url: str = "http://localhost:8080"
    openfga_store_id: str = ""
    openfga_model_id: str = ""

    # Temporal
    temporal_address: str = "localhost:7233"
    temporal_namespace: str = "default"
    temporal_task_queue: str = "approval-queue"
    approval_timeout_seconds: int = 86400            # 24 h

    # OIDC / JWT
    oidc_issuer: str = "https://keycloak.internal/realms/rag"
    oidc_jwks_uri: str = "https://keycloak.internal/realms/rag/protocol/openid-connect/certs"
    oidc_token_endpoint: str = "https://keycloak.internal/realms/rag/protocol/openid-connect/token"
    agent_client_id: str = "agent"
    agent_client_secret: str = "secret"

    # Notifications
    slack_bot_token: str = ""
    slack_approval_channel: str = "#approvals"
    approval_ui_base_url: str = "http://localhost:8000"

    # Observability
    langfuse_secret_key: str = ""
    langfuse_public_key: str = ""
    langfuse_host: str = "https://cloud.langfuse.com"
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"


settings = Settings()
