"""
Central configuration for ECHOBOUND.
All values can be overridden via environment variables so the platform can
run the same way in dev, staging and production without code changes.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    # --- Identity / product ---
    product_name: str = "ECHOBOUND"
    environment: str = os.getenv("ECHOBOUND_ENV", "development")

    # --- Storage ---
    sqlite_path: str = os.getenv("ECHOBOUND_DB", "echobound.db")
    postgres_dsn: str = os.getenv("ECHOBOUND_POSTGRES_DSN", "")
    object_storage_path: str = os.getenv("ECHOBOUND_ARCHIVE_DIR", "./archive")

    # --- Messaging / cache (interfaces are provider-independent, see
    #     echobound.streaming and echobound.cache abstractions) ---
    kafka_bootstrap: str = os.getenv("ECHOBOUND_KAFKA_BOOTSTRAP", "")
    nats_url: str = os.getenv("ECHOBOUND_NATS_URL", "")
    redis_url: str = os.getenv("ECHOBOUND_REDIS_URL", "")

    # --- API / Auth ---
    api_host: str = os.getenv("ECHOBOUND_API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("ECHOBOUND_API_PORT", "8088"))
    jwt_secret: str = os.getenv("ECHOBOUND_JWT_SECRET", "change-me-in-production")
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = int(os.getenv("ECHOBOUND_JWT_TTL_MIN", "480"))
    oidc_issuer: str = os.getenv("ECHOBOUND_OIDC_ISSUER", "")
    oidc_client_id: str = os.getenv("ECHOBOUND_OIDC_CLIENT_ID", "")

    # --- Multi-tenancy ---
    default_tenant: str = os.getenv("ECHOBOUND_DEFAULT_TENANT", "default")

    # --- Boundary memory tuning ---
    decay_half_life_days: float = float(os.getenv("ECHOBOUND_DECAY_HALF_LIFE_DAYS", "45"))
    candidate_promotion_min_observations: int = int(
        os.getenv("ECHOBOUND_CANDIDATE_MIN_OBS", "5")
    )
    candidate_promotion_min_span_hours: float = float(
        os.getenv("ECHOBOUND_CANDIDATE_MIN_SPAN_HOURS", "12")
    )
    dormant_after_days: int = int(os.getenv("ECHOBOUND_DORMANT_AFTER_DAYS", "30"))
    historical_after_days: int = int(os.getenv("ECHOBOUND_HISTORICAL_AFTER_DAYS", "90"))
    expired_after_days: int = int(os.getenv("ECHOBOUND_EXPIRED_AFTER_DAYS", "365"))

    # --- Query cost guard ---
    query_default_timeout_s: float = float(os.getenv("ECHOBOUND_QUERY_TIMEOUT_S", "8"))
    query_max_depth: int = int(os.getenv("ECHOBOUND_QUERY_MAX_DEPTH", "6"))
    query_max_results: int = int(os.getenv("ECHOBOUND_QUERY_MAX_RESULTS", "5000"))

    # --- Agent resource guard ---
    agent_max_events_per_sec: int = int(os.getenv("ECHOBOUND_AGENT_MAX_EPS", "20000"))
    agent_ring_buffer_pages: int = int(os.getenv("ECHOBOUND_AGENT_RB_PAGES", "256"))

    # --- Local AI ---
    local_ai_enabled: bool = _env_bool("ECHOBOUND_LOCAL_AI_ENABLED", True)
    local_ai_endpoint: str = os.getenv("ECHOBOUND_LOCAL_AI_ENDPOINT", "")  # e.g. Ollama http://localhost:11434
    local_ai_allow_external: bool = _env_bool("ECHOBOUND_LOCAL_AI_ALLOW_EXTERNAL", False)

    # --- Privacy ---
    privacy_hash_salt: str = os.getenv("ECHOBOUND_PRIVACY_SALT", "echobound-static-salt-change-me")
    collect_raw_payloads: bool = _env_bool("ECHOBOUND_COLLECT_RAW_PAYLOADS", False)


settings = Settings()
