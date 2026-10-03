from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SignalHound"
    environment: str = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://signalhound:signalhound@localhost:5432/signalhound"
    redis_url: str = "redis://localhost:6379/0"
    scanner_execution_enabled: bool = False
    segmentation_execution_enabled: bool = False
    segmentation_sources_json: str = "[]"
    node_execution_enabled: bool = False
    node_allow_insecure_loopback: bool = False
    intelligence_enabled: bool = False
    scanner_timeout_seconds: int = Field(default=300, ge=5, le=1800)
    cors_origins: str = "http://localhost:8011"
    max_request_body_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    celery_worker_concurrency: int = Field(default=1, ge=1, le=4)
    celery_task_time_limit_seconds: int = Field(default=900, ge=30, le=3600)
    celery_task_soft_time_limit_seconds: int = Field(default=840, ge=30, le=3540)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @model_validator(mode="after")
    def validate_security_defaults(self) -> "Settings":
        if self.environment.lower() in {"production", "prod"} and "*" in self.cors_origin_list:
            raise ValueError("Wildcard CORS origins are not allowed in production")
        if self.celery_task_soft_time_limit_seconds >= self.celery_task_time_limit_seconds:
            raise ValueError("Celery soft time limit must be lower than the hard time limit")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
