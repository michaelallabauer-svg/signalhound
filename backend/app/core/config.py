from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SignalHound"
    environment: str = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://signalhound:signalhound@localhost:5432/signalhound"
    redis_url: str = "redis://localhost:6379/0"
    scanner_execution_enabled: bool = False
    scanner_timeout_seconds: int = 300
    cors_origins: str = "http://localhost:8011"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
