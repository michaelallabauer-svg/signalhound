from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SignalHound"
    environment: str = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://signalhound:signalhound@localhost:5432/signalhound"
    redis_url: str = "redis://localhost:6379/0"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

