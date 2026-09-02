from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Data Security Toolbox"
    app_env: str = "development"
    secret_key: str = ""
    database_url: str = "sqlite:///./data/security_toolbox.db"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    storage_dir: Path = Path("./data/storage")
    report_dir: Path = Path("./data/reports")
    external_engine_dir: Path = Path("./data/external")
    max_upload_mb: int = 2048
    probe_token: str = ""
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def ensure_dirs(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.external_engine_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_dirs()
    return settings


settings = get_settings()
