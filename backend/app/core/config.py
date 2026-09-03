from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Data Security Toolbox"
    app_env: str = "development"
    secret_key: str = ""
    admin_username: str = "admin"
    admin_password: str = ""
    cookie_name: str = "dst_admin_session"
    cookie_secure: bool = False
    database_url: str = "sqlite:///./data/security_toolbox.db"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    storage_dir: Path = Path("./data/storage")
    report_dir: Path = Path("./data/reports")
    external_engine_dir: Path = Path("./data/external")
    integration_dir: Path = Path("./data/integrations")
    offline_dir: Path = Path("./data/offline")
    misp_url: str = ""
    misp_api_key: str = ""
    wazuh_url: str = ""
    osquery_socket: str = ""
    max_upload_mb: int = 2048
    probe_token: str = ""
    probe_bootstrap_token: str = ""
    pcap_index_limit: int = 10000
    pcap_retention_days: int = 7
    pcap_storage_max_gb: int = 100
    presidio_enabled: bool = True
    alert_suppress_window_seconds: int = 300
    alert_delivery_max_attempts: int = 3
    alert_policy: dict[str, object] = {
        "critical_finding_immediate": True,
        "high_finding_min_risk": 60,
        "critical_incident_immediate": True,
        "high_incident_min_risk": 60,
        "medium_notify": False,
    }
    webhook_url: str = ""
    webhook_secret: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    queue_pending_max: int = 200
    queue_oldest_pending_seconds: int = 900
    state_ttl_seconds: int = 120
    port_scan_ports_threshold: int = 20
    port_scan_window_seconds: int = 60
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def ensure_dirs(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.external_engine_dir.mkdir(parents=True, exist_ok=True)
        self.integration_dir.mkdir(parents=True, exist_ok=True)
        self.offline_dir.mkdir(parents=True, exist_ok=True)

    def validate_production(self) -> None:
        if self.app_env != "production":
            return
        weak_values = {"", "changeit", "changeme", "changeme123!", "security", "password", "secret", "admin", "test"}
        checks = {
            "SECRET_KEY": self.secret_key,
            "POSTGRES_PASSWORD": self.database_url,
            "PROBE_BOOTSTRAP_TOKEN": self.probe_bootstrap_token,
            "ADMIN_PASSWORD": self.admin_password,
        }
        for name, value in checks.items():
            if name == "POSTGRES_PASSWORD":
                marker = "://"
                if marker in value:
                    value = value.split(marker, 1)[1].split("@", 1)[0]
            if str(value).strip().lower() in weak_values:
                raise RuntimeError(f"production requires strong non-default {name}")
            if name == "SECRET_KEY" and len(str(value)) < 32:
                raise RuntimeError("production requires SECRET_KEY with at least 32 characters")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_dirs()
    settings.validate_production()
    return settings


settings = get_settings()
