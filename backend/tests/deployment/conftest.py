import pytest
from pathlib import Path

from app.core.config import settings


@pytest.fixture(autouse=True)
def deployment_settings():
    settings.deployment_secret_key = "test-deployment-secret-key-32-chars-min!!"
    settings.deployment_backend_url = "https://platform.local"
    settings.deployment_package_dir = Path(__file__).resolve().parents[3] / "probe_packages"
    yield
    settings.deployment_secret_key = ""
    settings.deployment_backend_url = ""
