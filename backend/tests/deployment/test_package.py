import pytest

from app.core.config import settings
from app.deployment.package import PackageError, find_package


def test_find_package_amd64() -> None:
    info = find_package("amd64")
    assert info["arch"] == "amd64"
    assert info["version"] == settings.probe_agent_version
    assert len(info["sha256"]) == 64


def test_find_package_arm64() -> None:
    info = find_package("arm64")
    assert info["arch"] == "arm64"


def test_unsupported_arch() -> None:
    with pytest.raises(PackageError):
        find_package("mips")


def test_missing_manifest(tmp_path) -> None:
    settings.deployment_package_dir = tmp_path
    with pytest.raises(PackageError):
        find_package("amd64")
