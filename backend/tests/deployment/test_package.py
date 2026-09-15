import pytest

from app.core.config import settings
from app.deployment.package import PackageError, find_package, list_packages


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


def test_find_package_with_explicit_version() -> None:
    info = find_package("amd64", settings.probe_agent_version)
    assert info["version"] == settings.probe_agent_version


def test_list_packages_reports_per_version_digest() -> None:
    items = list_packages()
    assert items
    for item in items:
        info = find_package(item["arch"], item["version"])
        assert item["sha256"] == info["sha256"], item
    digests = {item["sha256"] for item in items if item["arch"] == "amd64"}
    assert len(digests) == len({item["version"] for item in items if item["arch"] == "amd64"})
