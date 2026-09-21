"""The four ways the shared engine has to reach a real host.

The baseline flagged these as the highest-risk items (R2/R3): a missing copy step
fails at the customer site, not in the developer checkout. Each path is asserted
here so it cannot silently regress again.
"""
from __future__ import annotations

import json
import tarfile
from pathlib import Path

import yaml

from app.core.config import settings

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGES = REPO_ROOT / "probe_packages"
# Only the current package is built from this tree; 3.2.x/3.3.0 are released
# artifacts that must keep their original contents.
CURRENT_VERSION = settings.probe_agent_version
INSTALLER = REPO_ROOT / "probe" / "install.sh"
UNINSTALLER = REPO_ROOT / "probe" / "uninstall.sh"
UNIT = REPO_ROOT / "probe" / "data-security-toolbox-probe.service"
LOAD_IMAGES = REPO_ROOT / "offline" / "load-images.sh"
REQUIREMENTS = REPO_ROOT / "probe" / "requirements.txt"
DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"
COMPOSE = REPO_ROOT / "docker-compose.yml"

REQUIRED_SHARED = (
    "shared/__init__.py",
    "shared/sensitive_detection/__init__.py",
    "shared/sensitive_detection/engine.py",
    "shared/sensitive_detection/rules.py",
    "shared/sensitive_detection/matching.py",
    "shared/sensitive_detection/report_guard.py",
    # Stage 3: the budget, fingerprint, sampler and parser layer is shared too.
    "shared/scanning/__init__.py",
    "shared/scanning/budget.py",
    "shared/scanning/fingerprint.py",
    "shared/scanning/sampler.py",
    "shared/scanning/magic.py",
    "shared/scanning/cache.py",
    "shared/scanning/parsers/__init__.py",
    "shared/scanning/parsers/xlsx.py",
)


def _manifests() -> list[tuple[Path, dict]]:
    return [(path, json.loads(path.read_text(encoding="utf-8")))
            for path in sorted(PACKAGES.glob(f"probe-{CURRENT_VERSION}/*/manifest.json"))]


def test_every_built_probe_package_lists_the_shared_engine() -> None:
    manifests = _manifests()
    assert manifests, "no built probe package: run probe_packages/build_packages.py"
    for manifest_path, manifest in manifests:
        listed = set(manifest["files"])
        assert set(REQUIRED_SHARED) <= listed, manifest_path
        # The deployment service verifies every manifest entry exists on disk.
        for name in manifest["files"]:
            assert (manifest_path.parent / name).is_file(), f"{manifest_path}: {name}"


def test_probe_package_artifact_contains_the_shared_engine() -> None:
    for manifest_path, manifest in _manifests():
        with tarfile.open(manifest_path.parent / manifest["artifact"]) as archive:
            names = set(archive.getnames())
        assert set(REQUIRED_SHARED) <= names, manifest_path


def test_backend_images_build_from_the_repository_root() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    builds = [service["build"] for service in compose["services"].values() if service.get("build")]
    assert not [item for item in builds if item.get("context") == "./backend"], \
        "a backend image would build without shared/ in its context"
    assert len([item for item in builds if item.get("dockerfile") == "backend/Dockerfile"]) == 4


def test_backend_image_copies_the_shared_package() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY shared ./shared" in dockerfile
    # The build context is the repository root, so every COPY is root-relative.
    assert "COPY backend/app ./app" in dockerfile


def test_installer_installs_the_shared_package_into_a_writable_rules_dir() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    assert 'SHARED_DIR="${APP_DIR}/shared"' in installer
    assert 'cp -R "${SCRIPT_DIR}/shared/sensitive_detection" "${SCRIPT_DIR}/shared/scanning" "${SHARED_DIR}/"' in installer
    # Stage 2 stores current/previous/staging rule versions and Stage 3 the
    # analysis cache, so systemd has to allow writing to both directories.
    assert "ReadWritePaths=${SPOOL_DIR} ${RULES_DIR} ${CACHE_DIR} ${CONFIG_DIR}" in installer
    assert 'RULES_DIR="/var/lib/data-security-toolbox/rules"' in installer
    assert 'CACHE_DIR="/var/lib/data-security-toolbox/cache"' in installer


def test_probe_package_carries_the_ruleset_client_and_its_config() -> None:
    """Hot update is useless if the module or its writable directory is missing."""
    manifests = _manifests()
    assert manifests, "no built probe package: run probe_packages/build_packages.py"
    for manifest_path, manifest in manifests:
        assert "ruleset_client.py" in manifest["files"], manifest_path
    installer = INSTALLER.read_text(encoding="utf-8")
    assert '"${SCRIPT_DIR}/ruleset_client.py"' in installer
    # The probe has to be told where to keep current/previous/staging and how
    # large a pack it may download.
    example = (REPO_ROOT / "probe" / "probe.toml.example").read_text(encoding="utf-8")
    assert "[ruleset]" in example
    assert "max_pack_bytes" in example
    assert "/var/lib/data-security-toolbox/rules" in example


def test_probe_package_carries_the_scan_budgets_and_their_writable_cache() -> None:
    """A shipped probe must be able to bound a scan and cache its results."""
    manifests = _manifests()
    assert manifests, "no built probe package: run probe_packages/build_packages.py"
    for manifest_path, manifest in manifests:
        assert "shared/scanning/budget.py" in manifest["files"], manifest_path
        assert "shared/scanning/parsers/xlsx.py" in manifest["files"], manifest_path
    example = (REPO_ROOT / "probe" / "probe.toml.example").read_text(encoding="utf-8")
    assert "max_full_hash_size" in example
    assert "xlsx_max_rows" in example
    assert "cache_path" in example


def test_probe_budget_defaults_come_from_the_shared_package() -> None:
    """The probe config must not carry a second, drifting copy of the defaults."""
    import probe.probe as probe_module

    shared = probe_module._scan_budget_defaults()
    assert shared, "shared.scanning.budget is not importable from the probe"
    for key, value in shared.items():
        assert probe_module.DEFAULT_CONFIG["data"][key] == value, key
    # The budget key is named `timeout_seconds` in TOML, not `max_runtime_seconds`.
    assert "max_runtime_seconds" not in probe_module.DEFAULT_CONFIG["data"]
    assert probe_module.DEFAULT_CONFIG["data"]["timeout_seconds"] == 120


def test_probe_requirements_pin_the_timeout_capable_regex_engine() -> None:
    requirements = REQUIREMENTS.read_text(encoding="utf-8")
    assert "regex==" in requirements
    # Without it the engine still runs but cannot bound a hostile pattern.
    assert "openpyxl==" in requirements


def test_shipped_scripts_use_unix_line_endings() -> None:
    """A CRLF checkout must never reach a Linux host.

    bash reads `set -euo pipefail` followed by a carriage return as an unknown
    option and aborts the install at line 2 with
    "set: pipefail : invalid option name", and systemd misparses the unit. The
    artifact is also built on Windows workstations (`core.autocrlf=true`), so
    the assertion follows the tarball, not just the repository.
    """
    for path in (INSTALLER, UNINSTALLER, UNIT, LOAD_IMAGES):
        assert b"\r\n" not in path.read_bytes(), f"{path} has CRLF line endings"

    manifests = _manifests()
    assert manifests, "no built probe package: run probe_packages/build_packages.py"
    for manifest_path, manifest in manifests:
        with tarfile.open(manifest_path.parent / manifest["artifact"]) as archive:
            for name in ("install.sh", "uninstall.sh", "data-security-toolbox-probe.service"):
                data = archive.extractfile(name).read()
                assert b"\r\n" not in data, f"{manifest_path}: {name} has CRLF line endings"


def test_shipped_installer_is_executable() -> None:
    """Windows has no POSIX mode bits, so the artifact has to carry them."""
    manifests = _manifests()
    assert manifests, "no built probe package: run probe_packages/build_packages.py"
    for manifest_path, manifest in manifests:
        with tarfile.open(manifest_path.parent / manifest["artifact"]) as archive:
            member = archive.getmember("install.sh")
        assert member.mode & 0o111, f"{manifest_path}: install.sh is not executable"


def test_package_ships_the_uninstaller_next_to_the_installer() -> None:
    """A removal has to run the list of paths that the installer wrote.

    Re-implementing the deletion on the platform side is how the two lists drift
    and a removal starts leaving production files behind, so the uninstaller
    ships in the artifact, is executable, and is copied onto the host by
    `install.sh` (so it stays runnable even without the platform).
    """
    manifests = _manifests()
    assert manifests, "no built probe package: run probe_packages/build_packages.py"
    for manifest_path, manifest in manifests:
        assert "uninstall.sh" in manifest["files"], manifest_path
        with tarfile.open(manifest_path.parent / manifest["artifact"]) as archive:
            member = archive.getmember("uninstall.sh")
            script = archive.extractfile(member).read().decode()
        assert member.mode & 0o111, f"{manifest_path}: uninstall.sh is not executable"
        # The decisions the removal makes about optional artifacts are taken
        # from install.sh's marker files, so both halves have to agree on them.
        for marker in (".created-user", ".installed-capture-tool"):
            assert marker in script, f"{manifest_path}: uninstall.sh ignores {marker}"
    installer = INSTALLER.read_text(encoding="utf-8")
    assert '"${SCRIPT_DIR}/uninstall.sh" "${APP_DIR}/uninstall.sh"' in installer
    assert '"${APP_DIR}/.created-user"' in installer
    # New packages keep tools private; the uninstaller still understands legacy markers.
    assert 'RUNTIME_DIR="${APP_DIR}/runtime"' in installer
    assert '/usr/local/bin/dumpcap' not in installer
