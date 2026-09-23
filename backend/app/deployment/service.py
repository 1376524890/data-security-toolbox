"""Deployment service orchestration: SSH push, install, enrollment, callback."""

from __future__ import annotations

import ipaddress
import json
import shlex
import socket
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.core.config import settings
from app.deployment.credential import decrypt_credential
from app.deployment.enrollment import create_enrollment
from app.deployment.package import PackageError, find_package
from app.deployment.preflight import run_preflight
from app.deployment.record import DeploymentError, DeploymentRecord, _now
from app.deployment.ssh_client import SshClient, SshError
from app.models import ProbeDeployment, ProbeDeploymentCredential


def open_ssh(deployment: ProbeDeployment, verify_host_key: bool | None = None) -> SshClient:
    """Decrypt the row's credential and return a connected SSH client.

    Shared by deployment and removal: both authenticate with the same
    short-lived, AES-GCM encrypted secret and both honour the platform's
    host-key policy.
    """
    if not deployment.credential:
        raise DeploymentError("CREDENTIAL_MISSING", "deployment credential not found")
    credential = deployment.credential
    secret = decrypt_credential(
        deployment.id,
        deployment.auth_type,
        credential.key_id,
        credential.nonce,
        credential.encrypted_secret,
    )
    key_passphrase = None
    if deployment.auth_type == "private_key" and secret.startswith("{"):
        key_data = json.loads(secret)
        secret = key_data["private_key"]
        key_passphrase = key_data.get("key_passphrase")
    ssh = SshClient(
        host=deployment.host,
        port=deployment.port,
        username=deployment.username,
        password=secret if deployment.auth_type == "password" else None,
        private_key=secret if deployment.auth_type == "private_key" else None,
        key_passphrase=key_passphrase,
        verify_host_key=settings.deployment_verify_host_key if verify_host_key is None else verify_host_key,
    )
    ssh.connect()
    return ssh


#: Capture-time defaults, kept in one place so the code, the manual-install TOML
#: and a console cannot drift. 30 s / 64 MiB is the balance point measured on a
#: loaded host: a segment is small enough that analysing one finishes well inside
#: the time the next takes to fill, so a backlog drains instead of building,
#: while a segment is still large enough to hold whole sessions (a 30 s window)
#: for the flow and timeline engines.
DEFAULT_SEGMENT_SECONDS = 30
DEFAULT_SEGMENT_MAX_MB = 64

#: NIC name prefixes that are container/bridge devices rather than the network
#: under test. A probe deployed onto the platform's own host used to capture on
#: ``any``, which includes the docker bridge its own uploads leave by - so each
#: segment recorded the upload of the previous one and the probe sustained
#: itself with no real traffic at all (96% of a measured capture was this loop).
VIRTUAL_INTERFACE_PREFIXES = ("docker", "br-", "veth", "virbr", "tun", "tap", "lo")


def capture_interface_for(data_config: dict[str, Any] | None, candidates: list[str]) -> str:
    """Pick the capture NIC: the operator's choice, else the first real one.

    ``candidates`` comes from the target host's preflight, so the decision uses
    what that host actually has rather than a name guessed on the platform, and
    it is already narrowed to NICs the kernel reports as up - see
    ``preflight.run_preflight`` for why a down port must never be offered.
    """
    chosen = str((data_config or {}).get("capture_interface") or "").strip()
    if chosen:
        return chosen
    usable = [str(item) for item in candidates or [] if str(item).strip()]
    real = [name for name in usable if not name.startswith(VIRTUAL_INTERFACE_PREFIXES)]
    return (real or usable or ["any"])[0]


def capture_self_filter(backend_url: str) -> str:
    """BPF expression that keeps the platform's own management channel out.

    The probe's own upload is the single largest flow a freshly deployed probe
    sees, and it is never the data under test - the DLP engine already treats it
    as own traffic after the fact. Dropping it at capture time is the difference
    between a usable sensor and one that spends its whole budget recording
    itself.

    Only the exact ``host and port`` pair is excluded: a filter on the port alone
    would hide genuine application traffic that happens to share it, and one on
    the host alone would hide every other service on the platform's host.
    """
    text = str(backend_url or "").strip()
    if not text:
        return ""
    parts = urlsplit(text if "//" in text else f"//{text}")
    host = parts.hostname
    if not host:
        return ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            addresses = sorted(
                {info[4][0] for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)}
            )
        except OSError:
            # An unresolvable host is not a reason to fail a deployment; it only
            # means this layer cannot help and the interface choice stands alone.
            return ""
    return " and ".join(f"not (host {address} and port {port})" for address in addresses)


def build_probe_toml(deployment: ProbeDeployment, enrollment_token: str, ca_file: str | None,
                     interface: str = "", segment_seconds: int | None = None,
                     segment_max_mb: int | None = None) -> str:
    """Generate the probe TOML for the target host (no secrets beyond enrollment)."""
    verify_tls = "true" if ca_file else "false"
    ca_line = 'ca_file = "/etc/data-security-toolbox/ca.pem"' if ca_file else ""
    profile = deployment.profile
    if profile == "lite":
        capture_enabled = "false"
        file_interval = 0
        paths = "[]"
    elif profile == "sensor":
        capture_enabled = "true"
        file_interval = 0
        paths = "[]"
    else:  # standard
        capture_enabled = "true"
        file_interval = 0
        paths = "[]"
    data_config = deployment.data_config or {}
    data_paths = [str(item) for item in (data_config.get("paths") or []) if str(item).strip()]
    data_enabled = "true" if data_paths else "false"
    data_interval = int(data_config.get("interval_seconds") or 3600)
    # 0 = "no limit" and it has to survive this round-trip: ``or 10000`` / ``or 3``
    # turned a deliberate 0 back into the old cap, which is how a probe-deployed
    # data inventory silently stopped three levels down.
    data_max_files = int(data_config.get("max_files") or 0)
    data_max_depth = int(data_config.get("max_depth") or 0)
    data_databases = "true" if data_config.get("include_databases", True) else "false"
    capture_interface = str(data_config.get("capture_interface") or interface or "any")
    capture_segment_seconds = int(
        segment_seconds or data_config.get("segment_seconds") or DEFAULT_SEGMENT_SECONDS
    )
    capture_segment_max_mb = int(
        segment_max_mb or data_config.get("segment_max_mb") or DEFAULT_SEGMENT_MAX_MB
    )
    self_filter = capture_self_filter(deployment.backend_url)
    return "\n".join(
        [
            "[server]",
            'url = ' + json.dumps(deployment.backend_url),
            f"verify_tls = {verify_tls}",
            ca_line,
            "",
            "[capture]",
            f'interface = "{capture_interface}"',
            f"segment_seconds = {capture_segment_seconds}",
            f"segment_max_mb = {capture_segment_max_mb}",
            f"filter = {json.dumps(self_filter)}",
            f"enabled = {capture_enabled}",
            "",
            "[spool]",
            'path = "/var/lib/data-security-toolbox/spool"',
            "max_mb = 2048",
            "retention_seconds = 86400",
            "",
            "[agent]",
            "heartbeat_seconds = 30",
            "asset_interval_seconds = 900",
            f"file_interval_seconds = {file_interval}",
            f'bootstrap_token = "{enrollment_token}"',
            f'deployment_id = {deployment.id}',
            'token_path = "/etc/data-security-toolbox/probe.token"',
            "ports = [22, 80, 443, 445, 3306, 5432, 6379, 8080]",
            f"paths = {paths}",
            # Same rule as [data]: 0 = no cap on how many files are collected.
            "max_files = 0",
            "demo = false",
            "",
            "[scan]",
            "# Platform-queued bounded TCP inventory runs on this probe host.",
            "allow_remote = true",
            "poll_seconds = 30",
            "",
            "[data]",
            "# Data-asset inventory of this server: file identity, inferred columns and",
            "# sensitive-data categories. Only aggregate evidence is uploaded.",
            f"enabled = {data_enabled}",
            f"interval_seconds = {data_interval}",
            f"paths = {json.dumps(data_paths)}",
            f"exclude_paths = {json.dumps([str(item) for item in (data_config.get('exclude_paths') or []) if str(item).strip()])}",
            f"max_files = {data_max_files}",
            f"max_depth = {data_max_depth}",
            f"include_databases = {data_databases}",
            "allow_remote = true",
            "poll_seconds = 30",
            "",
        ]
    )


class DeploymentService(DeploymentRecord):
    def __init__(self, db: Session, deployment_id: int, verify_host_key: bool | None = None):
        self.db = db
        self.deployment_id = deployment_id
        self.verify_host_key = settings.deployment_verify_host_key if verify_host_key is None else verify_host_key

    def _upload_package(self, ssh: SshClient, pkg: dict[str, Any], remote_dir: str) -> None:
        artifact = pkg["artifact"]
        remote_artifact = f"{remote_dir}/{Path(artifact.name).name}"
        ssh.sftp_put(artifact, remote_artifact)
        rc, out, err = ssh.exec(
            f"cd {shlex.quote(remote_dir)} && sha256sum {shlex.quote(Path(artifact.name).name)}"
        )
        if rc != 0 or not out.strip().startswith(pkg["sha256"]):
            raise DeploymentError("PACKAGE_FAILED", "package SHA256 mismatch on target")
        rc, _, _ = ssh.exec(f"tar -xzf {shlex.quote(remote_artifact)} -C {shlex.quote(remote_dir)}")
        if rc != 0:
            raise DeploymentError("PACKAGE_FAILED", "unable to extract probe package")
        # `install.sh` runs under bash and writes a systemd unit, so a package
        # built from a CRLF checkout (Windows, core.autocrlf=true) aborts on the
        # target with "set: pipefail : invalid option name". New packages are
        # written with Unix line endings; this keeps an artifact built before
        # that fix deployable.
        rc, _, _ = ssh.exec(
            f"cd {shlex.quote(remote_dir)} && "
            "find . -maxdepth 2 -type f \\( -name '*.sh' -o -name '*.service' \\) "
            "-exec sed -i 's/\\r$//' {} + 2>/dev/null; "
            "tr -d '\\r' < install.sh | cmp -s - install.sh"
        )
        if rc != 0:
            raise DeploymentError("PACKAGE_FAILED", "probe package installer has CRLF line endings")

    def _upload_config(self, ssh: SshClient, toml: str, remote_dir: str, ca_file: str | None) -> str | None:
        remote_toml = f"{remote_dir}/probe.toml"
        import io

        sftp = ssh._client.open_sftp()
        try:
            with sftp.open(remote_toml, "w") as handle:
                handle.write(toml)
        finally:
            sftp.close()
        ca_remote = None
        if ca_file and Path(ca_file).is_file():
            ca_remote = f"{remote_dir}/ca.pem"
            ssh.sftp_put(Path(ca_file), ca_remote)
        return ca_remote

    def _install(self, ssh: SshClient, pkg: dict[str, Any], remote_dir: str, ca_remote: str | None) -> None:
        ca_arg = f"--ca {shlex.quote(ca_remote)}" if ca_remote else "--ca ''"
        command = (
            f"bash {shlex.quote(remote_dir)}/install.sh --install-only "
            f"--config {shlex.quote(remote_dir)}/probe.toml {ca_arg}"
        )
        if ssh.username != "root":
            command = "sudo -n " + command
        rc, out, err = ssh.exec(command, timeout=300)
        if rc != 0:
            raise DeploymentError("INSTALL_FAILED", (err or out)[:2000])

    def run(self) -> None:
        deployment = self._load()
        if deployment.action != "install":
            # Removal rows are driven by RemovalService; never let the installer
            # upload and start a probe against a row that asked to remove one.
            return
        if deployment.status in {"ONLINE", "WAIT_CALLBACK", "REGISTERED", "FAILED", "CANCELLED"}:
            return
        if deployment.status == "CREATED":
            deployment.status = "CONNECTING"
            self.db.commit()
        ssh: SshClient | None = None
        remote_dir: str | None = None
        try:
            self._lease(deployment)
            ssh = open_ssh(deployment, self.verify_host_key)
            self._advance(deployment, "PREFLIGHT", 20, "connected; running preflight")
            preflight = run_preflight(ssh, deployment.profile, backend_url=deployment.backend_url)
            deployment.preflight_result = preflight
            self.db.commit()
            if not preflight.get("compatible"):
                self._fail(deployment, "PREFLIGHT_FAILED", "target host failed preflight checks")
                return
            self._advance(deployment, "UPLOADING", 40, "selecting and uploading package")
            pkg = find_package(preflight["arch"])
            deployment.package_version = pkg["version"]
            deployment.package_digest = pkg["sha256"]
            self.db.commit()
            remote_dir = self._remote_temp_dir(ssh)
            self._upload_package(ssh, pkg, remote_dir)
            self._advance(deployment, "INSTALLING", 60, "installing probe and systemd unit")
            token = create_enrollment(self.db, deployment)
            ca_file = settings.deployment_ca_file or None
            # The interface is chosen from what the target host reported, not
            # hardcoded to 'any': see capture_interface_for for why 'any' on a
            # shared host is a self-sustaining capture loop.
            interface = capture_interface_for(
                deployment.data_config, list(preflight.get("interfaces") or [])
            )
            deployment.preflight_result = {**preflight, "capture_interface": interface}
            self.db.commit()
            toml = build_probe_toml(deployment, token, ca_file, interface=interface)
            ca_remote = self._upload_config(ssh, toml, remote_dir, ca_file)
            self._install(ssh, pkg, remote_dir, ca_remote)
            deployment.callback_deadline = _now() + timedelta(seconds=settings.deployment_callback_timeout_seconds)
            deployment.status = "WAIT_CALLBACK"
            deployment.current_stage = "WAIT_CALLBACK"
            deployment.progress = 80
            self._event(deployment, "WAIT_CALLBACK", "installed; awaiting registration")
            self.db.commit()
            prefix = "" if ssh.username == "root" else "sudo -n "
            # `restart`, not `start`: install.sh runs with --install-only, so a
            # probe that is already running (retry or upgrade) would otherwise be
            # left with the previous code and config in memory and never enrol -
            # `systemctl start` is a no-op on an active unit.
            rc, _, _ = ssh.exec(prefix + "systemctl restart data-security-toolbox-probe 2>&1")
            if rc != 0:
                raise DeploymentError("START_FAILED", "unable to start probe service")
            self.db.refresh(deployment)
            if deployment.status == "WAIT_CALLBACK":
                deployment.progress = 90
            self._event(deployment, "STARTED", "service started; awaiting registration + heartbeat")
            self.db.commit()
        except (SshError, DeploymentError, PackageError) as exc:
            self._fail(deployment, getattr(exc, "code", "INSTALL_FAILED"), str(exc))
        except Exception as exc:  # noqa: BLE001 - land in Failed, never leave Running
            self._fail(deployment, "INSTALL_FAILED", f"{type(exc).__name__}: {exc}")
        finally:
            if ssh is not None:
                if remote_dir:
                    try:
                        ssh.exec(f"rm -rf {shlex.quote(remote_dir)}")
                    except Exception:
                        pass
                ssh.close()
            # A task-dedicated probe (retain_credential) keeps its credential so
            # the platform can uninstall it when the task ends; every other run -
            # including a failed one, via _fail - destroys it here.
            keep_for_task = (bool((deployment.data_config or {}).get("retain_credential"))
                             and deployment.status == "WAIT_CALLBACK")
            if not keep_for_task:
                self._destroy_credential(deployment)
