"""Deployment service orchestration: SSH push, install, enrollment, callback."""

from __future__ import annotations

import json
import shlex
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.deployment.credential import decrypt_credential
from app.deployment.enrollment import create_enrollment
from app.deployment.package import PackageError, find_package
from app.deployment.preflight import run_preflight
from app.deployment.ssh_client import SshClient, SshError
from app.models import ProbeDeployment, ProbeDeploymentCredential, ProbeDeploymentEvent


class DeploymentError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _now() -> datetime:
    return datetime.now(UTC)


def build_probe_toml(deployment: ProbeDeployment, enrollment_token: str, ca_file: str | None, interface: str = "any") -> str:
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
    return "\n".join(
        [
            "[server]",
            'url = ' + json.dumps(deployment.backend_url),
            f"verify_tls = {verify_tls}",
            ca_line,
            "",
            "[capture]",
            f'interface = "{interface}"',
            "segment_seconds = 30",
            "segment_max_mb = 64",
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
            "max_files = 50",
            "demo = false",
            "",
        ]
    )


class DeploymentService:
    def __init__(self, db: Session, deployment_id: int, verify_host_key: bool | None = None):
        self.db = db
        self.deployment_id = deployment_id
        self.verify_host_key = settings.deployment_verify_host_key if verify_host_key is None else verify_host_key

    def _load(self) -> ProbeDeployment:
        deployment = self.db.get(ProbeDeployment, self.deployment_id)
        if not deployment:
            raise DeploymentError("NOT_FOUND", "deployment not found")
        return deployment

    def _event(self, deployment: ProbeDeployment, stage: str, message: str) -> None:
        seq = (len(deployment.events) or 0) + 1
        self.db.add(ProbeDeploymentEvent(deployment_id=deployment.id, seq=seq, stage=stage, message=message))

    def _advance(self, deployment: ProbeDeployment, stage: str, progress: int, message: str) -> None:
        deployment.status = stage
        deployment.current_stage = stage
        deployment.progress = progress
        self._event(deployment, stage, message)
        self.db.commit()

    def _fail(self, deployment: ProbeDeployment, code: str, message: str) -> None:
        deployment.status = "FAILED"
        deployment.error_code = code
        deployment.error_message = message[:2000]
        deployment.progress = 100
        self._event(deployment, "FAILED", message)
        self.db.commit()
        self._destroy_credential(deployment)

    def _destroy_credential(self, deployment: ProbeDeployment) -> None:
        if deployment.credential_destroyed_at is not None:
            return
        if deployment.credential:
            self.db.delete(deployment.credential)
        deployment.credential_destroyed_at = _now()
        self.db.commit()

    def _lease(self, deployment: ProbeDeployment) -> None:
        deployment.lease_expires_at = _now() + timedelta(minutes=30)
        deployment.version = (deployment.version or 0) + 1
        self.db.commit()

    def _remote_temp_dir(self, ssh: SshClient) -> str:
        rc, out, _ = ssh.exec("mktemp -d /tmp/dstprobe-deploy-XXXXXX 2>/dev/null")
        if rc != 0 or not out.strip():
            raise DeploymentError("INSTALL_FAILED", "unable to create remote temp dir")
        return out.strip().splitlines()[-1]

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
        if deployment.status in {"ONLINE", "WAIT_CALLBACK", "REGISTERED", "FAILED", "CANCELLED"}:
            return
        if deployment.status == "CREATED":
            deployment.status = "CONNECTING"
            self.db.commit()
        ssh: SshClient | None = None
        remote_dir: str | None = None
        try:
            self._lease(deployment)
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
                verify_host_key=self.verify_host_key,
            )
            ssh.connect()
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
            interface = 'any'
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
            rc, _, _ = ssh.exec(prefix + "systemctl start data-security-toolbox-probe 2>&1")
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
            self._destroy_credential(deployment)
