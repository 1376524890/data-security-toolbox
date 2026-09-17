"""Remote probe removal: push ``uninstall.sh``, run it, keep the audit trail.

Removal is a deployment in every respect except the remote step, so it reuses
``ProbeDeployment``, its encrypted credential, its event log and its status
machine. What this service adds is the part the platform never had: a way to
take the probe back off a host.

It has to work on a *broken* install as well as a healthy one - the hosts that
most need stripping are the ones where the installer failed half-way and left a
running service behind - so it depends on nothing on the target except the SSH
connection and a shell. The uninstaller itself is uploaded from the probe
package rather than reimplemented here: the list of files a probe creates has
to live next to the installer that creates them, or the two drift and a removal
silently leaves production data behind.
"""

from __future__ import annotations

import json
import shlex
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.deployment.package import PackageError, find_uninstaller
from app.deployment.record import (
    ACTIVE_STATUSES,
    DeploymentError,
    DeploymentRecord,
    store_credential,
)
from app.deployment.service import open_ssh
from app.deployment.ssh_client import SshClient, SshError
from app.models import Probe, ProbeDeployment
from app.services.probe_service import ProbeInUseError, ProbeNotFoundError, delete_probe_record

# A removal that reports failures lands in FAILED with a REMOVAL_* code, which
# keeps it retryable from the console: the uninstaller is idempotent, so a
# second run is the fix, not a hazard.
FINISHED_STATES = {"REMOVED", "FAILED", "CANCELLED"}

# The last line `probe/uninstall.sh` prints. Everything above it is the
# human-readable log.
SUMMARY_PREFIX = "DST_UNINSTALL "


def parse_uninstall_summary(stdout: str) -> dict[str, Any] | None:
    """Return the summary the uninstaller printed, or None if it never got there.

    The log above the summary is target-host output, so it is treated as
    untrusted text; only the summary line is parsed, and the *last* one wins so
    a host cannot forge a clean result earlier in the stream.
    """
    for line in reversed(stdout.splitlines()):
        candidate = line.strip()
        if not candidate.startswith(SUMMARY_PREFIX):
            continue
        try:
            payload = json.loads(candidate[len(SUMMARY_PREFIX):])
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None
    return None


def _tail(text: str, limit: int = 4000) -> str:
    value = (text or "").strip()
    return value[-limit:] if len(value) > limit else value


def _human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024:
            return f"{size:.0f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def create_removal_deployment(
    db: Session,
    *,
    host: str,
    port: int,
    username: str,
    auth_type: str,
    password: str | None,
    private_key: str | None,
    key_passphrase: str | None,
    name: str,
    idempotency_key: str,
    created_by: str,
    probe_id: int | None = None,
    options: dict[str, Any] | None = None,
) -> ProbeDeployment:
    """Build the row a removal runs through, and attach the credential to it.

    Refuses a host that already has a live row: one SSH session per host at a
    time, whether that session is installing or removing. Request-level
    concerns - idempotency, admin policy, dispatch - stay with the caller; this
    only guarantees a row that ``RemovalService`` can run.
    """
    active = db.scalar(
        select(ProbeDeployment).where(
            ProbeDeployment.host == host,
            ProbeDeployment.status.in_(ACTIVE_STATUSES),
        )
    )
    if active:
        raise DeploymentError("HOST_BUSY", "host already has an active deployment")
    deployment = ProbeDeployment(
        name=name or f"remove-{host}",
        action="uninstall",
        host=host,
        port=port,
        username=username,
        auth_type=auth_type,
        status="CREATED",
        current_stage="queued",
        created_by=created_by,
        idempotency_key=idempotency_key,
        probe_id=probe_id,
        removal_options=dict(options or {}),
    )
    db.add(deployment)
    db.flush()
    store_credential(
        db,
        deployment,
        auth_type=auth_type,
        password=password,
        private_key=private_key,
        key_passphrase=key_passphrase,
    )
    return deployment


class RemovalService(DeploymentRecord):
    """Strip a probe from a target host over its deployment's SSH connection."""

    def __init__(self, db: Session, deployment_id: int, verify_host_key: bool | None = None):
        self.db = db
        self.deployment_id = deployment_id
        self.verify_host_key = settings.deployment_verify_host_key if verify_host_key is None else verify_host_key

    @staticmethod
    def _flags(deployment: ProbeDeployment) -> list[str]:
        """Translate the row's options into uninstaller flags.

        No flag is the default and the strictest reading: remove everything the
        installer created, including the service account, but only when the
        installer's own marker file proves it created that account.
        """
        options = deployment.removal_options or {}
        flags: list[str] = []
        if options.get("keep_data"):
            flags.append("--keep-data")
        if options.get("keep_user"):
            flags.append("--keep-user")
        if options.get("remove_user"):
            flags.append("--remove-user")
        return flags

    def _probe_status(self, deployment: ProbeDeployment) -> str:
        if not deployment.probe_id:
            return ""
        probe = self.db.get(Probe, deployment.probe_id)
        return probe.status if probe else ""

    def run(self) -> None:
        deployment = self._load()
        if deployment.action != "uninstall":
            # The install endpoint owns the other action, and a task dispatched
            # against the wrong row must never delete anything on the host.
            return
        if deployment.status in FINISHED_STATES:
            return
        if deployment.status == "CREATED":
            deployment.status = "CONNECTING"
            self.db.commit()
        ssh: SshClient | None = None
        remote_dir: str | None = None
        status_before = self._probe_status(deployment)
        try:
            self._lease(deployment)
            ssh = open_ssh(deployment, self.verify_host_key)
            self._advance(deployment, "REMOVING", 40, "connected; removing probe files from target host")
            uninstaller = find_uninstaller()
            remote_dir = self._remote_temp_dir(ssh)
            remote_script = f"{remote_dir}/uninstall.sh"
            ssh.sftp_put(uninstaller, remote_script)
            command = f"bash {shlex.quote(remote_script)}"
            flags = " ".join(self._flags(deployment))
            if flags:
                command = f"{command} {flags}"
            if ssh.username != "root":
                command = "sudo -n " + command
            rc, out, err = ssh.exec(command, timeout=settings.deployment_removal_timeout_seconds)
            self._record_result(deployment, status_before, rc, out, err, parse_uninstall_summary(out))
        except (SshError, DeploymentError, PackageError) as exc:
            self._fail(deployment, getattr(exc, "code", "REMOVAL_FAILED"), str(exc))
        except Exception as exc:  # noqa: BLE001 - land in Failed, never leave Removing
            self._fail(deployment, "REMOVAL_FAILED", f"{type(exc).__name__}: {exc}")
        finally:
            if ssh is not None:
                if remote_dir:
                    try:
                        ssh.exec(f"rm -rf {shlex.quote(remote_dir)}")
                    except Exception:
                        pass
                ssh.close()
            self._destroy_credential(deployment)

    def _record_result(
        self,
        deployment: ProbeDeployment,
        status_before: str,
        rc: int,
        stdout: str,
        stderr: str,
        summary: dict[str, Any] | None,
    ) -> None:
        """Persist what the host reported, then settle the row.

        The summary is the audit trail the operator needs - which paths were
        removed, which were already gone, what survived, how much disk came
        back - so it is stored as reported instead of being reduced to a status
        the console cannot explain.
        """
        report: dict[str, Any] = {
            "action": "uninstall",
            "exit_code": rc,
            "finished_at": datetime.now(UTC).isoformat(),
            "probe_status_before": status_before,
            "summary": summary or {},
            "stdout_tail": _tail(stdout),
            "stderr_tail": _tail(stderr),
        }
        if summary is None:
            # No summary means the script never reached its last line: bash
            # aborted, sudo refused, or the connection dropped mid-run. The
            # host state is unknown, so nothing is claimed about it.
            report["ok"] = False
            report["reason"] = "uninstaller did not report a result"
        else:
            report["ok"] = bool(summary.get("ok")) and rc == 0
            report["removed"] = [str(item) for item in (summary.get("removed") or [])]
            report["kept"] = [str(item) for item in (summary.get("kept") or [])]
            report["absent"] = [str(item) for item in (summary.get("absent") or [])]
            report["failed"] = [str(item) for item in (summary.get("failed") or [])]
            report["bytes_freed"] = int(summary.get("bytes_freed") or 0)
            report["files_freed"] = int(summary.get("files_freed") or 0)
            report["probe_status_after"] = "offline" if report["ok"] else status_before
        deployment.result = report
        if report["ok"]:
            deployment.status = "REMOVED"
            deployment.current_stage = "REMOVED"
            deployment.progress = 100
            deployment.error_code = ""
            deployment.error_message = ""
            self._event(deployment, "REMOVED", self._success_message(report))
            self.db.commit()
            self._forget_probe_identity(deployment)
            return
        # Partially removed is worth saying out loud: the host is half-stripped,
        # the operator has to look at what survived, and a retry is safe.
        code = "REMOVAL_PARTIAL" if report.get("removed") else "REMOVAL_FAILED"
        detail = report.get("reason") or ""
        if report.get("removed"):
            detail = "removed: " + ", ".join(report["removed"])
        if report.get("failed"):
            detail = (detail + "; " if detail else "") + "could not remove: " + ", ".join(report["failed"])
        if stderr.strip():
            detail = (detail + "; " if detail else "") + _tail(stderr, 500)
        self._fail(deployment, code, detail or "probe removal failed")

    @staticmethod
    def _success_message(report: dict[str, Any]) -> str:
        parts = ["probe removed from host"]
        if report.get("removed"):
            parts.append("removed: " + ", ".join(report["removed"]))
        if report.get("kept"):
            parts.append("kept: " + ", ".join(report["kept"]))
        freed = int(report.get("bytes_freed") or 0)
        if freed:
            parts.append(f"freed {_human_bytes(freed)} in {int(report.get('files_freed') or 0)} files")
        return "; ".join(parts)

    def _forget_probe_identity(self, deployment: ProbeDeployment) -> None:
        """Make the platform forget a probe that no longer exists on the host.

        The files are gone, so the agent can never authenticate again; leaving
        its token valid would keep a live credential for a dead probe. The
        record itself is only dropped when the operator asked for that in the
        same step - the evidence it collected stays useful either way.
        """
        probe_id = deployment.probe_id
        if not probe_id:
            return
        probe = self.db.get(Probe, probe_id)
        if probe is None:
            return
        probe.token = ""
        probe.token_hash = ""
        probe.status = "offline"
        self.db.commit()
        if not (deployment.removal_options or {}).get("delete_record"):
            return
        try:
            delete_probe_record(self.db, probe_id)
            self._event(deployment, "REMOVED", "platform probe record deleted")
        except (ProbeNotFoundError, ProbeInUseError) as exc:
            # The host is stripped either way; the record has to stay only
            # because something was still using it, which is a console problem.
            self._event(deployment, "REMOVED", f"platform probe record kept: {exc}")
        self.db.commit()
