"""Paramiko SSH/SFTP client used by the deployment Worker.

Host-key verification is strict by default: the deployment never uses
``AutoAddPolicy`` unless an explicit test/driver override requests it. The
platform maintains its own known_hosts file so the SSH trust decision stays in
platform configuration. On first contact with a host, the key is captured into
that managed file (trust-on-first-use); after that every connection is verified
against the recorded key, and a changed key is rejected.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Any

import paramiko

from app.core.config import settings


class SshError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _load_private_key(private_key: str, passphrase: str | None) -> paramiko.PKey:
    candidates: list[type[paramiko.PKey]] = [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]
    last_error: Exception | None = None
    for klass in candidates:
        try:
            return klass.from_private_key(io.StringIO(private_key), password=passphrase)
        except paramiko.PasswordRequiredException as exc:
            if passphrase is None:
                raise SshError("AUTH_FAILED", "private key requires a passphrase") from exc
            last_error = exc
        except paramiko.SSHException as exc:
            last_error = exc
    raise SshError("AUTH_FAILED", f"unable to parse private key: {last_error}")


class _TrustOnFirstUsePolicy(paramiko.MissingHostKeyPolicy):
    """Accept and persist an unknown host key on first contact (TOFU).

    paramiko consults this policy only when the host key is absent from the
    managed known_hosts. The key is recorded and saved so later connections are
    verified against it; a changed key raises before this policy is consulted.
    """

    def __init__(self, known_hosts_path: Path):
        self.known_hosts_path = known_hosts_path

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        client._host_keys.add(hostname, key.get_name(), key)  # noqa: SLF001
        client.save_host_keys(str(self.known_hosts_path))


class SshClient:
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: str | None = None,
        private_key: str | None = None,
        key_passphrase: str | None = None,
        timeout: int | None = None,
        verify_host_key: bool | None = None,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self.key_passphrase = key_passphrase
        self.timeout = timeout or settings.deployment_ssh_timeout
        self.verify_host_key = settings.deployment_verify_host_key if verify_host_key is None else verify_host_key
        self._client: paramiko.SSHClient | None = None

    def _managed_known_hosts(self) -> Path:
        """Resolve a writable known_hosts file for this platform.

        Prefer the configured ``deployment_known_hosts`` when it already exists
        or lives under a writable directory. Otherwise fall back to a managed
        file under the (writable) storage volume so host-key capture works even
        when the configured path is read-only or absent.
        """
        configured = settings.deployment_known_hosts
        if configured:
            path = Path(configured)
            if path.is_file():
                return path
            if path.parent.exists() and os.access(path.parent, os.W_OK):
                return path
        managed = Path(settings.storage_dir) / "deployment" / "known_hosts"
        managed.parent.mkdir(parents=True, exist_ok=True)
        return managed

    def _seed_known_hosts(self, managed: Path) -> None:
        """Bootstrap the managed known_hosts from admin-supplied key files.

        Copies host keys from an existing configured known_hosts and from a
        sibling ``known_hosts.pending`` (read-only deployment dir) into the
        managed file on first use, so pre-collected fingerprints are verified
        strictly without re-trusting them.
        """
        if managed.exists():
            return
        sources: list[Path] = []
        configured = settings.deployment_known_hosts
        if configured:
            cfg = Path(configured)
            if cfg.is_file() and cfg != managed:
                sources.append(cfg)
            pending = cfg.parent / "known_hosts.pending"
            if pending.is_file():
                sources.append(pending)
        if not sources:
            return
        host_keys = paramiko.HostKeys()
        for source in sources:
            try:
                host_keys.load(str(source))
            except Exception:
                continue
        managed.parent.mkdir(parents=True, exist_ok=True)
        if host_keys:
            host_keys.save(str(managed))

    def connect(self) -> "SshClient":
        client = paramiko.SSHClient()
        if self.verify_host_key:
            known_hosts_path = self._managed_known_hosts()
            self._seed_known_hosts(known_hosts_path)
            known_hosts_path.touch(exist_ok=True)
            client.load_host_keys(str(known_hosts_path))
            client.set_missing_host_key_policy(_TrustOnFirstUsePolicy(known_hosts_path))
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, Any] = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if self.password:
            kwargs["password"] = self.password
        if self.private_key:
            kwargs["pkey"] = _load_private_key(self.private_key, self.key_passphrase)
        try:
            client.connect(**kwargs)
        except paramiko.AuthenticationException as exc:
            raise SshError("AUTH_FAILED", "authentication failed") from exc
        except paramiko.SSHException as exc:
            raise SshError("CONNECT_FAILED", str(exc)) from exc
        except OSError as exc:
            raise SshError("CONNECT_FAILED", f"network error: {exc}") from exc
        self._client = client
        return self

    def exec(self, command: str, timeout: int | None = None) -> tuple[int, str, str]:
        if not self._client:
            raise SshError("CONNECT_FAILED", "not connected")
        _stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout or self.timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        return stdout.channel.recv_exit_status(), out, err

    def sftp_put(self, local: Path, remote: str) -> None:
        if not self._client:
            raise SshError("CONNECT_FAILED", "not connected")
        sftp = self._client.open_sftp()
        try:
            sftp.put(str(local), remote)
        finally:
            sftp.close()

    def listdir(self, path: str, limit: int = 2000) -> list[tuple[str, str, int]]:
        """One directory level as ``(name, kind, size)``; ``kind`` is dir/file/skip.

        Read-only and bounded: the directory tree explorer walks a *handful* of
        levels for an operator to tick, so the caller passes the limits and this
        never recurses on its own.
        """
        if not self._client:
            raise SshError("CONNECT_FAILED", "not connected")
        sftp = self._client.open_sftp()
        try:
            entries: list[tuple[str, str, int]] = []
            for index, item in enumerate(sftp.listdir_attr(path)):
                if index >= limit:
                    raise SshError("ENTRY_BUDGET", f"{path} 条目超过上限 {limit}")
                name = str(item.filename)
                if name in {".", ".."}:
                    continue
                mode = item.st_mode or 0
                import stat as _stat

                kind = ("dir" if _stat.S_ISDIR(mode)
                        else "file" if _stat.S_ISREG(mode) else "skip")
                entries.append((name, kind, int(item.st_size or 0)))
            return entries
        except SshError:
            raise
        except OSError as exc:
            raise SshError("PATH_ERROR", f"无法读取目录 {path}: {exc}") from exc
        finally:
            sftp.close()

    def host_key_sha256(self) -> str:
        """The remote server key's SHA256, in the ``SHA256:...`` form.

        The wizard echoes this into a pinned-key file source so a direct
        (probe-less) target keeps the same host-key verification the SFTP
        adapter already enforces.
        """
        if not self._client:
            raise SshError("CONNECT_FAILED", "not connected")
        transport = self._client.get_transport()
        key = transport.get_remote_server_key() if transport else None
        if key is None:
            raise SshError("CONNECT_FAILED", "no remote host key")
        import base64
        import hashlib

        digest = hashlib.sha256(key.asbytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
