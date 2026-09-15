"""Paramiko SSH/SFTP client used by the deployment Worker.

Host-key verification is strict by default: the deployment never uses
``AutoAddPolicy`` unless an explicit test/driver override requests it. This keeps
the SSH trust decision in platform configuration rather than in the Worker.
"""

from __future__ import annotations

import io
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

    def connect(self) -> "SshClient":
        client = paramiko.SSHClient()
        if self.verify_host_key:
            known_hosts = settings.deployment_known_hosts
            if not known_hosts or not Path(known_hosts).is_file():
                raise SshError("CONNECT_FAILED", "no known_hosts configured")
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
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

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
