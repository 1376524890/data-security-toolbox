"""Connectivity test and synchronous directory-tree browse for dispatch targets.

The task wizard needs to (a) prove it can reach a host and (b) show its directory
tree so the operator can tick a scope. Both are read-only and bounded, and the
credentials are used for that one call only — nothing here persists them; a
deployment that later installs a probe stores its own encrypted credential.

The SSH path shares :class:`SshClient` with probe deployment (same host-key
policy), so the wizard cannot be a weaker way in than the deployment pipeline.
"""
from __future__ import annotations

import time
from typing import Any

from app.deployment.ssh_client import SshClient, SshError

#: Hard ceilings so one click can never walk a whole file server.
MAX_DEPTH = 6
MAX_ENTRIES = 2000
MAX_SECONDS = 20.0


class TargetError(ValueError):
    """The target spec is unusable, or the browse hit a bound."""


def _ssh_client(spec: dict[str, Any]) -> SshClient:
    auth = str(spec.get("auth_type") or "password")
    return SshClient(
        host=str(spec.get("host") or "").strip(),
        port=int(spec.get("port") or 22),
        username=str(spec.get("username") or "root"),
        password=spec.get("password") if auth == "password" else None,
        private_key=spec.get("private_key") if auth == "private_key" else None,
        key_passphrase=spec.get("key_passphrase") or None,
    )


def _require(host: str) -> None:
    if not host:
        raise TargetError("目标主机不能为空")
    if len(host) > 255:
        raise TargetError("目标主机过长")


def test_ssh(spec: dict[str, Any]) -> dict[str, Any]:
    """Open one SSH connection and close it; nothing is written to the host."""
    host = str(spec.get("host") or "").strip()
    _require(host)
    ssh = _ssh_client(spec)
    try:
        ssh.connect()
        # The fingerprint lets a direct (probe-less) target be saved as a
        # pinned-key file source without a second, unverified connection.
        return {"ok": True, "protocol": "ssh", "error": "",
                "host_key_sha256": ssh.host_key_sha256()}
    except SshError as exc:
        return {"ok": False, "protocol": "ssh", "error": exc.code, "message": exc.message}
    finally:
        ssh.close()


def browse_ssh(spec: dict[str, Any], *, roots: list[str] | None = None,
               max_depth: int = 3, max_entries: int = MAX_ENTRIES) -> dict[str, Any]:
    """Depth-first (bounded) listing of ``roots``, flattened for the picker.

    Every row carries its depth and parent so the console can rebuild the tree,
    and truncation is reported instead of being presented as a complete listing.
    """
    host = str(spec.get("host") or "").strip()
    _require(host)
    candidates = roots or spec.get("roots") or ["/"]
    root_list = [str(item).strip() for item in candidates if str(item).strip()]
    if not root_list:
        raise TargetError("至少需要一个根目录")
    depth_limit = max(0, min(int(max_depth), MAX_DEPTH))
    entry_limit = max(1, min(int(max_entries), MAX_ENTRIES))

    ssh = _ssh_client(spec)
    started = time.monotonic()
    rows: list[dict[str, Any]] = []
    truncated = False
    reason = ""
    try:
        ssh.connect()
        queue: list[tuple[str, int]] = [(path, 0) for path in root_list]
        while queue:
            if len(rows) >= entry_limit:
                truncated, reason = True, "entry_budget"
                break
            if time.monotonic() - started > MAX_SECONDS:
                truncated, reason = True, "time_budget"
                break
            path, depth = queue.pop(0)
            try:
                children = ssh.listdir(path)
            except SshError as exc:
                name = path.rsplit("/", 1)[-1] or path
                rows.append({"path": path, "name": name, "type": "error", "size": 0,
                             "depth": depth, "reason": exc.code})
                continue
            for name, kind, size in sorted(children, key=lambda item: (item[1] != "dir", item[0])):
                if len(rows) >= entry_limit:
                    truncated, reason = True, "entry_budget"
                    break
                child = f"{path.rstrip('/')}/{name}" if path != "/" else f"/{name}"
                rows.append({"path": child, "name": name, "type": kind, "size": size,
                             "depth": depth})
                if kind == "dir" and depth < depth_limit:
                    queue.append((child, depth + 1))
    finally:
        ssh.close()
    return {"protocol": "ssh", "root": root_list[0] if len(root_list) == 1 else "",
            "roots": root_list, "rows": rows, "entries": len(rows),
            "truncated": truncated, "reason": reason,
            "elapsed_ms": int((time.monotonic() - started) * 1000)}
