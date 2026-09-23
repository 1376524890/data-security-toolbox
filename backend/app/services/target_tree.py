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

#: Ceilings for callers that *ask* for a cap. The service itself never truncates
#: silently: 0 means "no cap" for both depth and entries, so a picker can show a
#: whole tree. A non-zero value is the caller's own bound and is reported back as
#: ``truncated`` when it bites (the wizard expands level by level, so it asks for
#: one level at a time and never hits these).
MAX_DEPTH = 64
MAX_ENTRIES = 200000


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
               max_depth: int = 0, max_entries: int = 0) -> dict[str, Any]:
    """Breadth-first listing of ``roots``, one level per requested depth.

    ``max_depth`` counts levels *below* each root (1 = the root's children only),
    which is what a lazy tree needs: every expansion asks for one more level, so
    the console can walk the whole tree instead of being stopped at 3 levels.
    0 means "no depth cap".

    Rows carry the depth of the entry itself, and truncation is only ever the
    caller's own cap - it is reported instead of being presented as a complete
    listing.
    """
    host = str(spec.get("host") or "").strip()
    _require(host)
    candidates = roots or spec.get("roots") or ["/"]
    root_list = [str(item).strip() for item in candidates if str(item).strip()]
    if not root_list:
        raise TargetError("至少需要一个根目录")
    # 0 keeps its meaning all the way through: no cap. A non-zero value is the
    # caller's bound, clamped to the ceiling.
    requested_depth = int(max_depth)
    depth_limit = min(requested_depth, MAX_DEPTH) if requested_depth > 0 else 0
    requested_entries = int(max_entries)
    entry_limit = min(requested_entries, MAX_ENTRIES) if requested_entries > 0 else 0

    ssh = _ssh_client(spec)
    started = time.monotonic()
    rows: list[dict[str, Any]] = []
    truncated = False
    reason = ""
    try:
        ssh.connect()
        #: ``depth`` is the depth of the directory itself; a root is 0, so its
        #: children are level 1. Walking stops before a directory that would sit
        #: below the operator's cap, which keeps "one call = one level" true.
        queue: list[tuple[str, int]] = [(path, 0) for path in root_list]
        for path, depth in queue:
            if depth_limit and depth >= depth_limit:
                continue
            if entry_limit and len(rows) >= entry_limit:
                truncated, reason = True, "entry_budget"
                break
            try:
                children = ssh.listdir(path)
            except SshError as exc:
                name = path.rsplit("/", 1)[-1] or path
                rows.append({"path": path, "name": name, "type": "error", "size": 0,
                             "depth": depth, "reason": exc.code})
                continue
            for name, kind, size in sorted(children, key=lambda item: (item[1] != "dir", item[0])):
                if entry_limit and len(rows) >= entry_limit:
                    truncated, reason = True, "entry_budget"
                    break
                child = f"{path.rstrip('/')}/{name}" if path != "/" else f"/{name}"
                rows.append({"path": child, "name": name, "type": kind, "size": size,
                             "depth": depth + 1})
                if kind == "dir":
                    queue.append((child, depth + 1))
    finally:
        ssh.close()
    return {"protocol": "ssh", "root": root_list[0] if len(root_list) == 1 else "",
            "roots": root_list, "rows": rows, "entries": len(rows),
            "truncated": truncated, "reason": reason,
            "elapsed_ms": int((time.monotonic() - started) * 1000)}
