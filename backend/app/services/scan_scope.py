"""The scope a data-asset scan may never be given.

A checker that scans itself produces findings about the platform instead of about
the customer. ``/opt/data-security-toolbox`` holds the probe's own bundled
interpreter and rule files, ``/etc/data-security-toolbox`` its credentials and
``/var/lib/data-security-toolbox`` its spool and cache; a ``password = ...`` in our
own engine source is not the customer's credential, and reporting it as one is a
false positive by construction.

So every job is narrowed before it is queued: the probe's install tree joins the
job's exclusions, and an include path that *is* that tree is refused outright
rather than answered with an empty scan that claims to have completed. The
exclusion travels with the task payload, so what a probe was asked to do stays
visible in one place.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

#: The probe's own install tree, from ``probe/install.sh`` and its systemd unit.
OWN_TREE = (
    "/opt/data-security-toolbox",
    "/etc/data-security-toolbox",
    "/var/lib/data-security-toolbox",
)


class ScanScopeError(ValueError):
    """The requested scope can never produce a finding about the customer."""


def _normalise(value: Any) -> str:
    text = str(value or "").strip()
    while "//" in text:
        text = text.replace("//", "/")
    return text.rstrip("/") or "/"


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def own_tree_in(paths: Iterable[Any]) -> list[str]:
    """The requested include paths that sit inside the probe's own install tree."""
    offenders: list[str] = []
    for raw in paths or ():
        text = str(raw or "").strip()
        path = _normalise(text)
        # A trailing separator, a doubled slash and a bare "/" are all handled
        # here so a request cannot slip past by spelling the path differently.
        if not text or path == "/":
            continue
        if any(_inside(path, root) for root in OWN_TREE) and text not in offenders:
            offenders.append(text)
    return offenders


def exclude_own_tree(config: dict[str, Any]) -> dict[str, Any]:
    """A job config with the probe's own tree excluded, or a refusal.

    Excluding rather than only refusing is what keeps a broad include honest: an
    operator who scans ``/`` gets the customer's files and never ours.
    """
    offenders = own_tree_in(config.get("paths") or [])
    if offenders:
        raise ScanScopeError(
            "扫描范围包含工具箱自身目录，探针不会采集：" + "、".join(offenders)
        )
    excludes = [str(item) for item in (config.get("exclude_paths") or [])]
    known = {_normalise(item) for item in excludes}
    for root in OWN_TREE:
        if root not in known:
            excludes.append(root)
            known.add(root)
    return {**config, "exclude_paths": excludes}
