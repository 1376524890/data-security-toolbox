"""Rule-set hot update on the probe: bounded, verified, atomically switched.

The flow is deliberately short and recoverable:

    manifest -> (skip when already current) -> bounded download -> SHA256 check
    -> schema/engine/agent compatibility -> build a temporary engine
    -> bounded self test -> atomic switch -> state file

Failure keeps the previous rules and records why; the agent, heartbeat, capture
and report upload keep running. A probe that has never synced uses the rule pack
shipped inside the package - it never invents production rules locally.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

_APP_ROOT = Path(__file__).resolve().parent.parent
if (_APP_ROOT / "shared" / "sensitive_detection").is_dir() and str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

from shared.sensitive_detection import build_engine  # noqa: E402
from shared.sensitive_detection.engine import ENGINE_VERSION  # noqa: E402
from shared.sensitive_detection.matching import REGEX_BACKEND, SUPPORTS_TIMEOUT  # noqa: E402
from shared.sensitive_detection.ruleset import build_local_pack, load_rule_pack  # noqa: E402

STATE_FILE = "state.json"
CURRENT = "current"
PREVIOUS = "previous"
STAGING = "staging"
PACK_FILE = "ruleset.json"

# Synthetic values used for the bounded self test. They are generated from the
# documented formats, never copied from customer data.
SELF_TEST_TEXT = "手机号 13800138000 身份证 110101199003076173 邮箱 user@example.com"
SELF_TEST_REQUIRED = {"PHONE": "13800138000", "ID_CARD": "110101199003076173", "EMAIL": "user@example.com"}

SOURCE_SERVER = "server"
SOURCE_BUILTIN = "builtin"


class RuleSetUpdateError(RuntimeError):
    """This update is refused; the previously loaded rules stay in effect."""


@dataclass
class RuleSetStatus:
    version: str = ""
    sha256: str = ""
    rule_count: int = 0
    source: str = SOURCE_BUILTIN
    engine_version: str = ENGINE_VERSION
    loaded_at: str = ""
    last_attempt: str = ""
    last_error: str = ""
    last_error_at: str = ""
    updated_count: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_ruleset_version": self.version,
            "ruleset_sha256": self.sha256,
            "ruleset_rule_count": self.rule_count,
            "ruleset_source": self.source,
            "engine_version": self.engine_version,
            "ruleset_loaded_at": self.loaded_at,
            "ruleset_last_attempt": self.last_attempt,
            "ruleset_last_error": self.last_error,
            "ruleset_updated_count": self.updated_count,
        }


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


class RuleSetClient:
    """Loads, verifies and hot-swaps the detection rule pack."""

    def __init__(self, *, directory: Path, fetch_json: Callable[[str], dict],
                 fetch_bytes: Callable[[str, int], bytes], manifest_url: Callable[[str], str],
                 download_url: Callable[[str, str], str], agent_version: str,
                 max_pack_bytes: int = 2 * 1024 * 1024, self_test_timeout: float = 2.0,
                 enabled: bool = True) -> None:
        self.directory = Path(directory)
        self._fetch_json = fetch_json
        self._fetch_bytes = fetch_bytes
        self._manifest_url = manifest_url
        self._download_url = download_url
        self.agent_version = agent_version
        self.max_pack_bytes = int(max_pack_bytes)
        self.self_test_timeout = float(self_test_timeout)
        self.enabled = enabled
        self.status = RuleSetStatus()
        self._engine = None
        self._pack = None

    # -- layout -------------------------------------------------------------
    @property
    def state_path(self) -> Path:
        return self.directory / STATE_FILE

    @property
    def current_file(self) -> Path:
        return self.directory / CURRENT / PACK_FILE

    @property
    def previous_file(self) -> Path:
        return self.directory / PREVIOUS / PACK_FILE

    def capabilities(self) -> dict[str, Any]:
        return {
            "ruleset_hot_update": bool(self.enabled),
            "ruleset_source": self.status.source,
            "current_ruleset_version": self.status.version,
            "engine_version": ENGINE_VERSION,
            "regex_backend": REGEX_BACKEND,
            "regex_timeout": SUPPORTS_TIMEOUT,
            "rule_count": len(self._engine.rules) if self._engine is not None else 0,
        }

    # -- startup ------------------------------------------------------------
    def load_usable(self) -> str:
        """Pick the newest complete, self-consistent pack; else the built-in one.

        Returns a short description of what was chosen so the reason a probe is
        running on built-in rules is visible instead of implied.
        """
        for label, path in ((CURRENT, self.current_file), (PREVIOUS, self.previous_file)):
            payload = self._read_pack(path)
            if payload is None:
                continue
            try:
                pack = load_rule_pack(payload, agent_version=self.agent_version)
                engine = build_engine(pack.rules)
            except Exception as exc:
                self._record_error(f"本地规则包不可用({label}): {exc}")
                continue
            self._activate(engine, pack, source=SOURCE_SERVER, path=path)
            return label
        self._activate_builtin()
        return SOURCE_BUILTIN

    def _read_pack(self, path: Path) -> bytes | None:
        try:
            return path.read_bytes() if path.is_file() else None
        except OSError as exc:
            self._record_error(f"读取规则包失败: {exc}")
            return None

    def _activate_builtin(self) -> None:
        pack = build_local_pack(f"builtin-{ENGINE_VERSION}")
        engine = build_engine(pack.rules)
        self._engine, self._pack = engine, pack
        self.status.version = pack.ruleset_version
        self.status.sha256 = pack.sha256
        self.status.rule_count = pack.rule_count
        self.status.source = SOURCE_BUILTIN

    def _activate(self, engine, pack, *, source: str, path: Path | None = None) -> None:
        self._engine, self._pack = engine, pack
        self.status.version = pack.ruleset_version
        self.status.sha256 = pack.sha256
        self.status.rule_count = pack.rule_count
        self.status.source = source
        self.status.engine_version = pack.engine_version
        self.status.loaded_at = _now()
        # The error is deliberately *not* cleared here: loading a usable pack must
        # not hide why an earlier attempt failed. A clean server sync clears it.
        if path is not None:
            self._write_state(path)

    # -- hot update ---------------------------------------------------------
    def sync(self) -> RuleSetStatus:
        """One update attempt. Never raises: the caller keeps running."""
        self.status.last_attempt = _now()
        if not self.enabled:
            return self.status
        if not SUPPORTS_TIMEOUT:
            # Without a per-match timeout a hostile pack could hang the scan, so a
            # downloadable pack is refused outright and the reason is reported.
            self._record_error(f"regex 后端 {REGEX_BACKEND} 不支持超时，拒绝加载外部规则包")
            return self.status
        try:
            manifest = self._fetch_json(self._manifest_url(""))
            if manifest.get("up_to_date"):
                self.status.last_error = ""
                return self.status
            row = manifest.get("manifest") or {}
            version = str(row.get("ruleset_version") or "")
            expected = str(row.get("sha256") or "")
            size = int(row.get("size") or 0)
            if not version or not expected:
                raise RuleSetUpdateError("服务端 manifest 缺少版本或摘要")
            if size and size > self.max_pack_bytes:
                raise RuleSetUpdateError(f"规则包 {size} 字节超过探针上限 {self.max_pack_bytes}")
            payload = self._fetch_bytes(self._download_url(version), self.max_pack_bytes)
            if not payload:
                raise RuleSetUpdateError("规则包内容为空")
            actual = hashlib.sha256(payload).hexdigest()
            if actual != expected:
                raise RuleSetUpdateError(f"SHA256 不匹配: 期望 {expected[:12]} 实际 {actual[:12]}")
            pack = load_rule_pack(payload, agent_version=self.agent_version, expected_sha256=expected)
            engine = build_engine(pack.rules)
            self._self_test(engine)
            self._stage(payload, version)
            self._switch(version)
            self._activate(engine, pack, source=SOURCE_SERVER, path=self.current_file)
            self.status.updated_count += 1
            self.status.last_error = ""
            self.status.last_error_at = ""
            return self.status
        except Exception as exc:  # any failure keeps the previous rules in place
            self._record_error(f"规则热更新失败: {type(exc).__name__}: {exc}")
            return self.status

    def _self_test(self, engine) -> None:
        enabled = [rule for rule in engine.rules if rule.get("enabled", True)]
        if not enabled:
            raise RuleSetUpdateError("规则包没有启用规则")
        started = time.monotonic()
        hits = engine.scan_text(SELF_TEST_TEXT, source_type="text")
        elapsed = time.monotonic() - started
        if elapsed > self.self_test_timeout:
            raise RuleSetUpdateError(f"自测超时 {elapsed:.2f}s")
        if getattr(engine.last_report, "timeouts", None):
            raise RuleSetUpdateError(f"自测中有规则超时: {engine.last_report.timeouts}")
        found = {hit.entity for hit in hits if hit.count}
        declared = {rule["entity"] for rule in enabled if rule.get("pattern")}
        for entity, sample in SELF_TEST_REQUIRED.items():
            if entity in declared and entity not in found:
                raise RuleSetUpdateError(f"自测失败: {entity} 规则存在但未识别合成样例 {sample[:6]}…")

    def _stage(self, payload: bytes, version: str) -> None:
        staging = self.directory / STAGING
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True, exist_ok=True)
        temporary = staging / f"{PACK_FILE}.tmp"
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, staging / PACK_FILE)
        (self.directory / "state.json.staging").write_text(
            json.dumps({"version": version, "sha256": hashlib.sha256(payload).hexdigest()}),
            encoding="utf-8")

    def _switch(self, version: str) -> None:
        """Atomic publish: whole directories are renamed, never patched in place."""
        self.directory.mkdir(parents=True, exist_ok=True)
        staging = self.directory / STAGING
        current = self.directory / CURRENT
        previous = self.directory / PREVIOUS
        if not (staging / PACK_FILE).is_file():
            raise RuleSetUpdateError("staging 目录缺少规则包")
        if previous.exists():
            shutil.rmtree(previous)
        if current.exists():
            os.replace(current, previous)
        os.replace(staging, current)

    def _write_state(self, path: Path) -> None:
        state = {
            "version": self.status.version,
            "sha256": self.status.sha256,
            "rule_count": self.status.rule_count,
            "source": self.status.source,
            "loaded_at": self.status.loaded_at,
            "last_error": self.status.last_error,
            "last_error_at": self.status.last_error_at,
            "updated_count": self.status.updated_count,
        }
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
            os.replace(temporary, self.state_path)
        except OSError as exc:
            self._record_error(f"规则状态写入失败: {exc}")

    def _record_error(self, message: str) -> None:
        self.status.last_error = str(message)[:400]
        self.status.last_error_at = _now()

    # -- scan snapshot ------------------------------------------------------
    def engine_snapshot(self):
        """The engine to pin for one scan task.

        A hot update only affects later tasks: a running report can never mix two
        rule versions without saying so.
        """
        if self._engine is None:
            self.load_usable()
        return self._engine

    def snapshot_version(self) -> str:
        return self.status.version
