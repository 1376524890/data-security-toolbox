"""Local incremental cache: skip re-reading a file whose analysis cannot change.

The key covers the file identity (device, inode, size, mtime_ns) *and* everything
that could change the result (engine version, rule-set version, and a fingerprint
of the effective scan configuration). Content is re-read when any of those move;
otherwise only the cheap metadata is compared.

What is stored is deliberately limited to identity, hashes and detection
*summaries*. No file content, no sample values and no reconstructable sample is
ever written - the cache must not become a second copy of the data it indexes.

The cache is a local convenience, not an integrity monitor: metadata cannot see
a modification that preserves size and mtime, which is stated as a limitation
rather than papered over. A corrupt or unreadable cache is discarded and rebuilt.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CACHE_VERSION = "1.0.0"
SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_cache (
    key TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    device INTEGER NOT NULL,
    inode INTEGER NOT NULL,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    engine_version TEXT NOT NULL,
    ruleset_version TEXT NOT NULL,
    config_fingerprint TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_analysis_cache_path ON analysis_cache(path);
CREATE TABLE IF NOT EXISTS cache_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def config_fingerprint(config: dict[str, Any]) -> str:
    """Stable digest of the settings that can change an analysis result.

    Only analysis-affecting keys are included, so unrelated edits (paths, limits)
    do not needlessly invalidate every cached file.
    """
    relevant = {
        "engine_version": config.get("engine_version", ""),
        "ruleset_version": config.get("ruleset_version", ""),
        "max_single_file_size": config.get("max_single_file_size", 0),
        "max_full_hash_size": config.get("max_full_hash_size", 0),
        "sample_block_size": config.get("sample_block_size", 0),
        "max_sample_rows": config.get("max_sample_rows", 0),
        "max_depth": config.get("max_depth", 0),
        "xlsx_max_rows": config.get("xlsx_max_rows", 0),
        "cache_version": CACHE_VERSION,
    }
    blob = json.dumps(relevant, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def key_for(path: str, stat: os.stat_result, *, engine_version: str, ruleset_version: str,
            fingerprint: str) -> str:
    material = "|".join(str(item) for item in (
        os.path.realpath(path), stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns,
        engine_version, ruleset_version, fingerprint,
    ))
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


@dataclass(slots=True)
class CacheStats:
    hits: int = 0
    misses: int = 0
    writes: int = 0
    invalid: int = 0
    unavailable: bool = False
    error: str = ""

    def as_evidence(self) -> dict[str, Any]:
        return {"hits": self.hits, "misses": self.misses, "writes": self.writes,
                "invalid": self.invalid, "available": not self.unavailable, "error": self.error}


class AnalysisCache:
    """SQLite-backed cache of per-file analysis summaries."""

    def __init__(self, path: Path | str, *, max_entries: int = 50_000) -> None:
        self.path = Path(path)
        self.max_entries = int(max_entries)
        self.stats = CacheStats()
        self._connection: sqlite3.Connection | None = None

    # -- lifecycle ----------------------------------------------------------
    def open(self) -> bool:
        """Open (creating the file if needed). Returns False instead of raising."""
        if self._connection is not None:
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(str(self.path), timeout=5.0)
            self._connection.executescript(SCHEMA)
            self._connection.execute(
                "INSERT OR REPLACE INTO cache_meta(name, value) VALUES('version', ?)", (CACHE_VERSION,))
            stored = self._connection.execute(
                "SELECT value FROM cache_meta WHERE name='version'").fetchone()
            if not stored or stored[0] != CACHE_VERSION:
                # Schema changed under us: treat as a miss for everything.
                self.reset()
            self._connection.commit()
            return True
        except sqlite3.Error as exc:
            self._fail(exc)
            return False

    def _fail(self, exc: Exception, *, invalid: bool = False) -> None:
        self.stats.unavailable = True
        self.stats.error = f"{type(exc).__name__}: {exc}"[:200]
        if invalid:
            self.stats.invalid += 1
        self.close()

    def close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            except sqlite3.Error:
                pass
            self._connection = None

    def reset(self) -> None:
        if self._connection is None:
            return
        try:
            self._connection.executescript("DROP TABLE IF EXISTS analysis_cache;")
            self._connection.executescript(SCHEMA)
            self._connection.commit()
        except sqlite3.Error as exc:
            self._fail(exc)

    # -- use ----------------------------------------------------------------
    def get(self, key: str) -> dict[str, Any] | None:
        if self._connection is None and not self.open():
            self.stats.misses += 1
            return None
        try:
            row = self._connection.execute(
                "SELECT payload FROM analysis_cache WHERE key = ?", (key,)).fetchone()
        except sqlite3.Error as exc:
            self._fail(exc)
            self.stats.misses += 1
            return None
        if not row:
            self.stats.misses += 1
            return None
        try:
            payload = json.loads(row[0])
        except ValueError:
            # A torn row is a miss, not a crash.
            self.stats.invalid += 1
            self.delete(key)
            self.stats.misses += 1
            return None
        self.stats.hits += 1
        return payload

    def put(self, key: str, *, path: str, stat: os.stat_result, engine_version: str,
            ruleset_version: str, fingerprint: str, payload: dict[str, Any]) -> None:
        if self._connection is None and not self.open():
            return
        try:
            self._connection.execute(
                "INSERT OR REPLACE INTO analysis_cache"
                "(key, path, device, inode, size, mtime_ns, engine_version, ruleset_version,"
                " config_fingerprint, payload, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (key, path, int(stat.st_dev), int(stat.st_ino), int(stat.st_size), int(stat.st_mtime_ns),
                 engine_version, ruleset_version, fingerprint,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True), time.time()))
            self._connection.commit()
            self.stats.writes += 1
            self._enforce_capacity()
        except sqlite3.Error as exc:
            self._fail(exc)

    def delete(self, key: str) -> None:
        if self._connection is None:
            return
        try:
            self._connection.execute("DELETE FROM analysis_cache WHERE key = ?", (key,))
            self._connection.commit()
        except sqlite3.Error as exc:
            self._fail(exc)

    def _enforce_capacity(self) -> None:
        try:
            count = self._connection.execute("SELECT COUNT(*) FROM analysis_cache").fetchone()[0]
            if count > self.max_entries:
                self._connection.execute(
                    "DELETE FROM analysis_cache WHERE key IN ("
                    " SELECT key FROM analysis_cache ORDER BY created_at ASC LIMIT ?)",
                    (count - self.max_entries,))
                self._connection.commit()
        except sqlite3.Error as exc:
            self._fail(exc)

    def purge_missing(self, *, limit: int = 500) -> int:
        """Drop rows whose file no longer exists, so the cache cannot grow forever."""
        if self._connection is None and not self.open():
            return 0
        removed = 0
        try:
            rows = self._connection.execute(
                "SELECT key, path FROM analysis_cache LIMIT ?", (limit,)).fetchall()
            for key, path in rows:
                if not Path(path).exists():
                    self._connection.execute("DELETE FROM analysis_cache WHERE key = ?", (key,))
                    removed += 1
            self._connection.commit()
        except (sqlite3.Error, OSError) as exc:
            self._fail(exc)
        return removed
