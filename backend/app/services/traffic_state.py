from __future__ import annotations

import hashlib
import threading
import time
from typing import Any

import redis

from app.core.config import settings


class RollingTrafficState:
    """Redis-backed rolling traffic state for cross-segment detection.

    A small in-process fallback keeps tests and degraded Redis environments
    functional; production uses Redis keys with TTL.
    """

    def __init__(self) -> None:
        self._redis: redis.Redis | None = None
        self._local: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        try:
            self._redis = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5)
            self._redis.ping()
        except Exception:
            self._redis = None

    def _key(self, probe: str, src_ip: str) -> str:
        return f"traffic:{probe}:{src_ip}"

    def observe(self, probe: str, flows: list[dict[str, Any]], now: float | None = None) -> None:
        timestamp = now or time.time()
        for flow in flows:
            src = str(flow.get("src_ip") or "")
            dst = str(flow.get("dst_ip") or "")
            port = int(flow.get("dst_port") or 0)
            if not src or not dst:
                continue
            payload = {
                "dst_ports": [port] if port else [],
                "dst_ips": [dst],
                "packets": int(flow.get("packets") or 1),
                "bytes": int(flow.get("bytes") or 0),
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
            self._merge(probe, src, payload, timestamp)

    def _merge(self, probe: str, src: str, payload: dict[str, Any], timestamp: float) -> None:
        key = self._key(probe, src)
        if self._redis is not None:
            try:
                self._redis.pipeline(transaction=False).rpush(f"{key}:ports", *payload["dst_ports"]).expire(f"{key}:ports", settings.state_ttl_seconds).rpush(f"{key}:ips", *payload["dst_ips"]).expire(f"{key}:ips", settings.state_ttl_seconds).incrby(f"{key}:packets", payload["packets"]).expire(f"{key}:packets", settings.state_ttl_seconds).incrby(f"{key}:bytes", payload["bytes"]).expire(f"{key}:bytes", settings.state_ttl_seconds).set(f"{key}:last", timestamp, ex=settings.state_ttl_seconds).set(f"{key}:first", timestamp, nx=True, ex=settings.state_ttl_seconds).execute()
                return
            except Exception:
                self._redis = None
        with self._lock:
            state = self._local.setdefault(key, {"dst_ports": set(), "dst_ips": set(), "packets": 0, "bytes": 0, "first_seen": timestamp, "last_seen": timestamp})
            state["dst_ports"].update(payload["dst_ports"])
            state["dst_ips"].update(payload["dst_ips"])
            state["packets"] += payload["packets"]
            state["bytes"] += payload["bytes"]
            state["first_seen"] = min(state["first_seen"], timestamp)
            state["last_seen"] = max(state["last_seen"], timestamp)

    def snapshot(self, probe: str, src: str) -> dict[str, Any]:
        key = self._key(probe, src)
        if self._redis is not None:
            try:
                ports = sorted({int(item) for item in self._redis.lrange(f"{key}:ports", 0, -1) if str(item).isdigit()})
                ips = sorted(set(self._redis.lrange(f"{key}:ips", 0, -1)))
                packets = int(self._redis.get(f"{key}:packets") or 0)
                bytes_count = int(self._redis.get(f"{key}:bytes") or 0)
                first = float(self._redis.get(f"{key}:first") or 0)
                last = float(self._redis.get(f"{key}:last") or 0)
                return {"dst_ports": ports, "dst_ips": ips, "packets": packets, "bytes": bytes_count, "first_seen": first, "last_seen": last}
            except Exception:
                self._redis = None
        with self._lock:
            state = self._local.get(key)
            if not state:
                return {"dst_ports": [], "dst_ips": [], "packets": 0, "bytes": 0, "first_seen": 0, "last_seen": 0}
            return {
                "dst_ports": sorted(state["dst_ports"]),
                "dst_ips": sorted(state["dst_ips"]),
                "packets": state["packets"],
                "bytes": state["bytes"],
                "first_seen": state["first_seen"],
                "last_seen": state["last_seen"],
            }

    def dedup_key(self, probe: str, src: str, rule_id: str) -> str:
        digest = hashlib.sha256(f"{probe}|{src}|{rule_id}".encode()).hexdigest()
        return f"detect:{probe}:{digest}"

    def reset(self) -> None:
        with self._lock:
            self._local.clear()
        if self._redis is not None:
            try:
                keys = list(self._redis.scan_iter("traffic:*"))
                keys += list(self._redis.scan_iter("detect:*"))
                if keys:
                    self._redis.delete(*keys)
            except Exception:
                pass

    def seen(self, probe: str, src: str, rule_id: str, window_seconds: int | None = None) -> bool:
        key = self.dedup_key(probe, src, rule_id)
        window = window_seconds or settings.port_scan_window_seconds
        if self._redis is not None:
            try:
                if self._redis.get(key):
                    return True
                self._redis.set(key, "1", ex=window)
                return False
            except Exception:
                self._redis = None
        with self._lock:
            if self._local.get(key):
                return True
            self._local[key] = {"expires": time.time() + window}
            return False


rolling_traffic_state = RollingTrafficState()
