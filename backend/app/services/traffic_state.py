from __future__ import annotations

import hashlib
import threading
import time
from typing import Any

import redis

from app.core.config import settings


class RollingTrafficState:
    """Redis-backed strict sliding-window traffic state for cross-segment detection.

    Each observation is stored in a Redis Sorted Set keyed by ``timestamp``.
    ``snapshot()`` first prunes members older than the requested window with
    ``ZREMRANGEBYSCORE`` so the returned set is a true sliding window, then
    returns the surviving members. A bounded in-process fallback keeps tests and
    degraded Redis environments functional.

    All keys carry a TTL so long-running probes never leave unbounded state.
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

    @staticmethod
    def _ttl() -> int:
        return max(int(settings.state_ttl_seconds), int(settings.port_scan_window_seconds) * 2)

    def observe(self, probe: str, flows: list[dict[str, Any]], now: float | None = None) -> None:
        timestamp = now or time.time()
        for flow in flows:
            src = str(flow.get("src_ip") or "")
            dst = str(flow.get("dst_ip") or "")
            port = int(flow.get("dst_port") or 0)
            if not src or not dst:
                continue
            payload = {
                "dst_ports": [str(port)] if port else [],
                "dst_ips": [dst],
                "packets": int(flow.get("packets") or 1),
                "bytes": int(flow.get("bytes") or 0),
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
            self._merge(probe, src, payload, timestamp)

    def _merge(self, probe: str, src: str, payload: dict[str, Any], timestamp: float) -> None:
        key = self._key(probe, src)
        ttl = self._ttl()
        if self._redis is not None:
            try:
                pipe = self._redis.pipeline(transaction=False)
                for port in payload["dst_ports"]:
                    pipe.zadd(f"{key}:ports", {port: timestamp})
                for ip in payload["dst_ips"]:
                    pipe.zadd(f"{key}:ips", {ip: timestamp})
                pipe.incrby(f"{key}:packets", payload["packets"]).expire(f"{key}:packets", ttl)
                pipe.incrby(f"{key}:bytes", payload["bytes"]).expire(f"{key}:bytes", ttl)
                pipe.set(f"{key}:last", timestamp, ex=ttl)
                pipe.set(f"{key}:first", timestamp, nx=True, ex=ttl)
                pipe.expire(f"{key}:ports", ttl)
                pipe.expire(f"{key}:ips", ttl)
                pipe.execute()
                return
            except Exception:
                self._redis = None
        with self._lock:
            state = self._local.setdefault(key, {"ports": {}, "ips": {}, "packets": 0, "bytes": 0, "first_seen": timestamp, "last_seen": timestamp})
            for port in payload["dst_ports"]:
                state["ports"][port] = timestamp
            for ip in payload["dst_ips"]:
                state["ips"][ip] = timestamp
            state["packets"] += payload["packets"]
            state["bytes"] += payload["bytes"]
            state["first_seen"] = min(state["first_seen"], timestamp)
            state["last_seen"] = max(state["last_seen"], timestamp)

    def snapshot(self, probe: str, src: str, window_seconds: int | None = None, now: float | None = None) -> dict[str, Any]:
        key = self._key(probe, src)
        window = max(1, int(window_seconds or settings.port_scan_window_seconds))
        cutoff = (now if now is not None else time.time()) - window
        if self._redis is not None:
            try:
                pipe = self._redis.pipeline(transaction=False)
                pipe.zremrangebyscore(f"{key}:ports", 0, cutoff)
                pipe.zremrangebyscore(f"{key}:ips", 0, cutoff)
                pipe.zrange(f"{key}:ports", 0, -1)
                pipe.zrange(f"{key}:ips", 0, -1)
                pipe.get(f"{key}:packets")
                pipe.get(f"{key}:bytes")
                pipe.get(f"{key}:first")
                pipe.get(f"{key}:last")
                removed_ports, removed_ips, ports_raw, ips_raw, packets_raw, bytes_raw, first_raw, last_raw = pipe.execute()
                ports = sorted({int(item) for item in ports_raw if str(item).isdigit()})
                ips = sorted(set(ips_raw))
                return {
                    "dst_ports": ports,
                    "dst_ips": ips,
                    "packets": int(packets_raw or 0),
                    "bytes": int(bytes_raw or 0),
                    "first_seen": float(first_raw or 0),
                    "last_seen": float(last_raw or 0),
                }
            except Exception:
                self._redis = None
        with self._lock:
            state = self._local.get(key)
            if not state:
                return {"dst_ports": [], "dst_ips": [], "packets": 0, "bytes": 0, "first_seen": 0, "last_seen": 0}
            ports = sorted(int(item) for item, ts in state["ports"].items() if ts >= cutoff)
            ips = sorted(ip for ip, ts in state["ips"].items() if ts >= cutoff)
            return {
                "dst_ports": ports,
                "dst_ips": ips,
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
        """Window-based detection cooldown.

        Returns True when the same probe/src/rule fired within ``window_seconds``
        so a duplicate Finding is suppressed; once the window elapses a new
        Finding is allowed again.
        """
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
