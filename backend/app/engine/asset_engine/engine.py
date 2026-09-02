import shutil
import socket
import subprocess
from typing import Any

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult


SERVICE_PATTERNS: dict[str, list[str]] = {
    "mysql": ["mysql", "5.7", "8.0"],
    "postgresql": ["postgresql", "postgres"],
    "mongodb": ["mongodb", "mongo"],
    "redis": ["redis", "redis-server"],
    "oracle": ["oracle", "listener"],
    "nginx": ["nginx", "Server: nginx"],
    "apache": ["apache", "httpd"],
    "iis": ["iis", "microsoft-iis"],
    "tomcat": ["tomcat", "apache-coyote"],
    "kafka": ["kafka", "broker"],
    "rabbitmq": ["rabbitmq", "amqp"],
    "elasticsearch": ["elasticsearch", "opensearch"],
    "web": ["http", "https"],
}


def classify_service(port: int, service: str, banner: str = "") -> str:
    text = f"{service} {banner}".lower()
    for category, keywords in SERVICE_PATTERNS.items():
        if any(keyword.lower() in text for keyword in keywords):
            return category
    if port in {5432, 3306, 1521, 1433, 27017, 6379}:
        return "database"
    if port in {80, 443, 8080, 8443}:
        return "web"
    if port in {9092}:
        return "kafka"
    if port in {5672}:
        return "rabbitmq"
    if port in {9200, 9300}:
        return "elasticsearch"
    if port in {21, 22, 445, 139, 2049}:
        return "file"
    if port in {23, 25, 161, 3389, 5900}:
        return "network"
    return "service"


def banner_probe(host: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return sock.recv(1024).decode("utf-8", "replace").strip()
    except Exception:
        return ""


def nmap_fingerprint(host: str, port: int) -> str:
    if not shutil.which("nmap"):
        return ""
    try:
        result = subprocess.run(["nmap", "-sV", "-p", str(port), "--version-light", host], capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return ""


class AssetEngine(DetectionEngine):
    name = "asset_engine"
    version = "2.0.0"

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        host = context.data.get("host", context.data.get("ip", ""))
        public_exposed = bool(context.data.get("public_exposed", context.data.get("exposure_factor", False)))
        services = context.data.get("services", [])
        if not isinstance(services, list):
            services = []
        for item in services:
            port = int(item.get("port", 0))
            service = str(item.get("service", ""))
            banner = str(item.get("banner", "")) or banner_probe(host, port)
            category = classify_service(port, service, banner)
            weak_auth = bool(item.get("weak_auth", False))
            if any(word in banner.lower() for word in ["noauth", "authentication not required", "no password"]):
                weak_auth = True
            if category in {"redis", "mysql", "postgresql", "mongodb", "oracle"} and public_exposed:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="ASSET_PUBLIC_DB_001",
                    severity="Critical",
                    confidence=0.95,
                    evidence={"host": host, "port": port, "service": service, "category": category, "banner": banner},
                    recommendation="数据库服务不得暴露在公网，应限制来源网段并启用加密认证。",
                ).normalize())
            if category in {"redis", "mysql", "postgresql", "mongodb", "oracle"} and weak_auth:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="ASSET_DB_WEAK_AUTH_001",
                    severity="High",
                    confidence=0.9,
                    evidence={"host": host, "port": port, "category": category, "banner": banner, "weak_auth": True},
                    recommendation="启用强认证、最小权限和访问审计，禁止空密码或匿名认证。",
                ).normalize())
            if category in {"web", "nginx", "apache", "iis", "tomcat"} and public_exposed:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="ASSET_PUBLIC_WEB_001",
                    severity="Medium",
                    confidence=0.8,
                    evidence={"host": host, "port": port, "service": service},
                    recommendation="公网 Web 服务应启用 TLS、WAF、补丁管理和访问日志。",
                ).normalize())
        return findings

