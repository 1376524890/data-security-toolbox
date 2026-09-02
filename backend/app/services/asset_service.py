from typing import Any


DB_SERVICES = {
    "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "oracle": "Oracle",
    "mssql": "Microsoft SQL Server",
    "mongodb": "MongoDB",
    "redis": "Redis",
}

WEB_SERVICES = {"http", "https", "nginx", "apache", "tomcat", "iis", "caddy"}
FILE_SERVICES = {"smb", "ftp", "sftp", "nfs", "samba", "webdav"}
NETWORK_SERVICES = {"snmp", "ssh", "telnet", "rdp", "vnc", "sip", "mqtt"}


def classify_service(port: int, service: str) -> str:
    name = service.lower().strip()
    if name in DB_SERVICES:
        return "database"
    if name in WEB_SERVICES or port in {80, 443, 8080, 8443}:
        return "web"
    if name in FILE_SERVICES or port in {21, 22, 445, 139, 2049}:
        return "file"
    if name in NETWORK_SERVICES or port in {23, 25, 161, 3389, 5900}:
        return "network"
    if port in {5432, 3306, 1521, 1433, 27017, 6379}:
        return "database"
    return "service"


def sensitive_categories(service: str, hostname: str = "", metadata: dict[str, Any] | None = None) -> list[str]:
    meta = metadata or {}
    text = f"{service} {hostname} {meta}".lower()
    categories: list[str] = []
    mappings = {
        "customer": ["customer", "client", "user"],
        "finance": ["finance", "payment", "bank", "invoice", "ledger"],
        "health": ["health", "patient", "medical", "clinical"],
        "credentials": ["credential", "password", "secret", "key"],
        "pii": ["pii", "identity", "idcard", "phone", "mobile"],
        "source_code": ["git", "svn", "jenkins", "source", "code"],
    }
    for category, keywords in mappings.items():
        if any(keyword in text for keyword in keywords):
            categories.append(category)
    return categories


def risk_level(asset_type: str, service: str, public_exposed: bool = False) -> str:
    name = service.lower()
    if public_exposed and asset_type in {"database", "web", "file"}:
        return "High"
    if asset_type == "database" or name in {"telnet", "snmp", "ftp", "smtp"}:
        return "High"
    if asset_type in {"web", "file", "network"}:
        return "Medium"
    return "Low"


def classify_assets(payload: dict[str, Any]) -> list[dict[str, Any]]:
    hostname = payload.get("hostname", "")
    os_name = payload.get("os", "")
    ip = payload.get("ip", "0.0.0.0")
    public_exposed = bool(payload.get("public_exposed", False))
    services = payload.get("services", [])
    if not isinstance(services, list):
        services = []
    if not services:
        services = [{"port": 0, "service": "host"}]
    assets: list[dict[str, Any]] = []
    for item in services:
        port = int(item.get("port", 0))
        service = str(item.get("service", ""))
        asset_type = classify_service(port, service)
        assets.append({
            "ip": ip,
            "hostname": hostname,
            "os": os_name,
            "port": port,
            "protocol": str(item.get("protocol", "tcp")).lower(),
            "service": service,
            "asset_type": asset_type,
            "risk_level": risk_level(asset_type, service, public_exposed),
            "sensitive_categories": sensitive_categories(service, hostname, payload.get("metadata", {})),
            "metadata": item,
        })
    return assets


def asset_relations(assets: list[dict[str, Any]]) -> list[dict[str, str]]:
    by_host: dict[str, list[dict[str, Any]]] = {}
    for asset in assets:
        by_host.setdefault(asset["ip"], []).append(asset)
    relations = []
    for ip, items in by_host.items():
        for item in items:
            relations.append({"source": ip, "target": f"{item['service']}:{item['port']}", "relation": "runs"})
    return relations

