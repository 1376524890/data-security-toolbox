from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field, model_validator


class ProbeRegister(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    hostname: str = ""
    ip_address: str = ""
    metadata: dict[str, Any] = {}
    deployment_id: int | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1)


class ProbeOut(BaseModel):
    id: int
    name: str
    hostname: str
    ip_address: str
    status: str
    last_seen: datetime | None
    metadata: dict[str, Any]


class ProbeScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1, description="要扫描的目标：IP / CIDR / 范围")
    discovery: bool = True
    top_ports: int = Field(default=1000, ge=1, le=65535)
    nuclei: bool = False
    nuclei_tags: str = ""
    nuclei_templates: str = ""


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=256, description="目标：IP / 主机名 / CIDR / 范围，如 192.168.110.0/24 或 192.168.110.1")
    discovery: bool = True
    top_ports: int = Field(default=1000, ge=1, le=65535)
    public_exposed: bool = False
    nuclei: bool = False
    nuclei_tags: str = ""
    nuclei_templates: str = ""


class Heartbeat(BaseModel):
    status: str = "online"
    metadata: dict[str, Any] = {}


class AssetOut(BaseModel):
    id: int
    probe_id: int | None
    ip: str
    hostname: str
    os: str
    port: int
    protocol: str
    service: str
    asset_type: str
    risk_level: str
    sensitive_categories: list[str]
    metadata: dict[str, Any]


class FileOut(BaseModel):
    id: int
    probe_id: int | None
    name: str
    path: str
    size: int
    sha256: str
    md5: str = ""
    file_type: str
    metadata_json: dict[str, Any]
    risk_level: str


class PcapOut(BaseModel):
    id: int
    probe_id: int | None
    filename: str
    storage_path: str
    size: int
    sha256: str
    packet_count: int
    duration: float
    capture_start: str
    capture_end: str
    protocol_summary: dict[str, Any]
    status: str


class TaskOut(BaseModel):
    id: int
    kind: str
    status: str
    progress: int
    current_stage: str
    log: str
    payload: dict[str, Any]
    result: dict[str, Any]
    error: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class LogAnalysisRequest(BaseModel):
    content: str


class GenerateReportRequest(BaseModel):
    title: str = "数据安全检测报告"
    report_type: str = "security"
    format: str = "pdf"


class TaskCreate(BaseModel):
    kind: str
    payload: dict[str, Any] = {}


class ProbeDeploymentPreflightRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    auth_type: Literal["password", "private_key"] = "password"
    password: str | None = None
    private_key: str | None = None
    key_passphrase: str | None = None
    profile: Literal["lite", "standard", "sensor"] = "standard"
    backend_url: str = Field(default='', max_length=1024)

    @model_validator(mode="after")
    def credential_exclusive(self) -> "ProbeDeploymentPreflightRequest":
        if self.backend_url:
            from urllib.parse import urlsplit
            parsed = urlsplit(self.backend_url)
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or any(ord(c) < 32 for c in self.backend_url):
                raise ValueError('回连地址必须是有效 HTTP/HTTPS 平台地址，不含账号、查询参数或控制字符')
            self.backend_url = self.backend_url.rstrip('/')
        if self.auth_type == "password":
            if not self.password:
                raise ValueError("password is required for password auth")
            if self.private_key:
                raise ValueError("private_key and password are mutually exclusive")
        else:
            if not self.private_key:
                raise ValueError("private_key is required for key auth")
            if self.password:
                raise ValueError("private_key and password are mutually exclusive")
        return self


class ProbeDeploymentCreate(ProbeDeploymentPreflightRequest):
    name: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)


class ProbeDeploymentOut(BaseModel):
    id: int
    name: str
    host: str
    port: int
    username: str
    auth_type: str
    profile: str
    status: str
    progress: int
    current_stage: str
    error_code: str
    error_message: str
    probe_id: int | None
    package_version: str
    created_by: str
    credential_destroyed: bool
    callback_deadline: datetime | None
    registered_at: datetime | None
    first_heartbeat_at: datetime | None
    preflight_result: dict[str, Any]
    result: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ProbeDeploymentEventOut(BaseModel):
    id: int
    seq: int
    stage: str
    message: str
    created_at: datetime


class ProbeDeploymentDetail(ProbeDeploymentOut):
    events: list[ProbeDeploymentEventOut] = Field(default_factory=list)
