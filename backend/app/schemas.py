from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator


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
    top_ports: int = Field(default=200, ge=1, le=65535)
    ports: list[int] = Field(default_factory=list, max_length=256, description="显式端口列表；为空时按 top_ports 扫描")
    nuclei: bool = False
    nuclei_tags: str = ""
    nuclei_templates: str = ""

    @field_validator("ports")
    @classmethod
    def ports_valid(cls, values: list[int]) -> list[int]:
        if any(int(item) < 1 or int(item) > 65535 for item in values):
            raise ValueError("invalid tcp port")
        return sorted({int(item) for item in values})


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=256, description="目标：IP / 主机名 / CIDR / 范围，如 192.168.110.0/24 或 192.168.110.1")
    discovery: bool = True
    top_ports: int = Field(default=200, ge=1, le=65535)
    ports: list[int] = Field(default_factory=list, max_length=256, description="显式端口列表；为空时按 top_ports 扫描")
    public_exposed: bool = False
    nuclei: bool = False
    nuclei_tags: str = ""
    nuclei_templates: str = ""
    probe_id: int | None = Field(default=None, ge=1, description="使用该探针就近扫描（留空则从平台/worker 扫描）")

    @field_validator("ports")
    @classmethod
    def ports_valid(cls, values: list[int]) -> list[int]:
        if any(int(item) < 1 or int(item) > 65535 for item in values):
            raise ValueError("invalid tcp port")
        return sorted({int(item) for item in values})


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


def _validate_ssh_credential(auth_type: str, password: str | None, private_key: str | None) -> None:
    """Reject an ambiguous or incomplete SSH credential.

    Shared by every request that carries one - deploy, retry, remove - so a new
    entry point cannot quietly accept a password for key auth, or neither.
    """
    if auth_type == "password":
        if not password:
            raise ValueError("password is required for password auth")
        if private_key:
            raise ValueError("private_key and password are mutually exclusive")
        return
    if not private_key:
        raise ValueError("private_key is required for key auth")
    if password:
        raise ValueError("private_key and password are mutually exclusive")


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
    data_paths: list[str] = Field(default_factory=list, max_length=32, description="探针所在服务器要采集的数据资产目录")
    data_interval_seconds: int = Field(default=3600, ge=60, le=86400)
    data_max_files: int = Field(default=200, ge=1, le=2000)
    data_max_depth: int = Field(default=3, ge=0, le=8)
    data_include_databases: bool = True
    #: Keep the SSH credential encrypted until the owning task ends, so the
    #: platform can uninstall this task-dedicated probe itself. Off by default:
    #: an operator-dispatched deployment still has its credential destroyed the
    #: moment the install finishes.
    retain_credential: bool = False

    @field_validator("data_paths")
    @classmethod
    def data_paths_valid(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            item = str(value).strip()
            if not item:
                continue
            if not item.startswith('/') or '..' in item.split('/') or len(item) > 512:
                raise ValueError('数据资产目录必须是绝对路径且不含 ".."')
            if item not in cleaned:
                cleaned.append(item)
        return cleaned

    @model_validator(mode="after")
    def credential_exclusive(self) -> "ProbeDeploymentPreflightRequest":
        if self.backend_url:
            from urllib.parse import urlsplit
            parsed = urlsplit(self.backend_url)
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or any(ord(c) < 32 for c in self.backend_url):
                raise ValueError('回连地址必须是有效 HTTP/HTTPS 平台地址，不含账号、查询参数或控制字符')
            self.backend_url = self.backend_url.rstrip('/')
        _validate_ssh_credential(self.auth_type, self.password, self.private_key)
        return self


class ProbeDeploymentCreate(ProbeDeploymentPreflightRequest):
    name: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)


class ProbeRemovalCreate(BaseModel):
    """Remove a probe from a target host.

    Reaching the host needs the same credential a deployment needs, but not a
    profile or a callback URL: the uninstaller only stops the service, deletes
    the files the installer created and reports what it found. The flags default
    to the strictest reading, and the service account is only deleted when the
    installer's own marker proves this probe created it, so a shared ``dstprobe``
    survives unless ``remove_user`` says otherwise.
    """

    name: str = Field(default="", max_length=128)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    auth_type: Literal["password", "private_key"] = "password"
    password: str | None = None
    private_key: str | None = None
    key_passphrase: str | None = None
    idempotency_key: str = Field(min_length=1, max_length=128)
    probe_id: int | None = Field(default=None, description="平台探针记录 ID；带上后删除成功会一并清除该记录")
    keep_data: bool = False
    keep_user: bool = False
    remove_user: bool = False
    delete_record: bool = Field(default=False, description="远端清理成功后同时删除平台探针记录")

    @model_validator(mode="after")
    def credential_exclusive(self) -> "ProbeRemovalCreate":
        _validate_ssh_credential(self.auth_type, self.password, self.private_key)
        return self


class ProbeDeleteRequest(BaseModel):
    """Delete a probe record, optionally stripping its host in the same step.

    ``remove_remote`` turns a record deletion into a removal deployment: the
    platform connects to the probe's last known host with the credential given
    here, deletes the probe's files, and only then drops the record. Host and
    user override the values recorded at deploy time, which is what makes the
    button work for a probe that was registered by hand or whose deployment row
    is gone.
    """

    remove_remote: bool = False
    host: str | None = Field(default=None, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=128)
    auth_type: Literal["password", "private_key"] = "password"
    password: str | None = None
    private_key: str | None = None
    key_passphrase: str | None = None
    keep_data: bool = False
    keep_user: bool = False
    remove_user: bool = False

    @model_validator(mode="after")
    def credential_required_when_remote(self) -> "ProbeDeleteRequest":
        if self.remove_remote:
            _validate_ssh_credential(self.auth_type, self.password, self.private_key)
        return self


class ProbeDeploymentOut(BaseModel):
    id: int
    name: str
    action: str
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
    removal_options: dict[str, Any]
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
