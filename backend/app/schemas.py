from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class ProbeRegister(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    hostname: str = ""
    ip_address: str = ""
    metadata: dict[str, Any] = {}


class ProbeOut(BaseModel):
    id: int
    name: str
    hostname: str
    ip_address: str
    status: str
    last_seen: datetime | None
    metadata: dict[str, Any]


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


class AlgorithmRandomnessRequest(BaseModel):
    data: str


class EvaluateRequest(BaseModel):
    X: list[list[float]]
    y: list[int]


class LogAnalysisRequest(BaseModel):
    content: str


class GenerateReportRequest(BaseModel):
    title: str = "数据安全检测报告"
    report_type: str = "security"
    format: str = "pdf"


class TaskCreate(BaseModel):
    kind: str
    payload: dict[str, Any] = {}
