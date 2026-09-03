from datetime import datetime, timezone
from typing import Any
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class User(TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), default="")
    role: Mapped[str] = mapped_column(String(64), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class AdminSession(Base):
    __tablename__ = "admin_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Probe(TimestampMixin, Base):
    __tablename__ = "probes"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(32), default="offline")
    token: Mapped[str] = mapped_column(String(255), default="")
    token_hash: Mapped[str] = mapped_column(String(64), default="")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    assets: Mapped[list["Asset"]] = relationship(back_populates="probe")


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), nullable=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    os: Mapped[str] = mapped_column(String(128), default="")
    port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(64), default="")
    service: Mapped[str] = mapped_column(String(128), default="")
    asset_type: Mapped[str] = mapped_column(String(128), default="unknown")
    risk_level: Mapped[str] = mapped_column(String(16), default="Low")
    sensitive_categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    probe: Mapped[Probe] = relationship(back_populates="assets")


class FileRecord(TimestampMixin, Base):
    __tablename__ = "files"
    id: Mapped[int] = mapped_column(primary_key=True)
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(512), index=True)
    path: Mapped[str] = mapped_column(String(1024), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    file_type: Mapped[str] = mapped_column(String(128), default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    risk_level: Mapped[str] = mapped_column(String(16), default="Low")


class PcapRecord(TimestampMixin, Base):
    __tablename__ = "pcaps"
    __table_args__ = (UniqueConstraint("probe_id", "segment_id", name="uq_pcap_probe_segment"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), nullable=True)
    segment_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    capture_interface: Mapped[str] = mapped_column(String(128), default="")
    capture_started_at: Mapped[str] = mapped_column(String(64), default="")
    capture_finished_at: Mapped[str] = mapped_column(String(64), default="")
    ingest_status: Mapped[str] = mapped_column(String(32), default="pending")
    analysis_status: Mapped[str] = mapped_column(String(32), default="pending")
    probe_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    filename: Mapped[str] = mapped_column(String(512), index=True)
    storage_path: Mapped[str] = mapped_column(String(1024), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    total_packet_count: Mapped[int] = mapped_column(Integer, default=0)
    indexed_packet_count: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    capture_start: Mapped[str] = mapped_column(String(64), default="")
    capture_end: Mapped[str] = mapped_column(String(64), default="")
    file_type: Mapped[str] = mapped_column(String(64), default="")
    protocol_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    retention_status: Mapped[str] = mapped_column(String(32), default="active")
    flows: Mapped[list["Flow"]] = relationship(back_populates="pcap", cascade="all, delete-orphan")
    packets: Mapped[list["PacketRecord"]] = relationship(back_populates="pcap", cascade="all, delete-orphan")
    anomalies: Mapped[list["Anomaly"]] = relationship(back_populates="pcap", cascade="all, delete-orphan")


class Flow(Base):
    __tablename__ = "flows"
    id: Mapped[int] = mapped_column(primary_key=True)
    pcap_id: Mapped[int] = mapped_column(ForeignKey("pcaps.id"), index=True)
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    src_port: Mapped[int] = mapped_column(Integer, default=0)
    dst_ip: Mapped[str] = mapped_column(String(64), index=True)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(64), index=True)
    app_protocol: Mapped[str] = mapped_column(String(64), default="")
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    start_time: Mapped[float] = mapped_column(Float, default=0.0)
    end_time: Mapped[float] = mapped_column(Float, default=0.0)
    pcap: Mapped[PcapRecord] = relationship(back_populates="flows")


class PacketRecord(Base):
    __tablename__ = "packets"
    id: Mapped[int] = mapped_column(primary_key=True)
    pcap_id: Mapped[int] = mapped_column(ForeignKey("pcaps.id"), index=True)
    number: Mapped[int] = mapped_column(Integer, index=True)
    timestamp: Mapped[float] = mapped_column(Float, index=True)
    src_ip: Mapped[str] = mapped_column(String(64), default="")
    dst_ip: Mapped[str] = mapped_column(String(64), default="")
    src_port: Mapped[int] = mapped_column(Integer, default=0)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(64), default="")
    length: Mapped[int] = mapped_column(Integer, default=0)
    info: Mapped[str] = mapped_column(Text, default="")
    pcap: Mapped[PcapRecord] = relationship(back_populates="packets")


class Anomaly(Base):
    __tablename__ = "anomalies"
    id: Mapped[int] = mapped_column(primary_key=True)
    pcap_id: Mapped[int] = mapped_column(ForeignKey("pcaps.id"), index=True)
    flow_id: Mapped[int] = mapped_column(ForeignKey("flows.id"), nullable=True)
    rule: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    pcap: Mapped[PcapRecord] = relationship(back_populates="anomalies")


class Task(TimestampMixin, Base):
    __tablename__ = "tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="Pending", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_stage: Mapped[str] = mapped_column(String(255), default="queued")
    log: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class AnalysisResult(TimestampMixin, Base):
    __tablename__ = "analysis_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), nullable=True)
    module: Mapped[str] = mapped_column(String(128), index=True)
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="Low")


class DetectionFinding(TimestampMixin, Base):
    __tablename__ = "detection_findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), nullable=True)
    target_type: Mapped[str] = mapped_column(String(64), index=True)
    target_id: Mapped[str] = mapped_column(String(128), default="")
    engine: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="Low")
    timestamp: Mapped[str] = mapped_column(String(64), default="")


class Incident(TimestampMixin, Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, default="")
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(128), default="pipeline")
    title: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    findings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="Low")
    timestamp: Mapped[str] = mapped_column(String(64), default="")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)


class Alert(TimestampMixin, Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("detection_findings.id"), nullable=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    title: Mapped[str] = mapped_column(String(255), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    source: Mapped[str] = mapped_column(String(128), default="pipeline", index=True)


class AlertDelivery(Base):
    __tablename__ = "alert_deliveries"
    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    channel: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(Text, default="")
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IOC(TimestampMixin, Base):
    __tablename__ = "iocs"
    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(1024), index=True)
    source: Mapped[str] = mapped_column(String(128), default="")
    first_seen: Mapped[str] = mapped_column(String(64), default="")
    last_seen: Mapped[str] = mapped_column(String(64), default="")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Vulnerability(TimestampMixin, Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=True)
    cve_id: Mapped[str] = mapped_column(String(64), index=True)
    cwe_id: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="Medium")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open")


class DataAsset(TimestampMixin, Base):
    __tablename__ = "data_assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(512), index=True)
    asset_type: Mapped[str] = mapped_column(String(128), index=True)
    sensitivity: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(128), default="file")
    columns: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class GraphRelation(Base):
    __tablename__ = "graph_relations"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_node: Mapped[str] = mapped_column(String(255), index=True)
    source_type: Mapped[str] = mapped_column(String(64), index=True)
    target_node: Mapped[str] = mapped_column(String(255), index=True)
    target_type: Mapped[str] = mapped_column(String(64), index=True)
    relation: Mapped[str] = mapped_column(String(64), index=True)
    risk: Mapped[str] = mapped_column(String(16), default="Low")


class Report(TimestampMixin, Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    report_type: Mapped[str] = mapped_column(String(64), default="security")
    format: Mapped[str] = mapped_column(String(16), default="html")
    storage_path: Mapped[str] = mapped_column(String(1024))
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AuditLog(TimestampMixin, Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(128))
    actor: Mapped[str] = mapped_column(String(128), default="system")
    target: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="Low")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class SystemSetting(TimestampMixin, Base):
    __tablename__ = "system_settings"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class IntegrationStatus(TimestampMixin, Base):
    __tablename__ = "integration_status"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    adapter_version: Mapped[str] = mapped_column(String(64), default="")
    installed: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    healthy: Mapped[bool] = mapped_column(Boolean, default=False)
    runtime_version: Mapped[str] = mapped_column(String(64), default="")
    supported_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    last_check: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="unavailable")
    message: Mapped[str] = mapped_column(Text, default="")


class OfflineResource(TimestampMixin, Base):
    __tablename__ = "offline_resources"
    id: Mapped[int] = mapped_column(primary_key=True)
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(128), default="")
    count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="imported", index=True)
    storage_path: Mapped[str] = mapped_column(String(1024), default="")
    manifest_path: Mapped[str] = mapped_column(String(1024), default="")
    resource_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LocalCve(TimestampMixin, Base):
    __tablename__ = "local_cves"
    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(128), default="offline")
    severity: Mapped[str] = mapped_column(String(16), default="Medium", index=True)
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    published: Mapped[str] = mapped_column(String(64), default="")
    modified: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
