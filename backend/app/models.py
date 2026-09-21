from datetime import datetime, timezone
from typing import Any
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
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
    deployment_id: Mapped[int | None] = mapped_column(ForeignKey("probe_deployments.id", ondelete="SET NULL"), nullable=True, index=True)


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
    md5: Mapped[str] = mapped_column(String(64), default="", index=True)
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
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    correlation_key: Mapped[str] = mapped_column(String(64), default="", index=True)
    alert_instance: Mapped[int] = mapped_column(Integer, default=1)
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


class AlertHit(Base):
    """One finding that contributed to an Alert.

    Suppression keeps a single live Alert per subject, so the individual
    observations would otherwise be lost: ``alerts.finding_id`` only points at
    the first one. Every hit records its own finding, the subject it resolved to
    and its own risk, and the flags say which row is the first, latest and
    highest-risk observation.
    """

    __tablename__ = "alert_hits"
    __table_args__ = (UniqueConstraint("alert_id", "finding_id", name="uq_alert_hit_finding"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    # Deleting an alert or a finding must not leave its hit log behind.
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("detection_findings.id", ondelete="CASCADE"), index=True)
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(128), default="")
    asset: Mapped[str] = mapped_column(String(255), default="", index=True)
    ioc: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    is_first: Mapped[bool] = mapped_column(Boolean, default=False)
    is_latest: Mapped[bool] = mapped_column(Boolean, default=False)
    is_highest_risk: Mapped[bool] = mapped_column(Boolean, default=False)


class AlertDelivery(Base):
    __tablename__ = "alert_deliveries"
    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    channel: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
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


# --- central rule sets -------------------------------------------------------
# The server is the single source of truth for detection rules. `rules` is the
# editable working copy of a rule set; `rule_set_versions` holds the immutable
# published bytes a probe downloads, so editing never changes what an already
# published version contains and a rollback is a new version, not an overwrite.
class RuleSet(TimestampMixin, Base):
    __tablename__ = "rule_sets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    active_version_id: Mapped[int] = mapped_column(ForeignKey("rule_set_versions.id"), nullable=True)


class Rule(TimestampMixin, Base):
    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("rule_set_id", "rule_id", name="uq_rules_set_rule_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_set_id: Mapped[int] = mapped_column(ForeignKey("rule_sets.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    entity: Mapped[str] = mapped_column(String(64), index=True)
    pattern: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    validator: Mapped[str] = mapped_column(String(64), default="")
    field_hints: Mapped[list[str]] = mapped_column(JSON, default=list)
    keywords: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(32), default="builtin")
    description: Mapped[str] = mapped_column(Text, default="")


class RuleSetVersion(TimestampMixin, Base):
    __tablename__ = "rule_set_versions"
    __table_args__ = (UniqueConstraint("rule_set_id", "version", name="uq_ruleset_version"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_set_id: Mapped[int] = mapped_column(ForeignKey("rule_sets.id"), index=True)
    version: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="published", index=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    engine_version: Mapped[str] = mapped_column(String(32), default="")
    min_agent_version: Mapped[str] = mapped_column(String(32), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    rule_count: Mapped[int] = mapped_column(Integer, default=0)
    origin_version: Mapped[str] = mapped_column(String(64), default="")
    changelog: Mapped[str] = mapped_column(String(512), default="")
    published_by: Mapped[str] = mapped_column(String(128), default="")
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    package: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class ScanProfile(TimestampMixin, Base):
    """A versioned, reusable scan configuration.

    A task snapshots the profile it ran with, so editing a profile never changes
    the effective scope of a job that has already been handed to a probe. The
    defaults mirror the shipped 3.3.1 behaviour exactly, so an absent profile and
    an unconfigured scan behave the same.
    """

    __tablename__ = "scan_profiles"
    __table_args__ = (UniqueConstraint("name", "version", name="uq_scan_profile_version"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    description: Mapped[str] = mapped_column(String(512), default="")
    # Scope
    include_paths: Mapped[list[str]] = mapped_column(JSON, default=list)
    exclude_paths: Mapped[list[str]] = mapped_column(JSON, default=list)
    file_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Bounds
    max_files: Mapped[int] = mapped_column(Integer, default=200)
    max_dirs: Mapped[int] = mapped_column(Integer, default=500)
    max_depth: Mapped[int] = mapped_column(Integer, default=3)
    max_runtime_seconds: Mapped[int] = mapped_column(Integer, default=120)
    max_bytes_read: Mapped[int] = mapped_column(BigInteger, default=512 * 1024 * 1024)
    max_single_file_size: Mapped[int] = mapped_column(BigInteger, default=2 * 1024 * 1024)
    max_full_hash_size: Mapped[int] = mapped_column(BigInteger, default=8 * 1024 * 1024)
    # Sampling
    large_file_sampling: Mapped[bool] = mapped_column(Boolean, default=True)
    sample_block_size: Mapped[int] = mapped_column(Integer, default=64 * 1024)
    max_sample_rows: Mapped[int] = mapped_column(Integer, default=25)
    # Soft resource limits: throttle/abort signals, not OS-enforced isolation.
    max_cpu_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    max_rss_mb: Mapped[float] = mapped_column(Float, default=0.0)
    # XLSX is the one container that is parsed; bound it explicitly.
    xlsx_max_entries: Mapped[int] = mapped_column(Integer, default=512)
    xlsx_max_uncompressed_bytes: Mapped[int] = mapped_column(BigInteger, default=64 * 1024 * 1024)
    xlsx_max_compression_ratio: Mapped[float] = mapped_column(Float, default=200.0)
    xlsx_max_shared_strings: Mapped[int] = mapped_column(Integer, default=200_000)
    xlsx_max_sheets: Mapped[int] = mapped_column(Integer, default=32)
    xlsx_max_columns: Mapped[int] = mapped_column(Integer, default=256)
    xlsx_max_rows: Mapped[int] = mapped_column(Integer, default=200)
    # Scheduled collection stays off unless an operator turns it on.
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    scheduled: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    created_by: Mapped[str] = mapped_column(String(128), default="")


# --- data objects, instances and detections ----------------------------------
# Three levels instead of one flat row. A `DataObject` is the logical identity of
# the content, an `AssetInstance` is one physical copy on one probe, and a
# `Detection` is one sensitive category observed on one instance. Equal full
# SHA256 is the only thing that may aggregate two files into one object; a partial
# fingerprint can only ever produce a clearly labelled candidate. `data_assets`
# stays as a derived compatibility projection for the legacy pages, so nothing old
# breaks and a divergence can be rebuilt instead of being unrecoverable.
class DataObject(TimestampMixin, Base):
    __tablename__ = "data_objects"
    __table_args__ = (UniqueConstraint("object_key", name="uq_data_object_key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    #: Deterministic identity key. Never a bare filename or size, which would
    #: silently merge unrelated files.
    object_key: Mapped[str] = mapped_column(String(192), index=True)
    object_type: Mapped[str] = mapped_column(String(64), index=True)
    #: Empty when no reliable hash exists. A missing hash is never fabricated.
    content_hash: Mapped[str] = mapped_column(String(128), default="", index=True)
    #: full_sha256 | partial_fingerprint | scoped
    hash_type: Mapped[str] = mapped_column(String(32), default="scoped", index=True)
    #: 1.0 means "the complete content hash matches". It does not mean the two
    #: objects are the same business record, and it is not a detection score.
    identity_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    #: Versioned partial-fingerprint parameters, kept so an old candidate can be
    #: explained (and invalidated) after the algorithm changes.
    partial_version: Mapped[str] = mapped_column(String(32), default="")
    partial_layout: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    instance_count: Mapped[int] = mapped_column(Integer, default=0)
    active_instance_count: Mapped[int] = mapped_column(Integer, default=0)
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    sensitivity: Mapped[str] = mapped_column(String(16), default="Unknown", index=True)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AssetInstance(TimestampMixin, Base):
    """One physical copy of an object on one probe.

    Identity is (probe_id, normalised absolute path). Renaming a file therefore
    creates a new instance and leaves the old one for the scope-aware
    ACTIVE/NOT_OBSERVED decision - it is never silently re-pointed.

    A database table has no probe and no file path, so identity is generalised to
    ``(owner_key, path)``: ``probe:<id>`` for files, ``db:<connection_id>`` for a
    table read over a configured connection. ``probe_id`` stays NULL for the
    latter - a database source must not borrow a host identity it never had.
    """

    __tablename__ = "asset_instances"
    __table_args__ = (UniqueConstraint("owner_key", "path", name="uq_asset_instance_owner_path"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    object_id: Mapped[int] = mapped_column(ForeignKey("data_objects.id"), index=True)
    #: NULL for a database-sourced instance: there is no probe in that path.
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), index=True, nullable=True)
    #: ``probe:<probe_id>`` | ``db:<connection_id>``; the owner of this observation.
    owner_key: Mapped[str] = mapped_column(String(160), default="", index=True)
    #: file | database
    source_kind: Mapped[str] = mapped_column(String(16), default="file", index=True)
    path: Mapped[str] = mapped_column(String(1024), default="")
    name: Mapped[str] = mapped_column(String(512), default="")
    #: file | directory | database_service
    instance_type: Mapped[str] = mapped_column(String(32), default="file", index=True)
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    inode: Mapped[int] = mapped_column(BigInteger, nullable=True)
    device: Mapped[int] = mapped_column(BigInteger, nullable=True)
    mtime_ns: Mapped[int] = mapped_column(BigInteger, nullable=True)
    owner: Mapped[str] = mapped_column(String(64), default="")
    group: Mapped[str] = mapped_column(String(64), default="")
    permission: Mapped[str] = mapped_column(String(16), default="")
    content_hash: Mapped[str] = mapped_column(String(128), default="")
    hash_type: Mapped[str] = mapped_column(String(32), default="scoped")
    #: ACTIVE | NOT_OBSERVED. STALE/DISAPPEARED are reserved and are never
    #: inferred, because "not observed" is not proof of deletion.
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_scan_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: The scope this instance was last successfully confirmed in. Only an
    #: identical scope may later turn it into NOT_OBSERVED.
    scope_key: Mapped[str] = mapped_column(String(256), default="", index=True)
    coverage: Mapped[str] = mapped_column(String(16), default="complete")
    termination_reason: Mapped[str] = mapped_column(String(64), default="complete")
    ruleset_version: Mapped[str] = mapped_column(String(64), default="")
    engine_version: Mapped[str] = mapped_column(String(64), default="")
    profile_version: Mapped[str] = mapped_column(String(64), default="")
    sensitivity: Mapped[str] = mapped_column(String(16), default="Unknown", index=True)
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Detection(TimestampMixin, Base):
    """One sensitive category on one instance for one object.

    `UNIQUE(instance_id, category, object_id)` is what makes "one instance, one
    row per category and object, many evidence rows" hold under concurrent
    uploads, while keeping the storage boundary honest: when the content at a
    path changes, the instance points at a new object and new detections, and the
    previous object keeps its own detections instead of being overwritten. The
    current view is `object_id == instance.object_id`.
    """

    __tablename__ = "detections"
    __table_args__ = (UniqueConstraint("instance_id", "category", "object_id",
                                       name="uq_detection_instance_category_object"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    object_id: Mapped[int] = mapped_column(ForeignKey("data_objects.id"), index=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("asset_instances.id"), index=True)
    #: NULL when the finding came from a database connection instead of a probe.
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), index=True, nullable=True)
    #: file | database; the source of the observation that produced this row.
    source_kind: Mapped[str] = mapped_column(String(16), default="file", index=True)
    scan_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    subcategory: Mapped[str] = mapped_column(String(64), default="")
    #: L1..L4 classification, a different axis from the legacy risk severity.
    sensitivity_level: Mapped[str] = mapped_column(String(16), default="L1", index=True)
    #: The existing Critical/High/Medium/Low vocabulary, kept as a derived value.
    severity: Mapped[str] = mapped_column(String(16), default="Low", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    sample_size: Mapped[int] = mapped_column(Integer, default=0)
    #: The configured ceiling that produced ``sample_size``; the two are shown
    #: together so a 2-row file never reads as a 50-row sample.
    sample_limit: Mapped[int] = mapped_column(Integer, default=0)
    sample_hit_count: Mapped[int] = mapped_column(Integer, default=0)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    engine_version: Mapped[str] = mapped_column(String(64), default="")
    ruleset_version: Mapped[str] = mapped_column(String(64), default="")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class DetectionEvidence(TimestampMixin, Base):
    """Why a detection fired.

    Rule, recogniser, field and counts describe the reason. The matched原文 the
    probe returned lives in ``extra['matches']`` (a bounded, capped sample), so a
    reviewer can verify the finding without the platform storing the file.
    """

    __tablename__ = "detection_evidence"
    __table_args__ = (UniqueConstraint("detection_id", "evidence_key", name="uq_detection_evidence_key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    detection_id: Mapped[int] = mapped_column(ForeignKey("detections.id"), index=True)
    #: Dedupe key: several recognisers agreeing on one fragment collapse into one
    #: row instead of inflating the count.
    evidence_key: Mapped[str] = mapped_column(String(200), default="")
    rule_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    rule_name: Mapped[str] = mapped_column(String(255), default="")
    #: builtin | manual | imported | presidio_static | presidio_runtime
    rule_source: Mapped[str] = mapped_column(String(32), default="")
    recognizer: Mapped[str] = mapped_column(String(64), default="")
    #: regex | keyword | field_name | context | validator
    evidence_type: Mapped[str] = mapped_column(String(32), default="")
    field_name: Mapped[str] = mapped_column(String(128), default="")
    sheet_name: Mapped[str] = mapped_column(String(128), default="")
    column_index: Mapped[int] = mapped_column(Integer, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    engine_version: Mapped[str] = mapped_column(String(64), default="")
    ruleset_version: Mapped[str] = mapped_column(String(64), default="")
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class DatabaseConnection(TimestampMixin, Base):
    """A target database the platform is allowed to read.

    Only the *server side* connects: the worker opens the session, so the
    platform container must be able to route to the address (no probe proxy, no
    SSH tunnel is implied). The password is never stored in the clear and never
    leaves the process: ``password_ciphertext`` is AES-GCM with the connection
    identity bound in as AAD, and the API only ever reports whether one is set.

    The stored record is a *configuration*, not a claim: reachability, version
    and permissions are only ever reported from a real connection attempt
    (``last_test_status`` / ``last_test_error``).
    """

    __tablename__ = "database_connections"
    __table_args__ = (UniqueConstraint("name", name="uq_database_connection_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    #: mysql | postgresql. Only engines with a real driver are accepted.
    engine: Mapped[str] = mapped_column(String(32), index=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    #: Default database/schema to reflect; a scan may still name another one.
    database: Mapped[str] = mapped_column(String(128), default="")
    username: Mapped[str] = mapped_column(String(128), default="")
    password_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    password_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    password_key_id: Mapped[str] = mapped_column(String(64), default="")
    #: disable | prefer | require | verify-full (driver-specific default kept when empty)
    tls_mode: Mapped[str] = mapped_column(String(16), default="")
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_test_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    #: ok | failed | auth_error | unreachable | read_only_violation | untested
    last_test_status: Mapped[str] = mapped_column(String(32), default="untested")
    last_test_error: Mapped[str] = mapped_column(Text, default="")
    last_scan_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
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


class ProbeDeployment(TimestampMixin, Base):
    """A server-initiated Probe deployment or removal on a target host.

    ``action`` is ``install`` for the push deployment described by the original
    design and ``uninstall`` for a removal: the same SSH transport, credential
    handling, event log and status machine are reused, but the remote step is
    ``uninstall.sh`` instead of ``install.sh``. Removal options live in
    ``removal_options`` so a host can be stripped with or without its captured
    spool and its system account.
    """

    __tablename__ = "probe_deployments"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(16), default="install", index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(128), default="root")
    auth_type: Mapped[str] = mapped_column(String(32), default="password")
    profile: Mapped[str] = mapped_column(String(32), default="standard")
    status: Mapped[str] = mapped_column(String(32), default="CREATED", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_stage: Mapped[str] = mapped_column(String(255), default="queued")
    error_code: Mapped[str] = mapped_column(String(64), default="")
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(128), default="")
    task_id: Mapped[str] = mapped_column(String(128), default="")
    package_version: Mapped[str] = mapped_column(String(64), default="")
    package_digest: Mapped[str] = mapped_column(String(64), default="")
    backend_url: Mapped[str] = mapped_column(String(512), default="")
    callback_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    first_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    credential_destroyed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=0)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    probe_id: Mapped[int | None] = mapped_column(ForeignKey("probes.id", ondelete="SET NULL"), nullable=True, index=True)
    preflight_result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    data_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    removal_options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    credential: Mapped["ProbeDeploymentCredential | None"] = relationship(back_populates="deployment", uselist=False, cascade="all, delete-orphan")
    enrollment: Mapped["ProbeEnrollment | None"] = relationship(back_populates="deployment", uselist=False, cascade="all, delete-orphan")
    events: Mapped[list["ProbeDeploymentEvent"]] = relationship(back_populates="deployment", cascade="all, delete-orphan", order_by="ProbeDeploymentEvent.seq")


class ProbeDeploymentCredential(Base):
    """AES-GCM encrypted SSH credential bound to a single deployment."""

    __tablename__ = "probe_deployment_credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    deployment_id: Mapped[int] = mapped_column(ForeignKey("probe_deployments.id", ondelete="CASCADE"), unique=True, index=True)
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str] = mapped_column(String(64), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deployment: Mapped[ProbeDeployment] = relationship(back_populates="credential")


class ProbeEnrollment(Base):
    """One-time enrollment token consumed atomically at Probe registration."""

    __tablename__ = "probe_enrollments"
    id: Mapped[int] = mapped_column(primary_key=True)
    deployment_id: Mapped[int] = mapped_column(ForeignKey("probe_deployments.id", ondelete="CASCADE"), unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    probe_id: Mapped[int | None] = mapped_column(ForeignKey("probes.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deployment: Mapped[ProbeDeployment] = relationship(back_populates="enrollment")


class ProbeDeploymentEvent(Base):
    """Append-only, sanitized progress event for a deployment."""

    __tablename__ = "probe_deployment_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    deployment_id: Mapped[int] = mapped_column(ForeignKey("probe_deployments.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer, default=1)
    stage: Mapped[str] = mapped_column(String(64), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deployment: Mapped[ProbeDeployment] = relationship(back_populates="events")


class FileSource(TimestampMixin, Base):
    __tablename__ = "file_sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    protocol: Mapped[str] = mapped_column(String(16))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    username: Mapped[str] = mapped_column(String(128), default="")
    root_path: Mapped[str] = mapped_column(String(1024), default="/")
    password_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    password_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    password_key_id: Mapped[str] = mapped_column(String(64), default="")
    host_key_sha256: Mapped[str] = mapped_column(String(128), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    limits: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=0)
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(32), default="untested")
    last_error: Mapped[str] = mapped_column(Text, default="")
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
