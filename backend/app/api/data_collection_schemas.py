"""data collection schemas responsibilities."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class DataAssetScanConfig(BaseModel):
    paths: list[str] = Field(
        default_factory=list, max_length=32, description="目标服务器上要采集的目录"
    )
    max_files: int = Field(default=10000, ge=1, le=100000)
    max_depth: int = Field(default=3, ge=0, le=8)
    include_databases: bool = True
    timeout_seconds: int = Field(default=120, ge=5, le=1800)
    #: Scope filters. A bare name filters that directory anywhere below a root; an
    #: absolute path excludes exactly that subtree. ``file_types`` is an extension
    #: allow-list, and an empty one keeps every type in scope.
    exclude_paths: list[str] = Field(default_factory=list, max_length=32)
    file_types: list[str] = Field(default_factory=list, max_length=32)
    #: Optional versioned profile. When set, its snapshot supplies the config and
    #: the fields above act as explicit overrides.
    profile_id: int | None = Field(default=None, ge=1)
    #: Policy groups (detection items) this task should enforce. Recorded on the
    #: task so a group cannot be deleted while a pending task still references it.
    policy_group_ids: list[int] = Field(default_factory=list, max_length=64)

    @field_validator("paths")
    @classmethod
    def paths_valid(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            item = str(value).strip()
            if not item:
                continue
            if ".." in item.split("/") or not item.startswith("/") or len(item) > 512:
                raise ValueError('paths must be absolute Linux paths without ".."')
            if item not in cleaned:
                cleaned.append(item)
        return cleaned

    @field_validator("exclude_paths")
    @classmethod
    def excludes_valid(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            item = str(value).strip().rstrip("/")
            if not item:
                continue
            # A bare directory name and an absolute subtree are both accepted, but
            # neither may walk upwards out of the scanned tree.
            if ".." in item.split("/") or len(item) > 512:
                raise ValueError('exclude_paths must not contain ".."')
            if item not in cleaned:
                cleaned.append(item)
        return cleaned

    @field_validator("file_types")
    @classmethod
    def file_types_valid(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            item = str(value).strip().lower()
            if not item:
                continue
            if not item.startswith("."):
                item = "." + item
            if item not in cleaned:
                cleaned.append(item)
        return cleaned


class DataAssetColumn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    header_name: str = Field(default="", max_length=256)
    sheet_name: str = Field(default="", max_length=128)
    column_index: int | None = Field(default=None, ge=0, le=65535)
    detected_type: str = Field(default="", max_length=64)
    inferred_type: str = Field(default="", max_length=32)
    sensitivity: str = Field(default="Unknown", max_length=16)
    confidence: float = Field(default=0.0, ge=0, le=1)
    categories: list[str] = Field(default_factory=list, max_length=16)
    count: int = Field(default=0, ge=0)
    sample_size: int = Field(default=0, ge=0)
    sample_hit_count: int = Field(default=0, ge=0)
    rule_ids: list[str] = Field(default_factory=list, max_length=64)


class ProbeDataAsset(BaseModel):
    name: str = Field(min_length=1, max_length=512)
    asset_type: str = Field(default="file", max_length=64)
    sensitivity: str = Field(default="Low", max_length=16)
    path: str = Field(default="", max_length=1024)
    size: int = Field(default=0, ge=0)
    sha256: str = Field(default="", max_length=64)
    # Stage 4 identity fields. An old probe omits them and the ingestion derives
    # the same answer from ``sha256`` plus the fingerprint evidence.
    hash_type: str = Field(default="", max_length=32)
    identity_confidence: float | None = Field(default=None, ge=0, le=1)
    level: str = Field(default="", max_length=8)
    modified_at: str = Field(default="", max_length=64)
    categories: list[str] = Field(default_factory=list, max_length=16)
    counts: dict[str, int] = Field(default_factory=dict)
    columns: list[DataAssetColumn] = Field(default_factory=list, max_length=256)
    evidence: dict = Field(default_factory=dict)
    coverage: str = Field(default="", max_length=16)
    termination_reason: str = Field(default="", max_length=64)
    scan_id: str = Field(default="", max_length=64)
    ruleset_version: str = Field(default="", max_length=64)
    engine_version: str = Field(default="", max_length=64)
    profile_version: str = Field(default="", max_length=64)


class DataAssetReport(BaseModel):
    """Inventory produced on the probe host itself; no raw content is uploaded.

    New in 1.1: ``schema_version``, ``scan_id``, the version triple, the aggregated
    ``budget``/``coverage`` and an explicit ``completed_scope``. Every one of them
    is optional so a 3.3.1 probe keeps uploading exactly what it always did, and
    the ingestion falls back to the legacy meaning instead of assuming coverage.
    """

    report_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    task_id: int | None = None
    schema_version: str = Field(default="", max_length=16)
    scan_id: str = Field(default="", max_length=64)
    assets: list[ProbeDataAsset] = Field(default_factory=list, max_length=4096)
    databases: list[ProbeDataAsset] = Field(default_factory=list, max_length=256)
    scanned_paths: list[str] = Field(default_factory=list, max_length=64)
    max_depth: int | None = Field(default=None, ge=0, le=8)
    complete: bool = True
    completed_scope: bool | None = None
    error: str = Field(default="", max_length=500)
    reason_code: str = Field(default="", max_length=64)
    termination_reason: str = Field(default="", max_length=64)
    observed_at: str = Field(default="", max_length=64)
    scanner: str = Field(default="probe-file-inventory", max_length=64)
    ruleset_version: str = Field(default="", max_length=64)
    engine_version: str = Field(default="", max_length=64)
    profile_version: str = Field(default="", max_length=64)
    counts: dict[str, int] = Field(default_factory=dict)
    totals: dict = Field(default_factory=dict)
    budget: dict = Field(default_factory=dict)
    coverage: dict = Field(default_factory=dict)
    degraded_capabilities: list[str] = Field(default_factory=list, max_length=32)
    report_guard: dict = Field(
        default_factory=dict, description="探针侧报告清洗计数（脱敏/截断/丢弃字段）"
    )


class DataAssetProgress(BaseModel):
    """Aggregated progress for a running job. Never a terminal transition."""

    task_id: int
    scan_id: str = Field(default="", max_length=64)
    current_path: str = Field(default="", max_length=1024)
    coverage: dict = Field(default_factory=dict)
