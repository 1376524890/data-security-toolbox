# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Detection-rule catalogue: the rule corpus, its upstream sources and imports.

This is the engine-rule surface the console reads.  Browsing and reading rule
content go through ``api/rule_presenter.py::rule_file_entries`` (the single
enumeration of builtin and file-based rules), the per-engine provenance through
``app.rules.catalog``/``app.rules.library``, the online upstream refresh through
``app.rules.sync`` and the manual Suricata/YARA import through
``app.integrations.offline_manager`` / the ``yara`` compiler.  The sensitive-data
(DLP) rule catalogue is a different rule family and stays in
``api/libraries.py``.  This module owns paths and response shapes only.
"""

from __future__ import annotations

import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.rule_presenter import rule_file_entries
from app.core.config import settings
from app.core.database import get_db
from app.models import SystemSetting
from app.services.audit_service import record_audit

router = APIRouter()


@router.get("/rules")
def list_rules(
    rule_type: str | None = Query(None),
    engine: str | None = Query(None),
    include_content: bool = Query(True),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List Sigma / Suricata / YARA rules with content."""
    items = rule_file_entries(db, engine=engine or "", include_content=include_content)
    if rule_type:
        items = [item for item in items if item["type"] == rule_type]
    if engine:
        items = [item for item in items if item["engine"] == engine]
    return {"items": items, "total": len(items)}


@router.get("/rules/content")
def rule_content(path: str, engine: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = next(
        (
            item
            for item in rule_file_entries(db, engine, include_content=False)
            if item["path"] == path
        ),
        None,
    )
    if item is None:
        raise HTTPException(404, "规则不存在")
    if item["type"] == "builtin":
        from app.rules.code_catalog import definition

        item["content"] = definition(engine, item["rule_id"])["content"]
    else:
        item["content"] = Path(path).read_text(encoding="utf-8", errors="replace")
    return item


@router.get("/rule-sources", tags=["rule-libraries"])
def list_rule_sources(db: Session = Depends(get_db)):
    """每个引擎的规则来源：文件数、上游发布方、能否在线拉取。

    控制台的「引擎总览」用它说明规则的出处，运维用它判断某个引擎是否需要
    在线更新；平台自研规则（无上游）在这里 refreshable=false。
    """
    from app.rules import library
    from app.rules import sync as rule_sync
    from app.rules.catalog import CATALOG

    state_row = db.scalar(select(SystemSetting).where(SystemSetting.key == "rule_source_state"))
    state = state_row.value if state_row and isinstance(state_row.value, dict) else {}
    sources = {item["engine"]: item for item in rule_sync.sources()}
    items = []
    for source in CATALOG:
        entry = sources.get(source.engine)
        items.append(
            {
                "engine": source.engine,
                "label": source.label,
                "rule_type": source.rule_type,
                "rule_files": len(library.rule_files(source.engine)),
                "refreshable": source.refreshable,
                "source_name": source.source_name,
                "source_url": source.source_url,
                "scope": source.scope,
                "managed_by": "upstream" if source.refreshable else "platform",
                "last_sync": state.get(source.engine, {}),
                "refresh_supported": bool(entry),
            }
        )
    return {"items": items, "total": len(items)}


class RuleSyncRequest(BaseModel):
    engines: list[str] = Field(default_factory=list, max_length=15)


@router.post("/rules/sync", tags=["rule-libraries"])
def sync_rules(request: Request, payload: RuleSyncRequest, db: Session = Depends(get_db)):
    """在线拉取引擎规则。

    只拉取 catalog 声明的上游；未指定 engines 时拉取全部可在线更新的引擎。
    拉取失败不会破坏现有规则（写盘前先按引擎原生格式校验），并把失败原因
    原样返回，便于离线环境判断是网络不可达还是上游变更。
    """
    from app.rules import sync as rule_sync

    requested = payload.engines
    if requested:
        targets = list(dict.fromkeys(requested))
        unknown = [
            item for item in targets if item not in {src["engine"] for src in rule_sync.sources()}
        ]
        if unknown:
            raise HTTPException(422, f"不支持在线拉取的引擎: {', '.join(unknown)}")
    else:
        targets = [src["engine"] for src in rule_sync.sources()]
    results = [rule_sync.refresh(engine).to_dict() for engine in targets]
    summary = {
        "updated": sum(1 for item in results if item["status"] == "updated"),
        "failed": sum(1 for item in results if item["status"] == "failed"),
        "files": sum(int(item["files"]) for item in results),
        "results": results,
    }
    row = db.scalar(select(SystemSetting).where(SystemSetting.key == "rule_source_state"))
    previous = dict(row.value) if row and isinstance(row.value, dict) else {}
    for item in results:
        previous[item["engine"]] = {
            "status": item["status"],
            "files": item["files"],
            "source": item["source"],
            "at": datetime.now(UTC).isoformat(),
            "detail": item["detail"][:300],
        }
    if row:
        row.value = previous
    else:
        db.add(SystemSetting(key="rule_source_state", value=previous))
    db.commit()
    record_audit(db, request, action="rules.sync", target="rules", details=summary)
    return summary


class DetectionRule(BaseModel):
    rule_type: Literal["suricata", "yara"]
    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    content: str = Field(min_length=1, max_length=1024 * 1024)


@router.post("/rules", tags=["rule-libraries"])
def create_detection_rule(payload: DetectionRule, db: Session = Depends(get_db)):
    if payload.rule_type == "suricata":
        from app.integrations.offline_manager import import_uploaded_offline

        result = import_uploaded_offline(
            db,
            payload.name + ".rules",
            payload.content.encode(),
            "suricata_rules",
            payload.name,
            uuid.uuid4().hex[:12],
        )
        if result.errors:
            raise HTTPException(422, "; ".join(result.errors))
        return result.to_dict()
    try:
        import yara

        yara.compile(source=payload.content, includes=False)
    except ImportError as exc:
        raise HTTPException(503, "缺少 yara-python，安装后才能校验并启用 YARA 规则") from exc
    except Exception as exc:
        raise HTTPException(422, f"YARA 校验失败: {exc}") from exc
    directory = settings.integration_dir / "yara_rules"
    directory.mkdir(parents=True, exist_ok=True)
    # Unique file name avoids silently replacing an existing rule.
    target = directory / (payload.name + "_" + uuid.uuid4().hex[:12] + ".yar")
    with tempfile.NamedTemporaryFile(dir=directory, suffix=".tmp", delete=False) as handle:
        handle.write(payload.content.encode())
        temporary = Path(handle.name)
    temporary.replace(target)
    return {"imported": 1, "path": str(target)}
