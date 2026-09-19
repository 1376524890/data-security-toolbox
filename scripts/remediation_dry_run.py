#!/usr/bin/env python3
"""Read-only dry run for the business-logic / data-truthfulness remediation.

The audit listed in ``业务逻辑与数据真实性整改清单.md`` requires the code fixes to
land first and the *historical* data repair to be designed afterwards: back up
the affected rows, print the affected-record list and the diff, then execute
with an audit trail. This script is that first half for a real database.

It is read-only by construction: every statement is a SELECT and nothing is
written, so it is safe to run against the delivery database. It also refuses to
do two things the checklist forbids: it never marks a rule hit as a false
positive, and it never invents a missing timestamp, hash, sample size or
version - a row that has no observed value stays reported as missing.

Run inside the backend container, which is where ``DATABASE_URL`` lives:

    docker cp scripts/remediation_dry_run.py source-backend-1:/tmp/
    docker exec source-backend-1 python /tmp/remediation_dry_run.py --limit 5
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.database import SessionLocal
from app.models import (
    Alert,
    AlertHit,
    AnalysisResult,
    AssetInstance,
    DataAsset,
    DataObject,
    Detection,
    DetectionFinding,
    FileRecord,
)
from app.services import data_object_service as svc
from app.services import sensitivity_map, test_service
from sqlalchemy import case, func, select

INSTANCE_ACTIVE = svc.INSTANCE_ACTIVE


def _rule(title: str) -> None:
    print(f"\n=== {title} ===")


def _line(text: str = "") -> None:
    print(text)


def _table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    if not rows:
        _line("  (无)")
        return
    widths = {name: max(len(name), *(len(str(row.get(name, ""))) for row in rows)) for name in columns}
    _line("  " + " | ".join(name.ljust(widths[name]) for name in columns))
    for row in rows:
        _line("  " + " | ".join(str(row.get(name, "")).ljust(widths[name]) for name in columns))


# --- 07 alert hit log -------------------------------------------------------
def section_alert_hits(db, limit: int) -> None:
    _rule("07 告警命中日志（alert_hits 回填）")
    alerts = db.scalars(select(Alert)).all()
    covered = set(db.scalars(select(AlertHit.alert_id).distinct()).all())
    with_finding = [item for item in alerts if item.finding_id]
    without_finding = [item for item in alerts if not item.finding_id]
    todo = [item for item in with_finding if item.id not in covered]
    _line(f"  告警总数 {len(alerts)}；已有命中日志 {len(covered)}；可自动回填 {len(todo)}；"
          f"无 finding_id（事件类告警，需人工） {len(without_finding)}")
    _line("  将执行的动作（dry-run，不落库）：为每个告警按其 finding_id 写入 1 条 alert_hits，"
          "is_first/is_latest/is_highest_risk 均为 true（旧库每条告警只留下第一条命中，"
          "被抑制掉的后续命中已在旧逻辑里丢失，不能补造）。")
    _table([{"alert_id": item.id, "finding_id": item.finding_id, "severity": item.severity,
             "risk": item.risk_score, "occurrence": item.occurrence_count,
             "缺少的后续命中": max(int(item.occurrence_count or 1) - 1, 0)}
            for item in todo[:limit]], ["alert_id", "finding_id", "severity", "risk",
                                        "occurrence", "缺少的后续命中"])
    lost = sum(max(int(item.occurrence_count or 1) - 1, 0) for item in alerts)
    _line(f"  注：告警 occurrence_count 合计显示 {lost} 次被抑制的历史命中，"
          "旧表未保存其 finding，无法还原，只能如实标记为缺失。")
    if without_finding[:limit]:
        _table([{"alert_id": item.id, "source": item.source, "title": item.title[:40]}
                for item in without_finding[:limit]], ["alert_id", "source", "title"])


# --- 15/17 category and counter state ---------------------------------------
def section_object_counters(db, limit: int) -> None:
    _rule("15/17 对象计数与实例类别")
    objects = db.scalars(select(DataObject)).all()
    real = {row[0]: (int(row[1]), int(row[2])) for row in db.execute(
        select(AssetInstance.object_id,
               func.count(AssetInstance.id),
               func.sum(case((AssetInstance.status == INSTANCE_ACTIVE, 1), else_=0)))
        .group_by(AssetInstance.object_id)).all()}
    stale = []
    for obj in objects:
        total, active = real.get(obj.id, (0, 0))
        if int(obj.instance_count or 0) != total or int(obj.active_instance_count or 0) != active:
            stale.append({"object_id": obj.id, "缓存(全部/活跃)": f"{obj.instance_count}/{obj.active_instance_count}",
                          "实际(全部/活跃)": f"{total}/{active}"})
    _line(f"  对象 {len(objects)} 个；缓存实例数与真实实例数不一致 {len(stale)} 个")
    _line("  将执行的动作（dry-run，不落库）：按真实实例重算 data_objects.instance_count / "
          "active_instance_count（清单第 17 项的 recount 口径）。")
    _table(stale[:limit], ["object_id", "缓存(全部/活跃)", "实际(全部/活跃)"])
    missing = db.scalars(select(DataObject).where(DataObject.active_instance_count > 0,
                                                  DataObject.id.not_in(real.keys() if real else [-1]))).all()
    _line(f"  缓存显示有活跃实例、但库中已无实例的对象：{len(missing)} 个"
          + (f"（示例 id {[item.id for item in missing[:5]]}）" if missing else ""))
    # Categories that the current detections no longer back.
    live: dict[int, set[str]] = {}
    for obj_id, category in db.execute(
            select(Detection.object_id, Detection.category)
            .join(AssetInstance, AssetInstance.id == Detection.instance_id)
            .where(AssetInstance.status == INSTANCE_ACTIVE,
                   Detection.object_id == AssetInstance.object_id)).all():
        live.setdefault(int(obj_id), set()).add(str(category))
    drifted = []
    rollups = 0
    for obj in objects:
        if not obj.categories:
            continue
        if obj.object_type in ("directory", "database"):
            # A directory only rolls up its children's categories and a
            # port-inferred database service carries no content finding: neither
            # is supposed to have a Detection, so their label is not drift.
            rollups += 1
            continue
        extra_categories = set(obj.categories) - live.get(obj.id, set())
        if extra_categories:
            drifted.append({"object_id": obj.id, "类别": ",".join(sorted(extra_categories)),
                            "当前检测": ",".join(sorted(live.get(obj.id, set()))) or "(无)"})
    _line(f"  对象类别包含“当前检测已不存在”的类别：{len(drifted)} 个"
          f"（另有 {rollups} 个目录/数据库服务汇总标签，按设计没有检测，不计入）")
    _line("  将执行的动作（dry-run，不落库）：不直接改写类别；下次对该路径的完整扫描会替换类别，"
          "原值保留在 instance.extra.category_history。")
    _table(drifted[:limit], ["object_id", "类别", "当前检测"])


# --- 18 sample semantics ----------------------------------------------------
def section_sample_sizes(db, limit: int) -> None:
    _rule("18 检测样本口径")
    rows = db.scalars(select(Detection)).all()
    legacy = [item for item in rows if not item.sample_limit]
    _line(f"  检测记录 {len(rows)} 条；sample_limit 为空/0（迁移前写入，未记录采样上限） {len(legacy)} 条")
    _line("  将执行的动作（dry-run，不落库）：不补造历史采样上限。页面按“上限未知”展示，"
          "只有新扫描写入的 sample_limit 才代表配置值。")
    _table([{"id": item.id, "category": item.category, "sample_size": item.sample_size,
             "hit_count": item.hit_count, "scan_id": item.scan_id}
            for item in legacy[:limit]], ["id", "category", "sample_size", "hit_count", "scan_id"])


# --- 11 rule hits that need human review ------------------------------------
def section_api_key_review(db, limit: int) -> None:
    _rule("11 API Key 判定（只列清单，不判误报）")
    rows = db.scalars(select(DetectionFinding).where(
        DetectionFinding.rule_id.in_(["SD_API_KEY_001", "DATA_SECRET_001"]))).all()
    _line(f"  命中 API Key / Secret 规则的发现 {len(rows)} 条")
    _line("  新规则要求 AKIA/ASIA 精确 16 位或 sk-/ghp_/AIza 前缀；本脚本只列出旧命中供人工复核，"
          "不自动标记为误报（清单第 11 项）。")
    _table([{"id": item.id, "rule_id": item.rule_id, "severity": item.severity,
             "risk": item.risk_score, "evidence_keys": ",".join(sorted((item.evidence or {}).keys()))[:60]}
            for item in rows[:limit]], ["id", "rule_id", "severity", "risk", "evidence_keys"])


# --- 25 re-analysis accumulation --------------------------------------------
def section_file_analysis(db, limit: int) -> None:
    _rule("25 文件重复分析（当前结果 vs 历史结果）")
    files = db.scalars(select(FileRecord)).all()
    superseded = db.scalars(select(DetectionFinding).where(
        DetectionFinding.target_type == "file")).all()
    marked = [item for item in superseded if (item.evidence or {}).get("superseded")]
    per_file = Counter(item.target_id for item in superseded)
    repeated = {key: value for key, value in per_file.items() if value > 1}
    runs = db.execute(select(AnalysisResult.module, func.count(AnalysisResult.id))
                      .where(AnalysisResult.module == "metadata").group_by(AnalysisResult.module)).all()
    _line(f"  文件 {len(files)} 个；文件类发现 {len(superseded)} 条，其中已标记 superseded {len(marked)} 条；"
          f"同一文件存在多条文件类发现 {len(repeated)} 个；metadata 分析记录 {sum(item[1] for item in runs)} 条")
    _line("  将执行的动作（dry-run，不落库）：对同一文件重新分析时，把上一轮文件派生结果标记 "
          "superseded（附 superseded_at / superseded_by_task），并删除旧的按文件 DataAsset 投影；"
          "首次重新分析的文件当前没有这类重复，无需处理。")
    _table([{"file_id": key, "文件类发现数": value} for key, value in repeated.items()][:limit],
           ["file_id", "文件类发现数"])
    legacy_projection = db.scalars(select(DataAsset).where(
        DataAsset.asset_type == "file")).all()
    _line(f"  按文件派生的旧 DataAsset 投影（asset_type=file）：{len(legacy_projection)} 条，"
          "这些行在重新分析时会被清掉并由对象模型重新投影。")
    _table([{"id": item.id, "name": item.name[:35], "sensitivity": item.sensitivity,
             "status": (item.extra or {}).get("status", "")}
            for item in legacy_projection[:limit]], ["id", "name", "sensitivity", "status"])


# --- 28 projection structure ------------------------------------------------
def section_projection(db, limit: int) -> None:
    _rule("28 旧投影的字段结构与证据快照")
    assets = db.scalars(select(DataAsset)).all()
    category_names = {entry["category"] for entry in sensitivity_map.catalog()}
    # The rebuild reads the immutable snapshot from the instance, so a row is
    # restorable when either the instance or the projection still holds it.
    instance_snapshot = {
        (item.probe_id, item.path)
        for item in db.scalars(select(AssetInstance)).all()
        if (item.extra or {}).get("columns") or (item.extra or {}).get("evidence")}
    restorable, no_snapshot = 0, []
    for item in assets:
        extra = item.extra or {}
        probe_id, path = extra.get("probe_id"), extra.get("path")
        if (extra.get("columns") or extra.get("evidence")
                or (probe_id and path and (probe_id, path) in instance_snapshot)):
            restorable += 1
        else:
            no_snapshot.append(item)
    fake_columns = []
    for item in assets:
        names = [str(column.get("name", "")) for column in (item.columns or []) if isinstance(column, dict)]
        if names and any(name in category_names for name in names):
            fake_columns.append({"id": item.id, "name": item.name[:30],
                                 "列名": ",".join(names[:4])})
    _line(f"  旧投影 {len(assets)} 条；可从快照恢复字段与证据 {restorable} 条；"
          f"两处都没有快照（重建保留原值并标 structure_restored=false） {len(no_snapshot)} 条；"
          f"列名疑似由敏感类别伪造 {len(fake_columns)} 条")
    _line("  将执行的动作（dry-run，不落库）：重建时优先用扫描快照恢复字段与证据；"
          "无快照的行保留原值并把 extra.rebuild.structure_restored 标为 false；"
          "列名被写成敏感类别的历史行另外标记 extra.rebuild.fabricated_columns=true"
          "（真实字段名已被覆盖且未保存，无法还原，不删原值、不伪造新名）。")
    _table(fake_columns[:limit], ["id", "name", "列名"])
    _table([{"id": item.id, "name": item.name[:35], "asset_type": item.asset_type,
             "status": (item.extra or {}).get("status", "")} for item in no_snapshot[:limit]],
           ["id", "name", "asset_type", "status"])


# --- 19/20 display totals ---------------------------------------------------
def section_totals(db, limit: int) -> None:
    _rule("19/20 展示口径（旧页面数字 vs 新聚合）")
    rows = svc.data_type_rows(db)
    totals = svc.data_type_summary(db)
    summed_objects = sum(row["object_count"] for row in rows)
    summed_instances = sum(row["active_instance_count"] for row in rows)
    _line(f"  类型中心：按行相加对象数 {summed_objects} / 实例数 {summed_instances}；"
          f"去重后真实对象数 {totals['objects']} / 实例数 {totals['instances']} / 主机数 {totals['hosts']}")
    _line(f"  副本：确认 {totals['confirmed_duplicates']}；疑似（≥2 实例） {totals['candidate_duplicates']}；"
          f"待确认身份（单实例部分指纹） {totals['identity_pending']}")
    _line(f"  跨类型重复计入的差值：对象 {summed_objects - totals['objects']}、"
          f"实例 {summed_instances - totals['instances']}（旧页面把这两个数当总数，"
          f"显示为 {summed_objects} / {summed_instances}）")
    assets = db.scalars(select(DataAsset)).all()
    observed = sum(1 for item in assets if (item.extra or {}).get("status") != "not_observed")
    not_observed = len(assets) - observed
    findings = db.scalar(select(func.count()).select_from(DetectionFinding).where(
        DetectionFinding.engine.in_(["data_engine", "dlp_engine"]))) or 0
    detections = len(db.scalars(select(Detection)).all())
    _line(f"  敏感发现页：数据资产投影 {len(assets)}（在位 {observed} / 历史未观测 {not_observed}，"
          f"旧页面按 200 条一页显示）；文件与网络类敏感发现 {findings} 条（旧页面按 100 条显示）；"
          f"对象模型检测 {detections} 条（旧页面完全未纳入）")
    _table([{"指标": key, "值": value} for key, value in totals.items()], ["指标", "值"])


# --- 23/24 asset linkage ----------------------------------------------------
def section_asset_linkage(db, limit: int) -> None:
    _rule("23/24 数据资产关联与 PII 汇总")
    assets = db.scalars(select(DataAsset)).all()
    with_file_id = [item for item in assets if (item.extra or {}).get("file_id")]
    with_counts = [item for item in assets if (item.extra or {}).get("counts")]
    with_columns = [item for item in assets if item.columns]
    _line(f"  数据资产 {len(assets)} 条；带 file_id 显式关联 {len(with_file_id)} 条；"
          f"带 counts（值级命中数） {len(with_counts)} 条；带结构化列 {len(with_columns)} 条")
    _line("  将执行的动作（dry-run，不落库）：关联改用 file_id，不再比对文件名与绝对路径；"
          "旧行没有 file_id 时详情只显示对象模型证据，不会误配到同名文件的检测。")
    _table([{"id": item.id, "name": item.name[:35], "asset_type": item.asset_type,
             "counts": str((item.extra or {}).get("counts", {}))[:40]} for item in with_counts[:limit]],
           ["id", "name", "asset_type", "counts"])


# --- 09 test data -----------------------------------------------------------
def section_test_data(db) -> None:
    _rule("09 测试数据与交付真实性")
    status = test_service.test_status(db)
    _line(f"  /test/status: present={status['present']} probes={status['probes']} "
          f"files={status['files']} pcaps={status['pcaps']} assets={status['assets']}")
    _line("  将执行的动作（dry-run，不落库）：无。交付库必须 present=false；"
          "测试数据导入默认关闭，生产环境启用会让后端启动失败。")


def main() -> None:
    parser = argparse.ArgumentParser(description="整改清单历史数据 dry-run（只读）")
    parser.add_argument("--limit", type=int, default=5, help="每个清单最多展示的记录数（默认 5）")
    args = parser.parse_args()
    with SessionLocal() as db:
        _line("整改清单历史数据 dry-run（只读，不会写入任何数据）")
        _line("库中的行数与差异均来自当前真实数据；不含任何模拟或测试数据。")
        section_test_data(db)
        section_alert_hits(db, args.limit)
        section_object_counters(db, args.limit)
        section_sample_sizes(db, args.limit)
        section_api_key_review(db, args.limit)
        section_file_analysis(db, args.limit)
        section_projection(db, args.limit)
        section_asset_linkage(db, args.limit)
        section_totals(db, args.limit)
        _line("\n=== 结论 ===")
        _line("以上为受影响记录清单与将执行动作的差异说明。本脚本未修改任何数据；")
        _line("要真正执行，需要先备份原始记录与证据，再按清单第四节逐项走审计端点/维护脚本。")


if __name__ == "__main__":
    main()
