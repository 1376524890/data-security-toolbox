"""数据出境评估: classify DLP transfer destinations with an offline region table."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnalysisResult, Task
from app.services import egress_regions
from app.services.assessments.envelope import caliber, envelope, gap, kpi

#: How many recent DLP analysis results to fold in; DLP keeps only recent objects.
TRANSFER_WINDOW = 50


def transfer_objects(db: Session, limit: int = TRANSFER_WINDOW) -> list[dict[str, Any]]:
    """The DLP transfer objects with their direction, newest capture per pcap."""
    query = (select(AnalysisResult, Task)
             .join(Task, AnalysisResult.task_id == Task.id)
             .where(AnalysisResult.module == "dlp"))
    rows = db.execute(query.order_by(AnalysisResult.id.desc()).limit(limit)).all()
    items: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for result, task in rows:
        pcap_id = (task.payload or {}).get("pcap_id")
        if pcap_id in seen:
            continue
        seen.add(pcap_id)
        for obj in (result.content or {}).get("objects", []):
            items.append({**obj, "pcap_id": pcap_id, "task_id": task.id})
    return items


def build(db: Session) -> dict[str, Any]:
    config = egress_regions.policy(db)
    present = egress_regions.table_present()
    objects = transfer_objects(db)

    buckets: dict[str, int] = {"internal": 0, "whitelist": 0, "blacklist": 0,
                               "country": 0, "unknown": 0}
    regions: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    for obj in objects:
        verdict = egress_regions.classify(
            obj.get("dst_ip"), blacklist=config["blacklist"], whitelist=config["whitelist"],
            internal=config["internal_cidrs"])
        buckets[verdict["bucket"]] = buckets.get(verdict["bucket"], 0) + 1
        if verdict["region"]:
            regions[verdict["region"]] = regions.get(verdict["region"], 0) + 1
        rows.append({"pcap_id": obj.get("pcap_id"), "task_id": obj.get("task_id"),
                     "filename": obj.get("filename", ""), "dst_ip": obj.get("dst_ip", ""),
                     "dst_port": obj.get("dst_port", 0), "size": obj.get("size", 0),
                     "bucket": verdict["bucket"], "region": verdict["region"],
                     "reason": verdict["reason"]})

    total = len(objects)
    denominator = max(total, 1)
    if present:
        conclusion = (
            f"共 {total} 个传输对象：内网 {buckets['internal']}、"
            f"白名单 {buckets['whitelist']}、黑名单 {buckets['blacklist']}、"
            f"可判定出境 {buckets['country']}、未识别 {buckets['unknown']}。")
    else:
        conclusion = (f"共 {total} 个传输对象。未加载 CIDR→地区表，"
                      f"{buckets['internal']} 个内网地址可确认，其余目的地址一律为“无法判定”，"
                      f"不表示无出境。")

    kpis = [
        kpi("transfers", "传输对象", total, denominator),
        kpi("internal", "内网目的", buckets["internal"], denominator, tone="primary"),
        kpi("country", "可判定出境", buckets["country"], denominator,
            tone="danger" if present else "default"),
        kpi("blacklist", "黑名单命中", buckets["blacklist"], denominator, tone="danger"),
        kpi("whitelist", "白名单放行", buckets["whitelist"], denominator),
        kpi("unknown", "未识别目的", buckets["unknown"], denominator, tone="warning"),
        kpi("regions", "涉及地区数", len(regions), max(len(regions), 1)),
        kpi("region_table", "地区表", "已加载" if present else "缺失", denominator),
    ]

    sections = {
        "buckets": buckets,
        "regions": [{"region": region, "count": count} for region, count in
                    sorted(regions.items(), key=lambda item: item[1], reverse=True)],
        "transfers": rows[:500],
        "policy": config,
    }

    gaps = [
        gap("region_table", "CIDR→地区表", "已加载" if present else "缺失",
            "未加载地区表时整页降级为“无法判定”，不会显示成“无出境”。"),
        gap("tls", "加密外发内容", "无法判定",
            "旁路不解密 TLS，仅能按目的地址判定，无法确认加密通道里的数据类别。"),
    ]

    return envelope(
        title="数据出境评估",
        conclusion=conclusion,
        kpis=kpis,
        sections=sections,
        caliber_data=caliber(region_table_present=present,
                             notes=("出境以目的 IP 判定：白名单优先，其次黑名单，再查静态地区表；"
                                    "判定不了的一律计入“未识别”。",)),
        gaps=gaps,
    )
