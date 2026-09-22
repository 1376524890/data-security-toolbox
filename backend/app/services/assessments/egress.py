"""数据出境评估: classify DLP transfer destinations with an offline region table."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnalysisResult, Task
from app.services import egress_regions
from app.services.assessments.envelope import caliber, envelope, gap, kpi

#: How many rule hits one transfer row carries into the report. A single object
#: can match thousands of values; the report names the rules, the drawer shows
#: the samples.
MATCH_SAMPLE_CAP = 20

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


def _hits(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """The rule hits a transfer object carries, flattened for the report.

    The object already stores them (the DLP engine writes ``matches`` with the
    rule id and the matched values); the egress report has to carry them too, or
    "which data left and which rule caught it" is unanswerable here.
    """
    hits: list[dict[str, Any]] = []
    for match in obj.get("matches") or []:
        samples = list(match.get("matches") or [])[:MATCH_SAMPLE_CAP]
        hits.append({
            "kind": match.get("kind") or "",
            "count": int(match.get("count") or 0),
            "sensitive": bool(match.get("sensitive", True)),
            "confidence": match.get("confidence"),
            "rule_id": match.get("rule_id") or "",
            "rule_ids": match.get("rule_ids") or [],
            "rule_source": match.get("rule_source") or "",
            "samples": [{"value": item.get("value", ""), "context": item.get("context", "")}
                        for item in samples],
        })
    return hits


def _rule_ids(hits: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for hit in hits:
        for rule_id in [hit["rule_id"], *hit["rule_ids"]]:
            if rule_id and rule_id not in found:
                found.append(rule_id)
    return found


def build(db: Session) -> dict[str, Any]:
    config = egress_regions.policy(db)
    present = egress_regions.table_present()
    objects = transfer_objects(db)
    # Same binding the flow report does: a transferred object whose bytes are an
    # inventoried file is that file, so the egress row names it. Without this the
    # report can say "something left" but never "this file left".
    from app.services.data_objects.queries import files_by_content_hash

    bound = files_by_content_hash(db, (obj.get("sha256") for obj in objects))
    for obj in objects:
        files = bound.get(str(obj.get("sha256") or "").lower(), [])
        obj["files"] = files
        obj["file_bound"] = bool(files)

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
        hits = _hits(obj)
        rule_ids = _rule_ids(hits)
        rows.append({
            # Identity of the concrete flow, so a row can be traced back to the
            # capture and opened packet by packet instead of being a dead end.
            "pcap_id": obj.get("pcap_id"), "task_id": obj.get("task_id"),
            "object_id": obj.get("id"), "filename": obj.get("filename", ""),
            "src_ip": obj.get("src_ip", ""), "src_port": obj.get("src_port", 0),
            "dst_ip": obj.get("dst_ip", ""), "dst_port": obj.get("dst_port", 0),
            "size": obj.get("size", 0), "sha256": obj.get("sha256", ""),
            "complete": bool(obj.get("complete")),
            "content_type": obj.get("content_type", ""),
            "binary_available": bool(obj.get("binary_available")),
            "bucket": verdict["bucket"], "region": verdict["region"],
            "reason": verdict["reason"],
            # Whether sensitive content was found, what matched, and under which rule.
            "sensitive": bool([hit for hit in hits if hit["sensitive"] and hit["count"]]),
            "matches": hits, "rule_ids": rule_ids,
            "hit_count": sum(hit["count"] for hit in hits),
            "files": obj.get("files") or [], "file_bound": bool(obj.get("file_bound")),
        })

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

    sensitive = [row for row in rows if row["sensitive"]]
    leaving = [row for row in rows if row["bucket"] in {"country", "blacklist"}]
    sensitive_leaving = [row for row in rows
                         if row["sensitive"] and row["bucket"] in {"country", "blacklist"}]
    rules_seen: dict[str, int] = {}
    for row in rows:
        for rule_id in row["rule_ids"]:
            rules_seen[rule_id] = rules_seen.get(rule_id, 0) + 1

    kpis = [
        kpi("transfers", "传输对象", total, denominator),
        kpi("sensitive", "含敏感信息", len(sensitive), denominator, tone="warning"),
        kpi("leaving", "外发对象", len(leaving), denominator,
            tone="danger" if leaving else "default"),
        kpi("sensitive_leaving", "敏感外发", len(sensitive_leaving), denominator,
            tone="danger" if sensitive_leaving else "default"),
        kpi("bound", "绑定到文件", sum(1 for row in rows if row["file_bound"]), denominator),
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
        "rules": [{"rule_id": rule_id, "objects": count}
                  for rule_id, count in sorted(rules_seen.items(), key=lambda item: -item[1])],
        "policy": config,
    }

    gaps = [
        gap("sensitive_rules", "敏感规则命中", f"{len(rules_seen)} 条规则",
            "命中来自规则集；FIELD_ONLY（仅字段名命中，无值命中）不计入敏感值命中。"),
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
