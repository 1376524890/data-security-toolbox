"""数据流动评估: observed flow volume, protocols and internal/external split."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Flow
from app.services import egress_regions
from app.services.assessments.envelope import caliber, envelope, gap, kpi


def build(db: Session) -> dict[str, Any]:
    total_flows = db.scalar(select(func.count()).select_from(Flow)) or 0
    total_bytes = db.scalar(select(func.sum(Flow.bytes))) or 0
    protocol_rows = db.execute(
        select(Flow.protocol, func.count(Flow.id), func.sum(Flow.bytes))
        .group_by(Flow.protocol).order_by(func.count(Flow.id).desc()).limit(20)
    ).all()

    internal = external = unknown = 0
    for flow in db.scalars(select(Flow)):
        verdict = egress_regions.classify(flow.dst_ip, blacklist=[], whitelist=[], internal=[])
        if verdict["bucket"] == "internal":
            internal += 1
        elif verdict["bucket"] == "country":
            external += 1
        else:
            unknown += 1

    kpis = [
        kpi("total_flows", "会话总数", total_flows, max(total_flows, 1)),
        kpi("internal_flows", "内网会话", internal, max(total_flows, 1), tone="primary"),
        kpi("external_flows", "外网会话（可判定）", external, max(total_flows, 1), tone="warning"),
        kpi("unknown_flows", "目的地址未识别", unknown, max(total_flows, 1), tone="danger"),
        kpi("total_bytes", "总字节", int(total_bytes), max(int(total_bytes), 1), unit="B"),
        kpi("protocols", "协议种类", len(protocol_rows), max(len(protocol_rows), 1)),
        kpi("dual_stack", "双栈会话", total_flows, max(total_flows, 1)),
        kpi("coverage", "可见会话", total_flows, max(total_flows, 1)),
    ]

    sections = {
        "protocols": [
            {"protocol": protocol or "unknown", "flows": flows, "bytes": int(size or 0)}
            for protocol, flows, size in protocol_rows
        ],
        "direction": {"internal": internal, "external": external, "unknown": unknown},
    }

    gaps = [
        gap("tls", "加密流量内容", "无法判定",
            "旁路采集不解密 TLS，加密会话只统计元数据，内容不可见。"),
        gap("region", "目的地区判定", "依赖地区表",
            "未加载 CIDR→地区表时，外网目的地址一律计入“未识别”，不判为无出境。"),
    ]

    conclusion = (
        f"共 {total_flows} 条会话，其中内网 {internal}、可判定外网 {external}、"
        f"未识别 {unknown}。加密流量与未识别目的地址的内容按口径不计入结论。"
    )
    return envelope(
        title="数据流动评估",
        conclusion=conclusion,
        kpis=kpis,
        sections=sections,
        caliber_data=caliber(region_table_present=egress_regions.table_present(),
                             notes=("会话来自已分析 PCAP 的流表，未抓到的流量不在范围内。",)),
        gaps=gaps,
    )
