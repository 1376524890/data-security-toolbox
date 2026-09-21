"""数据脆弱性评估: unpatched CVEs, weak/plaintext services and permission gaps."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Asset, AssetInstance, DetectionFinding, Vulnerability
from app.services.assessments.envelope import caliber, envelope, gap, kpi

#: Services that carry credentials or data in the clear.
WEAK_SERVICES = ("telnet", "ftp", "smtp", "pop3", "imap")


def build(db: Session) -> dict[str, Any]:
    total_assets = db.scalar(select(func.count()).select_from(Asset)) or 0

    vuln_rows = db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
    ).all()
    vuln_total = sum(count for _severity, count in vuln_rows)
    open_vulns = db.scalar(select(func.count()).select_from(Vulnerability)
                           .where(Vulnerability.status == "open")) or 0
    avg_cvss = db.scalar(select(func.avg(Vulnerability.cvss_score))) or 0.0

    weak = 0
    public_exposed = 0
    for asset in db.scalars(select(Asset)):
        if (asset.service or "").lower() in WEAK_SERVICES:
            weak += 1
        if (asset.extra or {}).get("public_exposed"):
            public_exposed += 1

    finding_rows = db.execute(
        select(DetectionFinding.severity, func.count(DetectionFinding.id))
        .group_by(DetectionFinding.severity)
    ).all()
    finding_total = sum(count for _severity, count in finding_rows)

    instances_total = db.scalar(select(func.count()).select_from(AssetInstance)) or 0
    permission_missing = db.scalar(
        select(func.count()).select_from(AssetInstance).where(AssetInstance.permission == "")) or 0

    kpis = [
        kpi("open_vulnerabilities", "未修复漏洞", open_vulns, max(vuln_total, 1), tone="danger"),
        kpi("weak_services", "明文/弱协议资产", weak, max(total_assets, 1), tone="warning"),
        kpi("public_exposed", "公网暴露资产", public_exposed, max(total_assets, 1), tone="danger"),
        kpi("engine_findings", "引擎发现", finding_total, max(finding_total, 1), tone="primary"),
        kpi("avg_cvss", "平均 CVSS", round(float(avg_cvss), 1), 10, unit="分"),
        kpi("observed_assets", "观测资产", total_assets, max(total_assets, 1)),
        kpi("permission_missing", "权限未上报实例", permission_missing, max(instances_total, 1),
            tone="warning"),
        kpi("data_instances", "数据实例", instances_total, max(instances_total, 1)),
    ]

    sections = {
        "vulnerability_severity": [
            {"severity": severity, "count": count} for severity, count in vuln_rows
        ],
        "finding_severity": [
            {"severity": severity, "count": count} for severity, count in finding_rows
        ],
        "weak_services": list(WEAK_SERVICES),
    }

    gaps = [
        gap("permission", "权限越权检测", "未接入",
            f"{permission_missing} 个实例未上报 permission，权限风险无法逐条判定。"),
        gap("patch_state", "补丁状态核对", "部分",
            "仅统计已导入的 CVE（离线库/Grype），未导入的资产不代表无漏洞。"),
    ]

    conclusion = (
        f"发现未修复漏洞 {open_vulns} 个（共 {vuln_total}），明文/弱协议资产 {weak} 个，"
        f"公网暴露 {public_exposed} 个；权限维度因数据缺失无法判定。"
    )
    return envelope(
        title="数据脆弱性评估",
        conclusion=conclusion,
        kpis=kpis,
        sections=sections,
        caliber_data=caliber(notes=("漏洞统计只覆盖已导入的离线 CVE/Grype 库，"
                                    "不代表全量补丁状态。",)),
        gaps=gaps,
    )
