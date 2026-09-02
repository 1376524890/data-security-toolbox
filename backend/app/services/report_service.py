from datetime import datetime, timezone
from importlib.resources import files as resource_files
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import settings


def build_summary(assets: list[dict[str, Any]], files: list[dict[str, Any]], pcaps: list[dict[str, Any]], anomalies: list[dict[str, Any]], audit: dict[str, Any], findings: list[dict[str, Any]] | None = None, data_assets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    findings = findings or []
    data_assets = data_assets or []
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "asset_count": len(assets),
        "file_count": len(files),
        "pcap_count": len(pcaps),
        "anomaly_count": len(anomalies),
        "finding_count": len(findings),
        "data_asset_count": len(data_assets),
        "audit": audit,
    }


def render_html(summary: dict[str, Any], assets: list[dict[str, Any]], files: list[dict[str, Any]], pcaps: list[dict[str, Any]], anomalies: list[dict[str, Any]], findings: list[dict[str, Any]] | None = None, data_assets: list[dict[str, Any]] | None = None) -> str:
    template_root = resource_files("app").joinpath("templates/reports")
    env = Environment(loader=FileSystemLoader(str(template_root)), autoescape=select_autoescape(["html"]))
    template = env.get_template("report.html.j2")
    return template.render(summary=summary, assets=assets, files=files, pcaps=pcaps, anomalies=anomalies, findings=findings or [], data_assets=data_assets or [])


def render_pdf(html: str, output: Path) -> Path:
    from weasyprint import HTML
    HTML(string=html).write_pdf(str(output))
    return output


def render_csv(rows: list[dict[str, Any]], output: Path) -> Path:
    import csv
    if not rows:
        rows = [{"message": "no data"}]
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return output
