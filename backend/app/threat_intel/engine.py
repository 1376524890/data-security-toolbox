import json
from pathlib import Path
from typing import Any

import requests

from app.core.config import settings
from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.rules.library import rule_params


# 判定参数来自平台规则库（app/rules/intel）；下列取值是引擎原本硬编码的默认值，
# 仅在规则文件缺失或规则被禁用时回退使用。
TI_IOC_DEFAULTS = {"max_matches": 100, "severity": "High", "confidence": 0.9}
CVE_RULE_DEFAULTS = {
    "local_limit": 10, "results_per_page": 10, "severity": "High", "confidence": 0.7,
    "nvd_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
}


class ThreatIntelEngine(DetectionEngine):
    name = "threat_intel"
    version = "1.0.0"

    def cve_lookup(self, keyword: str, api_key: str = "") -> list[dict[str, Any]]:
        rule = rule_params("threat_intel", "CVE_LOOKUP", CVE_RULE_DEFAULTS)
        local = self._local_cve_lookup(keyword, int(rule.get("local_limit") or 10))
        if local:
            return local
        headers = {"apiKey": api_key} if api_key else {}
        try:
            response = requests.get(str(rule.get("nvd_url") or CVE_RULE_DEFAULTS["nvd_url"]),
                                    params={"keywordSearch": keyword,
                                            "resultsPerPage": int(rule.get("results_per_page") or 10)},
                                    headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            return [{"cve_id": item.get("cve", {}).get("id", ""), "published": item.get("published", ""), "description": next(iter(item.get("cve", {}).get("descriptions", [{}])), {}).get("value", "")} for item in data.get("vulnerabilities", [])]
        except Exception:
            return []

    def _local_cve_lookup(self, keyword: str, limit: int = 10) -> list[dict[str, Any]]:
        from sqlalchemy import or_, select
        from app.core.database import SessionLocal
        from app.models import LocalCve
        with SessionLocal() as db:
            rows = db.scalars(select(LocalCve).where(or_(
                LocalCve.cve_id.ilike(f'%{keyword}%'),
                LocalCve.description['text'].as_string().ilike(f'%{keyword}%'),
            )).order_by(LocalCve.cvss_score.desc()).limit(max(1, limit))).all()
            if rows:
                return [{'cve_id': row.cve_id, 'published': row.published, 'description': row.description.get('text', ''),
                         'severity': row.severity, 'cvss_score': row.cvss_score, 'source': row.source} for row in rows]
        cve_dir = settings.integration_dir / "cves"
        if not cve_dir.exists():
            return []
        needle = keyword.lower()
        matches: list[dict[str, Any]] = []
        for path in sorted(cve_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            records = data if isinstance(data, list) else data.get("vulnerabilities", data.get("items", []))
            for record in records:
                cve_obj = record.get("cve", record) if isinstance(record, dict) else {}
                cve_id = str(cve_obj.get("id") or record.get("cve_id") or "")
                description = cve_obj.get("descriptions") or record.get("description") or ""
                text = f"{cve_id} {description}"
                if needle not in text.lower():
                    continue
                if isinstance(description, list):
                    description = " ".join(str(item.get("value", item)) for item in description if isinstance(item, dict))
                matches.append({
                    "cve_id": cve_id,
                    "published": str(cve_obj.get("published") or record.get("published") or ""),
                    "description": str(description),
                    "source": "local",
                })
                if len(matches) >= 10:
                    return matches
        return matches

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        raw_iocs = context.data.get("iocs", [])
        if context.data.get("ioc_library"):
            raw_iocs = context.data["ioc_library"]
        iocs: dict[str, str] = {}
        for item in raw_iocs:
            if isinstance(item, dict):
                value = str(item.get("value") or item.get("ioc") or "").lower()
                ioc_type = str(item.get("type") or item.get("ioc_type") or "ip").lower()
            else:
                value = str(item).lower()
                ioc_type = "ip"
            if value:
                iocs[value] = ioc_type
        ioc_rule = rule_params("threat_intel", "TI_IOC_001", TI_IOC_DEFAULTS)
        observed_types = [str(item).lower() for item in (ioc_rule.get("observed_types") or ["ip", "domain", "url", "hash"])]
        observed: dict[str, set[str]] = {kind: set() for kind in observed_types}
        for key, values in context.data.get('transfer_observations', {}).items():
            if key in observed:
                observed[key].update(str(v).lower() for v in values)
        for row in context.data.get('dns', {}).get('queries', []):
            if row.get('name'):
                observed.setdefault('domain', set()).add(row['name'].rstrip('.').lower())
        for row in context.data.get('tls', {}).get('handshakes', []):
            if row.get('sni'):
                observed.setdefault('domain', set()).add(row['sni'].rstrip('.').lower())
        for flow in context.flows:
            for key, value in (("ip", flow.get("src_ip")), ("ip", flow.get("dst_ip")), ("domain", flow.get("dns_query")), ("url", flow.get("url"))):
                if value:
                    observed.setdefault(key, set()).add(str(value).lower())
        for packet in context.packets:
            for value in (packet.get("src_ip"), packet.get("dst_ip")):
                if value:
                    observed.setdefault("ip", set()).add(str(value).lower())
        for line in context.log_lines:
            observed.setdefault("url", set()).add(line.strip().lower())
        for asset in context.assets:
            for key, value in (("ip", asset.get("ip")), ("domain", asset.get("hostname"))):
                if value:
                    observed.setdefault(key, set()).add(str(value).lower())
        matched = sorted(value for value, ioc_type in iocs.items() if value in observed.get(ioc_type, set()))
        if matched:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="TI_IOC_001",
                severity=str(ioc_rule.get("severity") or "High"),
                confidence=float(ioc_rule.get("confidence") or 0.9),
                evidence={"matched_iocs": matched[:int(ioc_rule.get("max_matches") or 100)],
                          "observed": {key: sorted(values)[:int(ioc_rule.get("max_matches") or 100)] for key, values in observed.items()}},
                recommendation="对命中 IOC 的通信进行隔离和取证，核实业务授权。",
            ).normalize())
        if context.data.get("cve_lookup_enabled"):
            for service in context.assets:
                keyword = f"{service.get('service', '')} {service.get('version', '')}".strip()
                if not keyword:
                    continue
                for cve in self.cve_lookup(keyword, context.data.get("nvd_api_key", "")):
                    findings.append(DetectionResult(
                        engine=self.name,
                        rule_id=f"CVE_{cve['cve_id']}",
                        severity="High",
                        confidence=0.7,
                        evidence={"cve": cve, "asset": service},
                        recommendation=f"根据 {cve['cve_id']} 评估并修复受影响资产。",
                    ).normalize())
        return findings
