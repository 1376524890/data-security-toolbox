import requests
from typing import Any

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult


class ThreatIntelEngine(DetectionEngine):
    name = "threat_intel"
    version = "1.0.0"

    def cve_lookup(self, keyword: str, api_key: str = "") -> list[dict[str, Any]]:
        headers = {"apiKey": api_key} if api_key else {}
        try:
            response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"keywordSearch": keyword, "resultsPerPage": 10}, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            return [{"cve_id": item.get("cve", {}).get("id", ""), "published": item.get("published", ""), "description": next(iter(item.get("cve", {}).get("descriptions", [{}])), {}).get("value", "")} for item in data.get("vulnerabilities", [])]
        except Exception:
            return []

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        iocs = set(context.data.get("iocs", []))
        observed = {flow.get("src_ip", "") for flow in context.flows} | {flow.get("dst_ip", "") for flow in context.flows}
        matched = sorted(iocs & observed)
        if matched:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="TI_IOC_001",
                severity="High",
                confidence=0.9,
                evidence={"matched_iocs": matched[:100], "observed": sorted(observed)[:100]},
                recommendation="对命中 IOC 的通信进行阻断、隔离和取证。",
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

