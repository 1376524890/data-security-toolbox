from typing import Any


def build_graph(assets: list[dict[str, Any]], data_assets: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    relations: list[dict[str, Any]] = []
    for asset in assets:
        relations.append({"source_node": asset.get("ip", ""), "source_type": "ip", "target_node": f"{asset.get('service', '')}:{asset.get('port', 0)}", "target_type": "service", "relation": "runs", "risk": asset.get("risk_level", "Low")})
        for category in asset.get("sensitive_categories", []):
            relations.append({"source_node": f"{asset.get('service', '')}:{asset.get('port', 0)}", "source_type": "service", "target_node": category, "target_type": "sensitive_data", "relation": "contains", "risk": "High"})
    for item in data_assets:
        relations.append({"source_node": item.get("source", ""), "source_type": "data_asset", "target_node": item.get("name", ""), "target_type": "sensitive_data", "relation": "contains", "risk": item.get("sensitivity", "Low")})
    for finding in findings:
        relations.append({"source_node": finding.get("engine", ""), "source_type": "engine", "target_node": finding.get("rule_id", ""), "target_type": "detection", "relation": "detected", "risk": finding.get("risk_level", finding.get("severity", "Low"))})
    return relations

