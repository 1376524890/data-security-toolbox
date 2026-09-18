"""Inventory checks implemented by adapters, using their actual Python source."""
import ast
import json
from functools import lru_cache
from pathlib import Path

from app.rules.builtin import BUILTIN_RULES, builtin_rule_definition

APP = Path(__file__).resolve().parents[1]
ADAPTERS = {
    "zeek": "integrations/zeek/adapter.py",
    "suricata": "integrations/suricata/adapter.py",
    "osquery": "integrations/host_audit/osquery_adapter.py",
    "wazuh": "integrations/host_audit/wazuh_adapter.py",
    "openscap": "integrations/openscap/adapter.py",
    "misp": "integrations/misp/adapter.py",
    "presidio": "integrations/presidio/adapter.py",
}


@lru_cache(maxsize=1)
def definitions() -> tuple[dict, ...]:
    entries = [builtin_rule_definition(key) for key in BUILTIN_RULES]
    from app.services.sensitive_engine import get_engine

    for engine in ('data_engine', 'dlp_engine', 'presidio'):
        for rule in get_engine().rules:
            entries.append({
                'rule_id': rule['rule_id'], 'engine': engine, 'type': 'builtin',
                'title': rule.get('name') or rule['rule_id'], 'severity': rule.get('level', ''),
                'condition': rule.get('pattern', ''), 'recommendation': '核实敏感数据用途与访问权限。',
                'source': 'shared/sensitive_detection/rules.py',
                'path': 'shared/sensitive_detection/rules.py', 'file': 'rules.py',
                'content': json.dumps(rule, ensure_ascii=False, indent=2), 'detection': rule,
            })
    for engine, relative in ADAPTERS.items():
        path = APP / relative
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for method in ast.walk(tree):
            if not isinstance(method, ast.FunctionDef):
                continue
            for call in ast.walk(method):
                if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id == "finding" and len(call.args) >= 6):
                    continue
                identifier = call.args[1]
                if not isinstance(identifier, ast.Constant) or not isinstance(identifier.value, str):
                    continue
                recommendation = call.args[5]
                title = (recommendation.value if isinstance(recommendation, ast.Constant)
                         else identifier.value)
                severity = call.args[2]
                entries.append({
                    "rule_id": identifier.value, "engine": engine, "type": "builtin",
                    "title": title, "severity": getattr(severity, "value", ""),
                    "condition": "按规则原文中的条件检查采集记录",
                    "recommendation": title, "source": f"app/{relative}",
                    "path": f"app/{relative}", "file": f"{path.name}:{method.lineno}",
                    "content": ast.get_source_segment(source, method) or "", "detection": None,
                })
        if engine in {"wazuh", "openscap", "presidio"}:
            entries.append({
                "rule_id": f"{engine.upper()}_ADAPTER", "engine": engine, "type": "builtin",
                "title": {"wazuh": "Wazuh 告警等级与规则映射", "openscap": "XCCDF 失败检查项映射",
                          "presidio": "敏感实体识别与告警映射"}[engine],
                "condition": "按规则原文转换真实检测结果", "severity": "",
                "recommendation": "结合原始检测记录核实并处置。", "source": f"app/{relative}",
                "path": f"app/{relative}", "file": path.name, "content": source, "detection": None,
            })
    for entry in entries:
        if not entry.get("content"):
            path = APP.parent / entry["path"]
            entry["content"] = path.read_text(encoding="utf-8")
    return tuple({(entry["engine"], entry["rule_id"]): entry for entry in entries}.values())


def definition(engine: str, rule_id: str) -> dict | None:
    for item in definitions():
        if item["engine"] == engine and item["rule_id"] == rule_id:
            return dict(item)
    if engine in {"wazuh", "openscap", "presidio"}:
        item = definition(engine, f"{engine.upper()}_ADAPTER")
        return {**item, "rule_id": rule_id} if item else None
    return None
