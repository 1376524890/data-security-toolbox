from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    severity: str
    confidence: float
    detection: dict[str, Any]
    condition: str
    recommendation: str = ""


def load_sigma_rules(path: Path) -> list[SigmaRule]:
    if not path.exists():
        return []
    rules = []
    for file_path in sorted(path.glob("*.yaml")) if path.is_dir() else []:
        document = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        if not isinstance(document, list):
            document = [document]
        for item in document:
            if "detection" not in item:
                continue
            rules.append(SigmaRule(
                rule_id=item.get("id", item.get("title", "SIGMA_UNKNOWN")),
                title=item.get("title", item.get("id", "Sigma rule")),
                severity=item.get("level", "medium").title(),
                confidence=float(item.get("confidence", 0.8)),
                detection=item["detection"],
                condition=item.get("condition", "any of them"),
                recommendation=item.get("recommendation", ""),
            ))
    return rules


def selector_matches(selector: Any, line: str) -> bool:
    if isinstance(selector, str):
        return selector.lower() in line.lower()
    if isinstance(selector, dict):
        return all(str(value).lower() in line.lower() for value in selector.values())
    if isinstance(selector, list):
        return any(selector_matches(item, line) for item in selector)
    return False


def evaluate_sigma(rule: SigmaRule, lines: list[str]) -> bool:
    detection = rule.detection
    selectors = {key: value for key, value in detection.items() if key != "condition" and key != "timeframe"}
    results = {key: any(selector_matches(value, line) for line in lines) for key, value in selectors.items()}
    condition = rule.condition.lower()
    if "all of them" in condition:
        return all(results.values())
    if "any of them" in condition or "1 of them" in condition:
        return any(results.values())
    if " and " in condition:
        return all(results.get(part.strip(), False) for part in condition.split(" and "))
    if " or " in condition:
        return any(results.get(part.strip(), False) for part in condition.split(" or "))
    return results.get(condition, False)
