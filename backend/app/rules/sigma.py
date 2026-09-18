"""Conservative Sigma evaluator: unsupported operators never become matches."""
import ast
import fnmatch
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
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
    content: str = ""
    path: str = ""
    logsource: dict[str, str] = field(default_factory=dict)


def _condition(condition: str, values: dict[str, bool]) -> bool:
    def quantified(match):
        count, pattern = match.groups()
        selected = [value for key, value in values.items()
                    if pattern == 'them' or fnmatch.fnmatchcase(key, pattern)]
        return str(bool(selected) and (all(selected) if count == 'all' else any(selected)))

    expression = re.sub(r'\b(all|1) of ([\w*]+)(?=\s|\)|$)', quantified, condition)
    tree = ast.parse(expression, mode='eval')

    def evaluate(node):
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.Name) and node.id in values:
            return values[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not evaluate(node.operand)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            children = [evaluate(child) for child in node.values]
            return all(children) if isinstance(node.op, ast.And) else any(children)
        raise ValueError('unsupported Sigma condition')

    return evaluate(tree)


def _supported_selector(selector) -> bool:
    if isinstance(selector, str):
        return True
    if isinstance(selector, list):
        return bool(selector) and all(_supported_selector(item) for item in selector)
    if not isinstance(selector, dict) or not selector:
        return False
    for key, value in selector.items():
        modifiers = str(key).split('|')[1:]
        if any(modifier not in {'contains', 'startswith', 'endswith', 'all', 'exists'}
               for modifier in modifiers):
            return False
        if sum(modifier in {'contains', 'startswith', 'endswith', 'exists'}
               for modifier in modifiers) > 1:
            return False
        if 'exists' in modifiers and not isinstance(value, bool):
            return False
        if not isinstance(value, (str, int, float, bool, list, type(None))):
            return False
        if isinstance(value, list) and (not value or any(isinstance(v, (dict, list)) for v in value)):
            return False
    return True


def supported_document(document) -> bool:
    if not isinstance(document, dict) or not document.get('title'):
        return False
    detection = document.get('detection')
    if not isinstance(detection, dict) or 'timeframe' in detection:
        return False
    selectors = {key: value for key, value in detection.items() if key != 'condition'}
    if not selectors or not all(_supported_selector(value) for value in selectors.values()):
        return False
    condition = detection.get('condition') or document.get('condition') or '1 of them'
    if not isinstance(condition, str):
        return False
    condition = condition.replace('any of them', '1 of them')
    try:
        _condition(condition, {key: False for key in selectors})
    except (ValueError, SyntaxError, RecursionError):
        return False
    return True


def load_sigma_rules(path: Path) -> list[SigmaRule]:
    paths = sorted(path.rglob('*.yaml')) + sorted(path.rglob('*.yml')) if path.is_dir() else [path]
    return [rule for file_path in paths if file_path.is_file()
            for rule in _load_file(str(file_path), file_path.stat().st_mtime_ns)]


@lru_cache(maxsize=20000)
def _load_file(filename: str, stamp: int) -> tuple[SigmaRule, ...]:
    paths = [Path(filename)]
    rules = []
    for file_path in paths:
        if not file_path.is_file():
            continue
        try:
            content = file_path.read_text(encoding='utf-8')
            document = yaml.safe_load(content)
        except (OSError, yaml.YAMLError):
            continue
        for item in document if isinstance(document, list) else [document]:
            if not supported_document(item) or item.get('enabled') is False:
                continue
            detection = item['detection']
            rules.append(SigmaRule(
                rule_id=str(item.get('id') or item.get('rule_id') or item['title']),
                title=item['title'], severity=str(item.get('level', 'medium')).title(),
                confidence=float(item.get('confidence', 0.8)), detection=detection,
                condition=str(detection.get('condition') or item.get('condition') or '1 of them'),
                recommendation=item.get('recommendation', ''), content=content, path=str(file_path),
                logsource=item.get('logsource') or {},
            ))
    return tuple(rules)


def _value_matches(actual, expected, modifiers) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    text, value = str(actual).casefold(), str(expected).casefold()
    if 'contains' in modifiers:
        return value in text
    if 'startswith' in modifiers:
        return text.startswith(value)
    if 'endswith' in modifiers:
        return text.endswith(value)
    # Sigma brackets are literals, unlike fnmatch character classes.
    pattern = re.escape(value).replace(r'\*', '.*').replace(r'\?', '.')
    return re.fullmatch(pattern, text, flags=re.DOTALL) is not None


def selector_matches(selector: Any, line: str | dict) -> bool:
    if isinstance(selector, str):
        return selector.casefold() in str(line).casefold()
    if isinstance(selector, list):
        return any(selector_matches(item, line) for item in selector)
    if not isinstance(selector, dict) or not isinstance(line, dict):
        return False
    for key, expected in selector.items():
        field, *modifiers = key.split('|')
        actual = line.get(field)
        if 'exists' in modifiers:
            if (field in line) != expected:
                return False
            continue
        values = expected if isinstance(expected, list) else [expected]
        actuals = actual if isinstance(actual, list) else [actual]
        matches = [any(_value_matches(value, target, modifiers) for value in actuals)
                   for target in values]
        if not (all(matches) if 'all' in modifiers else any(matches)):
            return False
    return True


def matching_lines(rule: SigmaRule, lines: list[str], logsource: dict | None = None) -> list[str]:
    matched = []
    for line in lines:
        try:
            record = json.loads(line) if isinstance(line, str) else line
        except (ValueError, TypeError):
            record = line
        source = record.get('_logsource', logsource or {}) if isinstance(record, dict) else logsource or {}
        required = {key: value for key, value in rule.logsource.items()
                    if key in {'product', 'category', 'service'}}
        if not isinstance(source, dict) or any(source.get(key) != value for key, value in required.items()):
            continue
        selectors = {key: selector_matches(value, record) for key, value in rule.detection.items()
                     if key not in {'condition', 'timeframe'}}
        try:
            match = _condition(rule.condition.replace('any of them', '1 of them'), selectors)
        except (ValueError, SyntaxError, RecursionError):
            match = False
        if match:
            matched.append(line)
    return matched


def evaluate_sigma(rule: SigmaRule, lines: list[str]) -> bool:
    return bool(matching_lines(rule, lines))
