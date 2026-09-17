import csv
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult


# Patterns and confidences come from the shared rule pack, so the platform, the
# probe and the network DLP stage cannot drift apart. REGEX_RULES stays as the
# legacy "lowercase category -> compiled pattern" mapping used by existing APIs.
def _builtin_patterns() -> dict[str, Any]:
    from app.services import sensitive_engine

    patterns: dict[str, Any] = {}
    for rule in sensitive_engine.get_engine().rules:
        name = sensitive_engine.legacy_name(rule.get("entity"))
        if not name or not rule.get("pattern"):
            continue
        patterns[name] = sensitive_engine.compiled_pattern(rule)
    return patterns


REGEX_RULES = _builtin_patterns()


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())


def extract_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".csv", ".txt", ".sql", ".log", ".json", ".xml", ".yaml", ".yml"}:
        return path.read_text(encoding="utf-8", errors="replace")
    if suffix in {".xlsx", ".xlsm"}:
        try:
            from openpyxl import load_workbook
            workbook = load_workbook(path, read_only=True, data_only=True)
            parts = []
            for sheet in workbook.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    parts.append(" ".join(str(value) for value in row if value is not None))
            return "\n".join(parts)
        except Exception:
            return ""
    if suffix == ".pdf":
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(str(path))
            return "\n".join((page.extract_text() or "") for page in reader.pages)
        except Exception:
            return ""
    return ""


def scan_text(text: str) -> dict[str, Any]:
    """Per-category counts. No matched value is returned, stored or logged."""
    from app.services import sensitive_engine

    hits = sensitive_engine.scan_text(text, source_type="file")
    counts: dict[str, int] = {name: 0 for name in REGEX_RULES}
    counts.update(sensitive_engine.count_by_legacy_name(hits))
    return {
        "counts": counts,
        "hits": [hit.to_dict() for hit in hits],
        "secret_count": sensitive_engine.secret_count(hits),
        "pii_count": sensitive_engine.pii_count(hits),
        # Legacy key. Entropy is now part of the per-rule confidence, so there is
        # no separate list of candidate secrets to hand around.
        "high_entropy_secrets": [],
    }


def infer_columns(text: str, source: str) -> list[dict[str, Any]]:
    columns: list[str] = []
    if source.endswith(".csv"):
        try:
            reader = csv.reader(text.splitlines())
            columns = next(reader, [])
        except Exception:
            columns = []
    elif source.endswith(".sql"):
        columns = re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+[A-Za-z0-9()]+", text, re.MULTILINE)
    elif source.endswith(".json"):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                columns = list(data.keys())
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                columns = list(data[0].keys())
        except Exception:
            columns = []
    from app.services import sensitive_engine

    engine = sensitive_engine.get_engine()
    classified = []
    for column in columns:
        hits = [hit for hit in engine.scan_field(str(column), source_type="file", file_name=source) if hit.sensitive]
        categories = [sensitive_engine.legacy_name(hit.entity) or str(hit.entity).lower() for hit in hits]
        # Legacy contract: this field is a binary "contains sensitive data" signal
        # (High/Unknown) rather than a severity level. The L1..L4 classification is
        # reported separately so the old pages keep working unchanged.
        classified.append({
            "name": column,
            "sensitivity": "High" if categories else "Unknown",
            "sensitivity_level": hits[0].level if hits else "",
            "severity": hits[0].severity if hits else "",
            "categories": categories,
        })
    return classified


_PRESIDIO_STATUS: dict[str, Any] = {
    "available": False, "enabled": False, "reason": "not_attempted", "rule_source": "presidio_runtime",
}


def presidio_status() -> dict[str, Any]:
    """How the last Presidio attempt really went - never a silent success."""
    return dict(_PRESIDIO_STATUS)


def presidio_scan(text: str) -> list[dict[str, Any]]:
    """Optional runtime recognizers.

    A missing model or a failed analyzer is recorded in :func:`presidio_status`
    so a report can say "not checked" instead of "nothing found". Findings are
    tagged ``rule_source=presidio_runtime``; they never carry matched text.
    """
    from app.core.config import settings

    if not settings.presidio_enabled:
        _PRESIDIO_STATUS.update(available=False, enabled=False, reason="disabled_by_settings")
        return []
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError as exc:
        _PRESIDIO_STATUS.update(available=False, enabled=True, reason=f"dependency_missing:{type(exc).__name__}")
        return []
    try:
        analyzer = AnalyzerEngine()
        results = analyzer.analyze(text=text, language="en")
    except Exception as exc:
        _PRESIDIO_STATUS.update(available=False, enabled=True, reason=f"analyzer_failed:{type(exc).__name__}")
        return []
    _PRESIDIO_STATUS.update(available=True, enabled=True, reason="")
    return [{"entity_type": item.entity_type, "score": round(float(item.score), 3), "start": item.start,
             "end": item.end, "rule_source": "presidio_runtime"} for item in results]


def yara_scan(path: Path, rule_dir: Path) -> list[dict[str, Any]]:
    try:
        import yara
    except ImportError:
        return []
    from app.core.config import settings
    rule_files = sorted(rule_dir.glob("*.yar")) if rule_dir.exists() else []
    rule_files += sorted((settings.integration_dir / 'yara_rules').glob('*.yar'))
    if not rule_files:
        return []
    compiled = yara.compile(sources={f'rule_{index}': file.read_text(encoding='utf-8') for index, file in enumerate(rule_files)}, includes=False)
    matches = compiled.match(str(path), timeout=10)
    return [{"rule": item.rule, "tags": item.tags, "meta": item.meta} for item in matches]


class DataEngine(DetectionEngine):
    name = "data_engine"
    version = "2.0.0"

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        paths = list(context.files)
        if context.path:
            paths.append(context.path)
        for path in paths:
            if not path.exists():
                continue
            text = extract_text(path)
            scan = scan_text(text)
            presidio = presidio_scan(text) if text else []
            yara_matches = yara_scan(path, Path(__file__).resolve().parents[2] / "rules" / "data")
            evidence = {
                "file": str(path),
                "size": path.stat().st_size,
                "regex": scan,
                "presidio": presidio[:50],
                "presidio_status": presidio_status(),
                "yara": yara_matches[:50],
            }
            columns = infer_columns(text, path.name)
            if columns:
                evidence["columns"] = columns
                context.data.setdefault("data_assets", []).append({
                    "name": path.name,
                    "asset_type": "file",
                    "sensitivity": "High" if any(column["sensitivity"] == "High" for column in columns) else "Low",
                    "source": path.name,
                    "columns": columns,
                })
            if scan["pii_count"] > 0 or presidio:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="DATA_PII_001",
                    severity="High",
                    confidence=0.9 if scan["pii_count"] else 0.7,
                    evidence=evidence,
                    recommendation="对包含身份证、手机号、银行卡、邮箱等 PII 的文件实施加密、脱敏和访问控制。",
                ).normalize())
            if scan["secret_count"] > 0 or scan["high_entropy_secrets"]:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="DATA_SECRET_001",
                    severity="Critical",
                    confidence=0.85,
                    evidence=evidence,
                    recommendation="立即轮换泄露的密钥/Token，并排查代码、配置和备份文件。",
                ).normalize())
            if yara_matches:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="DATA_YARA_001",
                    severity="High",
                    confidence=0.9,
                    evidence=evidence,
                    recommendation="根据 YARA 规则检查文件来源、作者和是否包含恶意/敏感内容。",
                ).normalize())
        text = context.data.get("text", "")
        if text:
            scan = scan_text(text)
            if scan["pii_count"] > 0:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="DATA_PII_001",
                    severity="High",
                    confidence=0.9,
                    evidence={"counts": scan["counts"], "hits": scan["hits"]},
                    recommendation="对文本中的 PII 进行脱敏和最小化采集。",
                ).normalize())
            if scan["secret_count"] > 0:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="DATA_SECRET_001",
                    severity="Critical",
                    confidence=0.85,
                    evidence={"counts": scan["counts"], "hits": scan["hits"]},
                    recommendation="轮换泄露密钥，并从日志和配置中清除明文凭据。",
                ).normalize())
        return findings
