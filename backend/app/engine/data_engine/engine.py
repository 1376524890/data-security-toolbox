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

# Entity families behind the two file/text findings, and the confidence a hit
# must reach before it may raise one. The threshold is the platform-wide alert
# confidence so DLP and the file engine cannot disagree about what is "real".
PII_FAMILIES = {"PHONE", "ID_CARD", "BANK_CARD", "EMAIL", "NAME", "ADDRESS", "MEDICAL_RECORD"}
SECRET_FAMILIES = {"API_KEY", "TOKEN", "CREDENTIAL"}
CONFIRMED_MIN_SCORE = 0.6
_SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _confirmed_of(scan: dict[str, Any], families: set[str]) -> list[dict[str, Any]]:
    """Value-level hits of one family from a :func:`scan_text` result."""
    return [item for item in scan.get("confirmed_hits", []) if item.get("entity") in families]


def _severity_of(items: list[dict[str, Any]], fallback: str) -> str:
    """Highest severity carried by the evidence, never invented upward."""
    ranked = max(items, key=lambda item: _SEVERITY_RANK.get(str(item.get("severity") or ""), 0), default=None)
    current = str(ranked.get("severity") or "") if ranked else ""
    return current if current in _SEVERITY_RANK else fallback


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())


_TEXT_SUFFIXES = {
    ".csv", ".txt", ".sql", ".log", ".json", ".jsonl", ".ndjson", ".xml", ".yaml", ".yml",
    ".tsv", ".conf", ".cfg", ".ini", ".toml", ".properties", ".env", ".list", ".md",
}

# Scan outcome vocabulary. "complete" claims the whole document was read; an empty
# string must never imply that, so unsupported/failed reads are named explicitly.
SCAN_COMPLETE = "complete"
SCAN_PARTIAL = "partial"
SCAN_UNSUPPORTED = "unsupported"
SCAN_FAILED = "failed"


def _docx_text(path: Path) -> str:
    """Extract paragraphs from a .docx without an optional third-party parser."""
    import zipfile
    from xml.etree import ElementTree

    namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    with zipfile.ZipFile(path) as archive:
        with archive.open("word/document.xml") as handle:
            root = ElementTree.parse(handle).getroot()
    paragraphs = [
        "".join(node.text or "" for node in paragraph.iter(f"{namespace}t"))
        for paragraph in root.iter(f"{namespace}p")
    ]
    return "\n".join(paragraphs)


def extract_document(path: Path) -> tuple[str, dict[str, Any]]:
    """Read a document and report how complete the read really was.

    Returns ``(text, status)``; ``status['status']`` is one of
    ``complete``/``partial``/``unsupported``/``failed`` and carries the format,
    character count, truncation flag and a reason. A format the engine cannot
    parse (or a document that fails to parse) is reported as such instead of
    coming back as an empty, apparently clean result.
    """
    suffix = path.suffix.lower()
    if suffix in _TEXT_SUFFIXES or path.name.lower().startswith(".env"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError) as exc:
            return "", {"status": SCAN_FAILED, "format": suffix or ".txt", "chars": 0,
                        "truncated": False, "reason": type(exc).__name__}
        return text, {"status": SCAN_COMPLETE, "format": suffix or ".txt", "chars": len(text),
                      "truncated": False, "reason": ""}
    if suffix == ".docx":
        try:
            text = _docx_text(path)
        except Exception as exc:
            return "", {"status": SCAN_FAILED, "format": ".docx", "chars": 0,
                        "truncated": False, "reason": type(exc).__name__}
        if not text.strip():
            return text, {"status": SCAN_UNSUPPORTED, "format": ".docx", "chars": 0,
                          "truncated": False, "reason": "no_extractable_text"}
        return text, {"status": SCAN_COMPLETE, "format": ".docx", "chars": len(text),
                      "truncated": False, "reason": ""}
    if suffix in {".xlsx", ".xlsm"}:
        try:
            from openpyxl import load_workbook
            workbook = load_workbook(path, read_only=True, data_only=True)
            parts = []
            for sheet in workbook.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    parts.append(" ".join(str(value) for value in row if value is not None))
            text = "\n".join(parts)
        except Exception as exc:
            return "", {"status": SCAN_FAILED, "format": suffix, "chars": 0,
                        "truncated": False, "reason": type(exc).__name__}
        return text, {"status": SCAN_COMPLETE, "format": suffix, "chars": len(text),
                      "truncated": False, "reason": ""}
    if suffix == ".pdf":
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(str(path))
            text = "\n".join((page.extract_text() or "") for page in reader.pages)
        except Exception as exc:
            return "", {"status": SCAN_FAILED, "format": ".pdf", "chars": 0,
                        "truncated": False, "reason": type(exc).__name__}
        if not text.strip():
            # A scanned PDF has no text layer; it was not checked, so it is not clean.
            return "", {"status": SCAN_UNSUPPORTED, "format": ".pdf", "chars": 0,
                        "truncated": False, "reason": "no_text_layer"}
        return text, {"status": SCAN_COMPLETE, "format": ".pdf", "chars": len(text),
                      "truncated": False, "reason": ""}
    return "", {"status": SCAN_UNSUPPORTED, "format": suffix, "chars": 0,
                "truncated": False, "reason": "unsupported_format"}


def extract_text(path: Path) -> str:
    """Backward-compatible text-only helper; see :func:`extract_document`."""
    return extract_document(path)[0]


def scan_text(text: str) -> dict[str, Any]:
    """Per-category counts plus the bounded matched原文 each hit carries.

    The原文 travels under ``matches`` only (value plus its line, capped by the
    engine), because an operator has to be able to verify what was found; every
    other field stays value-free.
    """
    from app.services import sensitive_engine

    # The platform's own rules (manual / imported) are part of this scan, so a
    # rule an analyst adds in the console is found in files and not only in the
    # network DLP stage.
    hits = sensitive_engine.scan_all(text, source_type="file")
    confirmed = sensitive_engine.confirmed_hits(hits)
    candidates = sensitive_engine.candidate_hits(hits)
    counts: dict[str, int] = {name: 0 for name in REGEX_RULES}
    counts.update(sensitive_engine.count_by_legacy_name(hits))
    # A rule the console added has no legacy category name; it still belongs in
    # the report under the entity its author wrote, or the hit would be visible
    # in the evidence while missing from the counts beside it.
    for hit in hits:
        if sensitive_engine.legacy_name(hit.entity):
            continue
        key = str(hit.entity).lower()
        counts[key] = counts.get(key, 0) + hit.count
    return {
        "counts": counts,
        "hits": [hit.to_dict() for hit in hits],
        # Counts feeding alerts use value-level, sufficiently confident hits
        # only. A hash that looks like a token (0.3), a card number that fails
        # Luhn (0.45) or a bare medical term (0.45) stays a candidate clue.
        "confirmed_hits": [hit.to_dict() for hit in confirmed],
        "candidate_hits": [hit.to_dict() for hit in candidates],
        "secret_count": sensitive_engine.secret_count(confirmed),
        "pii_count": sensitive_engine.pii_count(confirmed),
        "candidate_count": len(candidates),
        "max_confidence": sensitive_engine.max_confidence(confirmed),
        "text_truncated": sensitive_engine.text_truncated(),
        # Legacy key. Entropy is now part of the per-rule confidence, so there is
        # no separate list of candidate secrets to hand around.
        "high_entropy_secrets": [],
    }


def infer_columns(text: str, source: str) -> list[dict[str, Any]]:
    columns: list[str] = []
    rows: list[list[str]] = []
    if source.endswith(".csv"):
        try:
            records = list(csv.reader(text.splitlines()))
            columns = records[0] if records else []
            rows = records[1:]
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

    engine = sensitive_engine.scan_engine()
    classified: list[dict[str, Any]] = []
    for index, column in enumerate(columns):
        values = [row[index] for row in rows if index < len(row)][:50]
        hits = [
            hit for hit in engine.scan(sensitive_engine.SensitiveDetectionContext(
                text="\n".join(values), field_name=str(column),
                file_name=source, source_type="file"))
            if hit.sensitive
        ]
        confirmed = [hit for hit in hits if hit.confirmed]
        candidates = [hit for hit in hits if not hit.confirmed]

        def _names(items: list[Any]) -> list[str]:
            return [sensitive_engine.legacy_name(hit.entity) or str(hit.entity).lower() for hit in items]

        confirmed_categories = _names(confirmed)
        candidate_categories = [name for name in _names(candidates) if name not in confirmed_categories]
        strongest = max(confirmed or candidates, key=lambda hit: _SEVERITY_RANK.get(hit.severity, 0), default=None)
        # Legacy contract: this field is a binary "contains sensitive data" signal
        # (High/Unknown) rather than a severity level. Only a value-level hit may
        # raise it: a header such as ``phone`` on an empty template is a candidate.
        classified.append({
            "name": column,
            "sensitivity": "High" if confirmed_categories else "Unknown",
            "sensitivity_level": strongest.level if strongest else "",
            "severity": strongest.severity if strongest else "",
            "categories": confirmed_categories + candidate_categories,
            "confirmed_categories": confirmed_categories,
            "candidate_categories": candidate_categories,
            "sample_size": len(values),
            "sample_hit_count": sum(hit.count for hit in confirmed),
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
            text, text_status = extract_document(path)
            scan = scan_text(text)
            if text_status.get("truncated") or scan.get("text_truncated"):
                text_status = {**text_status, "status": SCAN_PARTIAL, "truncated": True}
            presidio = presidio_scan(text) if text else []
            yara_matches = yara_scan(path, Path(__file__).resolve().parents[2] / "rules" / "data")
            evidence = {
                "file": str(path),
                "size": path.stat().st_size,
                "text_status": text_status,
                "regex": scan,
                "presidio": presidio[:50],
                "presidio_status": presidio_status(),
                "yara": yara_matches[:50],
            }
            columns = infer_columns(text, path.name)
            # The capture is evidence for network analysis, not a business document.
            # Keep YARA/findings below; extracted files can still become assets.
            capture_container = context.target_type == "pcap" and path == context.path
            if columns and not capture_container:
                evidence["columns"] = columns
                has_confirmed = any(column["confirmed_categories"] for column in columns)
                has_candidate = any(column["candidate_categories"] for column in columns)
                context.data.setdefault("data_assets", []).append({
                    "name": path.name,
                    "asset_type": "file",
                    # A template whose only signal is a header name is not a
                    # discovered PII file: report it as a candidate.
                    "sensitivity": "High" if has_confirmed else ("Unknown" if has_candidate else "Low"),
                    "source": path.name,
                    "columns": columns,
                })
            elif not capture_container and text_status["status"] in {SCAN_FAILED, SCAN_UNSUPPORTED}:
                # Say the file was not inspected instead of letting an empty scan
                # look like a clean result.
                context.data.setdefault("data_assets", []).append({
                    "name": path.name,
                    "asset_type": "file",
                    "sensitivity": "Unknown",
                    "source": path.name,
                    "scan_status": text_status["status"],
                    "scan_reason": text_status.get("reason", ""),
                })
            pii_confirmed = _confirmed_of(scan, PII_FAMILIES)
            presidio_confirmed = [
                item for item in presidio
                if float(item.get("score") or 0) >= CONFIRMED_MIN_SCORE
            ]
            if pii_confirmed or presidio_confirmed:
                confidence = max(
                    [float(item.get("confidence") or 0) for item in pii_confirmed]
                    + [float(item.get("score") or 0) for item in presidio_confirmed],
                    default=0.0,
                )
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="DATA_PII_001",
                    severity=_severity_of(pii_confirmed, "Medium"),
                    confidence=confidence,
                    evidence=evidence,
                    recommendation="对包含身份证、手机号、银行卡、邮箱等 PII 的文件实施加密、脱敏和访问控制。",
                ).normalize())
            secret_confirmed = _confirmed_of(scan, SECRET_FAMILIES)
            if secret_confirmed:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id="DATA_SECRET_001",
                    severity=_severity_of(secret_confirmed, "High"),
                    confidence=max(
                        (float(item.get("confidence") or 0) for item in secret_confirmed),
                        default=0.0,
                    ),
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
            rules = (
                ("DATA_PII_001", PII_FAMILIES, "Medium", "对文本中的 PII 进行脱敏和最小化采集。"),
                ("DATA_SECRET_001", SECRET_FAMILIES, "High", "轮换泄露密钥，并从日志和配置中清除明文凭据。"),
            )
            for rule_id, families, fallback, recommendation in rules:
                confirmed = _confirmed_of(scan, families)
                if not confirmed:
                    continue
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id=rule_id,
                    severity=_severity_of(confirmed, fallback),
                    confidence=max(
                        (float(item.get("confidence") or 0) for item in confirmed),
                        default=0.0,
                    ),
                    evidence={"counts": scan["counts"], "hits": scan["confirmed_hits"],
                              "candidates": scan["candidate_hits"]},
                    recommendation=recommendation,
                ).normalize())
        return findings
